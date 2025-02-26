#[cfg(test)]
mod auth_tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::{Extension, Router};
    use auth0_support::auth::auth::{callback, login};
    use auth0_support::traits::claims_trait::ClaimsTrait;
    use auth0_support::config::config::{ConfigGetTrait, ConfigBuilder};
    use auth0_support::errors::errors::AppError;
    use chrono::Utc;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde::{Serialize};
    // use serde_json::json;
    use std::fs::File;
    use std::io::Read;
    use std::sync::Arc;
    use http::header;
    use tower::util::ServiceExt;
    // use tower_cookies::{Cookie, CookieManagerLayer};
    // use tower_cookies::cookie::CookieJar;
    use auth0_support::auth::crypt::CryptState;
    // use wiremock::matchers::{method, path};
    // use wiremock::{Mock, MockServer, ResponseTemplate};

    #[allow(dead_code)]
    #[derive(Serialize)]
    struct Claims {
        sub: String,
        exp: usize,
    }
    impl ClaimsTrait for Claims {
        fn get_exp(&self) -> usize {
            self.exp
        }
    }

    #[allow(dead_code)]
    async fn body_to_string(body: Body) -> Result<String, String> {
        let bytes = axum::body::to_bytes(body, usize::MAX)
            .await
            .map_err(|e| format!("Failed to read body: {:?}", e))?;
        String::from_utf8(bytes.to_vec())
            .map_err(|e| format!("Failed to parse body as UTF-8: {:?}", e))
    }
    #[allow(dead_code)]
    pub fn create_jwt(sub: &str, private_key_pem: &[u8]) -> Result<String, AppError> {
        let claims = Claims {
            sub: sub.to_string(),
            exp: (Utc::now().timestamp() + 3600) as usize,
        };

        encode(
            &Header::new(Algorithm::RS256),
            &claims,
            &EncodingKey::from_rsa_pem(private_key_pem)
                .map_err(|e| AppError::InternalServerError(format!("Encoding key error: {}", e)))?,
        )
            .map_err(|e| AppError::InternalServerError(format!("JWT encoding error: {}", e)))
    }
    #[allow(dead_code)]
    fn get_private_and_public_keys() -> (String, String) {
        let mut private_key_file =
            File::open("keys/private_key.pem").expect("Failed to open private_key.pem");
        let mut private_key = String::new();
        private_key_file
            .read_to_string(&mut private_key)
            .expect("Failed to read private_key.pem");

        let mut public_key_file =
            File::open("keys/public_key.pem").expect("Failed to open public_key.pem");
        let mut public_key = String::new();
        public_key_file
            .read_to_string(&mut public_key)
            .expect("Failed to read public_key.pem");
        (private_key, public_key)
    }

    #[tokio::test]
    async fn test_auth0_redirect() {
        let _ = tracing_subscriber::fmt::try_init();
        let config = Arc::new(ConfigBuilder::new_as_production().expect("環境変数が取得できませんでした。"));

        let app = Router::new()
            .route("/login", get(login))
            .layer(Extension(config.clone()));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/login?redirect_uri=http://localhost:3000")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // ステータスコードが 307 Temporary Redirect であることを確認
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);

        // `Location` ヘッダーが正しく Auth0 の認可URLになっているか確認
        let location_header = response.headers().get(header::LOCATION);
        assert!(location_header.is_some(), "Location ヘッダーが設定されていない");

        let location = location_header.unwrap().to_str().unwrap();
        assert!(location.starts_with(&config.auth0_domain()), "リダイレクトURLがAuth0になっていない");
    }

    #[tokio::test]
    async fn test_auth0_callback_success() {
        let _ = tracing_subscriber::fmt::try_init();

        use hyper::{Request, Response, StatusCode};
        use hyper::body::{Bytes, Incoming as Body};
        use http_body_util::{Empty, Full};
        use axum_server::Server;
        use tower::make::Shared;
        use tower::service_fn;
        use std::net::TcpListener;
        use std::convert::Infallible;

        async fn mock_token_endpoint(req: Request<Body>) -> Result<Response<Full<Bytes>>, Infallible> {
            if req.uri().path() == "/oauth/token" && req.method() == hyper::Method::POST {
                let json = r#"{
                "access_token": "test_access_token",
                "id_token": "test_id_token",
                "token_type": "Bearer",
                "expires_in": 3600
            }"#;
                Ok(Response::new(Full::from(json)))
            } else {
                Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::default())
                    .unwrap())
            }
        }

        // `TcpListener` を作成して `local_addr()` を取得
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local_addr = listener.local_addr().unwrap();

        let make_svc = Shared::new(service_fn(mock_token_endpoint));
        let server = Server::from_tcp(listener).serve(make_svc);

        tokio::spawn(async move {
            if let Err(e) = server.await {
                eprintln!("server error: {}", e);
            }
        });

        // Config をテスト用に上書き
        let mut test_config = ConfigBuilder::new_as_test().expect("環境変数の取得に失敗しました。");
        test_config.auth0_domain = format!("http://{}", local_addr);
        let config = std::sync::Arc::new(test_config);

        // 有効な state を生成
        let crypt_state = CryptState::new(config.clone());
        let valid_encrypted_state = crypt_state.encrypt_state("http://localhost:3000", None)
            .expect("state の生成に失敗しました。");

        let app = axum::Router::new()
            .route("/callback", axum::routing::get(callback))
            .layer(axum::extract::Extension(config.clone()))
            .layer(tower_cookies::CookieManagerLayer::new());

        let response = app
            .oneshot(
                http::Request::builder()
                    .uri(&format!("/callback?code=test_auth_code&state={}", valid_encrypted_state))
                    .method("GET")
                    .body(Empty::new())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn test_auth0_callback_missing_code() {
        let _ = tracing_subscriber::fmt::try_init();

        let config = Arc::new(ConfigBuilder::new_as_production().expect("環境変数が取得できませんでした。"));

        let app = Router::new()
            .route("/callback", get(callback))
            .layer(Extension(config.clone()));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/callback?code=&state=VALID_ENCRYPTED_STATE")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_auth0_callback_invalid_state() {
        let _ = tracing_subscriber::fmt::try_init();

        let config = Arc::new(ConfigBuilder::new_as_production().expect("環境変数が取得できませんでした。"));

        let app = Router::new()
            .route("/callback", get(callback))
            .layer(Extension(config.clone()));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/callback?code=test_auth_code&state=INVALID_STATE")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // state の復号に失敗した場合、デフォルトURLが設定されるためリダイレクトされる
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn test_auth0_callback_unauthorized_redirect_uri() {
        let _ = tracing_subscriber::fmt::try_init();

        let config = Arc::new(ConfigBuilder::new_as_production().expect("環境変数が取得できませんでした。"));

        let app = Router::new()
            .route("/callback", get(callback))
            .layer(Extension(config.clone()));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/callback?code=test_auth_code&state=ENCRYPTED_UNAUTHORIZED_URI")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_auth0_callback_auth0_token_request_failure() {
        let _ = tracing_subscriber::fmt::try_init();

        let config = Arc::new(ConfigBuilder::new_as_production().expect("環境変数が取得できませんでした。"));

        let app = Router::new()
            .route("/callback", get(callback))
            .layer(Extension(config.clone()));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/callback?code=test_auth_code&state=VALID_ENCRYPTED_STATE")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Auth0 側でエラーが発生した場合、500 が返る想定
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // #[tokio::test]
    // async fn it_inspects_bearer_token_and_shows_sub() {
    //     // テスト用のRSA秘密鍵と公開鍵を読み込む
    //     let (private_key, public_key) = get_private_and_public_keys();
    //
    //     let app = Router::new()
    //         .route("/login", get(login));
    //
    //     // 現在時刻から1時間後のexpを設定
    //     let expiration = (Utc::now().timestamp() + 3600) as usize;
    //
    //     let claims = Claims {
    //         sub: "user123".to_string(),
    //         exp: expiration,
    //     };
    //     let token = encode(
    //         &Header::new(Algorithm::RS256),
    //         &claims,
    //         &EncodingKey::from_rsa_pem(private_key.as_bytes()).unwrap(),
    //     )
    //         .unwrap();
    //
    //     let response = app
    //         .oneshot(
    //             Request::builder()
    //                 .uri(format!("/login?redirect_uri={}", "/"))
    //                 .method("GET")
    //                 .body(Body::empty())
    //                 .unwrap(),
    //         )
    //         .await
    //         .unwrap();
    //
    //     assert_eq!(response.status(), StatusCode::SEE_OTHER);
    // }

    // /// /login に未認証のユーザがアクセスした際に、Auth0 のログインページにリダイレクトされる動作をテストする
    // #[tokio::test]
    // async fn it_redirects_unauthenticated_user_to_auth0_login() {
    //     // テスト用のAppStateを設定
    //     let test_state = TestAppState {
    //         auth0_domain: "https://dev-secoex2w3wpe1cgp.us.auth0.com".to_string(),
    //         public_key: "your_test_public_key".to_string(),
    //     };
    //     let shared_state: Arc<dyn AppStateTrait> = Arc::new(test_state.clone());
    //
    //     let app = Router::new()
    //         .route("/login", axum::routing::get(login))
    //         .with_state(shared_state);
    //
    //     let response = app
    //         .oneshot(
    //             Request::builder()
    //                 .uri("/login")
    //                 .method("GET")
    //                 .body(Body::empty())
    //                 .unwrap(),
    //         )
    //         .await
    //         .unwrap();
    //
    //     assert_eq!(response.status(), StatusCode::SEE_OTHER);
    //
    //     let location = response
    //         .headers()
    //         .get(axum::http::header::LOCATION)
    //         .expect("Locationヘッダーが存在する")
    //         .to_str()
    //         .expect("Locationヘッダーが文字列である");
    //
    //     assert!(
    //         location.contains(&format!("{}/authorize", test_state.auth0_domain)),
    //         "location に認可URLが含まれていません"
    //     );
    // }
    //
    // /// 認証済みユーザが /login にアクセスするとトップページにリダイレクトされることをテストする
    // #[tokio::test]
    // async fn it_redirects_authenticated_user_to_homepage() {
    //     // テスト用のJWTトークンを生成
    //     let user_id = "user123";
    //
    //     // テスト用のRSA秘密鍵を読み込む
    //     let mut private_key_file =
    //         File::open("keys/private_key.pem").expect("Failed to open private_key.pem");
    //     let mut private_key = String::new();
    //     private_key_file
    //         .read_to_string(&mut private_key)
    //         .expect("Failed to read private_key.pem");
    //
    //     // JWTを生成
    //     let token = create_jwt(user_id, private_key.as_bytes()).expect("Failed to create JWT");
    //
    //     // テスト用のAppStateを設定（認証済みユーザーとして扱う）
    //     let test_state = TestAppState {
    //         auth0_domain: "https://dev-secoex2w3wpe1cgp.us.auth0.com".to_string(),
    //         public_key: "your_test_public_key".to_string(), // 必要に応じて実際の公開鍵を設定
    //     };
    //     let shared_state: Arc<dyn AppStateTrait> = Arc::new(test_state.clone());
    //
    //     // Routerを設定
    //     let app = Router::new()
    //         .route("/login", axum::routing::get(login))
    //         .with_state(shared_state);
    //
    //     // 認証済みユーザーとしてリクエストを送信
    //     let response = app
    //         .oneshot(
    //             Request::builder()
    //                 .uri("/login")
    //                 .method("GET")
    //                 .header("Authorization", format!("Bearer {}", token))
    //                 .body(Body::empty())
    //                 .unwrap(),
    //         )
    //         .await
    //         .unwrap();
    //
    //     // ステータスコードがリダイレクト（302 Found）であることを確認
    //     assert_eq!(response.status(), StatusCode::SEE_OTHER);
    //
    //     // リダイレクト先がホームページであることを確認（例："/home"）
    //     let location = response
    //         .headers()
    //         .get(axum::http::header::LOCATION)
    //         .expect("Locationヘッダーが存在する")
    //         .to_str()
    //         .expect("Locationヘッダーが文字列である");
    //
    //     assert!(
    //         location.contains("/callback"),
    //         "リダイレクト先がホームページでない"
    //     );
    // }
    //
    // /// /callback は有効な認証コードを受け取った場合にトークンを取得しセッションを確立することをテストする
    // #[tokio::test]
    // async fn it_callback_establishes_session_with_valid_code() {
    //     // モックサーバーの起動
    //     let mock_server = MockServer::start().await;
    //
    //     // トークンエンドポイントのモックレスポンス設定
    //     Mock::given(method("POST"))
    //         .and(path("/oauth/token"))
    //         .respond_with(ResponseTemplate::new(200).set_body_json(json!({
    //             "access_token": "test_access_token",
    //             "id_token": "test_id_token",
    //             "token_type": "Bearer",
    //             "expires_in": 3600
    //         })))
    //         .mount(&mock_server)
    //         .await;
    //
    //     // テスト用のAppStateを設定
    //     let test_state = TestAppState {
    //         auth0_domain: mock_server.uri(),
    //         public_key: "your_test_public_key".to_string(),
    //     };
    //     let shared_state: Arc<dyn AppStateTrait> = Arc::new(test_state);
    //
    //     // Routerを設定
    //     let app = Router::new()
    //         .route("/callback", get(callback))
    //         .with_state(shared_state);
    //
    //     // 有効な認証コードを送信
    //     let valid_code = "valid_auth_code";
    //
    //     // リクエストを送信
    //     let response = app
    //         .oneshot(
    //             Request::builder()
    //                 .uri(format!("/callback?code={}", valid_code))
    //                 .method("GET")
    //                 .body(Body::empty())
    //                 .unwrap(),
    //         )
    //         .await
    //         .unwrap();
    //
    //     // ステータスコードがリダイレクト（303 See Other）であることを確認
    //     assert_eq!(response.status(), StatusCode::SEE_OTHER);
    //
    //     // リダイレクト先が/display_subにリダイレクトされていることを確認
    //     let location = response
    //         .headers()
    //         .get(axum::http::header::LOCATION)
    //         .expect("Locationヘッダーが存在する")
    //         .to_str()
    //         .expect("Locationヘッダーが文字列である");
    //
    //     assert!(
    //         location.contains("/display_sub?token=test_access_token"),
    //         "正しいリダイレクト先ではないか、アクセストークンが取得できていないか、両方か"
    //     );
    // }
    //
    // /// /callback は無効な認証コードを受け取った場合にエラーレスポンスを返すことをテストする
    // #[tokio::test]
    // async fn it_callback_returns_error_with_invalid_code() {
    //     // モックサーバーを起動
    //     let mock_server = MockServer::start().await;
    //
    //     // トークンエンドポイントで無効な認証コードのレスポンスをモック
    //     Mock::given(method("POST"))
    //         .and(path("/oauth/token"))
    //         .respond_with(ResponseTemplate::new(400).set_body_json(json!({
    //             "error": "invalid_grant",
    //             "error_description": "Invalid authorization code"
    //         })))
    //         .mount(&mock_server)
    //         .await;
    //
    //     // テスト用のAppStateを設定
    //     let test_state = TestAppState {
    //         auth0_domain: mock_server.uri(), // モックサーバーのURIを使う
    //         public_key: "your_test_public_key".to_string(),
    //     };
    //     let shared_state: Arc<dyn AppStateTrait> = Arc::new(test_state);
    //
    //     // Routerを設定
    //     let app = Router::new()
    //         .route("/callback", get(callback))
    //         .with_state(shared_state);
    //
    //     // テスト用の無効な認証コード
    //     let invalid_code = "invalid_auth_code";
    //
    //     // リクエスト送信
    //     let response = app
    //         .oneshot(
    //             Request::builder()
    //                 .uri(format!("/callback?code={}", invalid_code))
    //                 .method("GET")
    //                 .body(Body::empty())
    //                 .unwrap(),
    //         )
    //         .await
    //         .unwrap();
    //
    //     // ステータスコードが400 Bad Requestであることを確認
    //     assert_eq!(
    //         response.status(),
    //         StatusCode::BAD_REQUEST,
    //         "Expected 400 Bad Request when invalid authorization code is provided"
    //     );
    //
    //     // レスポンスボディの確認
    //     let body = body_to_string(response.into_body())
    //         .await
    //         .expect("Failed to convert body to string");
    //
    //     assert!(
    //         body.contains("Invalid authorization code"),
    //         "Response body did not include expected error message: {}",
    //         body
    //     );
    // }
    //
    // /// /callback はトークン取得失敗時にエラーハンドリングを行うことをテストする
    // #[tokio::test]
    // async fn it_callback_handles_token_fetch_failure() {
    //     // モックサーバーを起動
    //     let mock_server = MockServer::start().await;
    //
    //     // トークンエンドポイントでネットワークエラーを模倣
    //     Mock::given(method("POST"))
    //         .and(path("/oauth/token"))
    //         .respond_with(ResponseTemplate::new(500)) // 500 Internal Server Error を返す
    //         .mount(&mock_server)
    //         .await;
    //
    //     // テスト用のAppStateを設定
    //     let test_state = TestAppState {
    //         auth0_domain: mock_server.uri(), // モックサーバーのURIを使う
    //         public_key: "your_test_public_key".to_string(),
    //     };
    //     let shared_state: Arc<dyn AppStateTrait> = Arc::new(test_state);
    //
    //     // Routerを設定
    //     let app = Router::new()
    //         .route("/callback", axum::routing::get(callback))
    //         .with_state(shared_state);
    //
    //     // テスト用の無効な認証コード
    //     let failing_code = "failing_auth_code";
    //
    //     // リクエスト送信
    //     let response = app
    //         .oneshot(
    //             Request::builder()
    //                 .uri(format!("/callback?code={}", failing_code))
    //                 .method("GET")
    //                 .body(Body::empty())
    //                 .unwrap(),
    //         )
    //         .await
    //         .unwrap();
    //
    //     // ステータスコードが500 Internal Server Errorであることを確認
    //     assert_eq!(
    //         response.status(),
    //         StatusCode::INTERNAL_SERVER_ERROR,
    //         "Expected 500 Internal Server Error when token fetch fails"
    //     );
    //
    //     // レスポンスボディを確認（オプション）
    //     let body = body_to_string(response.into_body())
    //         .await
    //         .expect("Failed to convert body to string");
    //
    //     assert!(
    //         body.contains(
    //             format!(
    //                 "Non-success status: {}, body: {}",
    //                 StatusCode::INTERNAL_SERVER_ERROR.to_string(),
    //                 ""
    //             )
    //                 .as_str()
    //         ),
    //         "Unexpected error message in the response body: {}",
    //         body
    //     );
    // }
    //
    // /// /me は認証済みユーザにユーザ情報を返すことをテストする
    // #[tokio::test]
    // async fn it_me_returns_user_info_for_authenticated_user() {
    //     // テスト用のRSA秘密鍵と公開鍵を読み込む
    //     let mut private_key_file =
    //         File::open("keys/private_key.pem").expect("Failed to open private_key.pem");
    //     let mut private_key = String::new();
    //     private_key_file
    //         .read_to_string(&mut private_key)
    //         .expect("Failed to read private_key.pem");
    //
    //     let mut public_key_file =
    //         File::open("keys/public_key.pem").expect("Failed to open public_key.pem");
    //     let mut public_key = String::new();
    //     public_key_file
    //         .read_to_string(&mut public_key)
    //         .expect("Failed to read public_key.pem");
    //
    //     // テスト用 JWT のクレームを定義
    //     #[derive(Debug, Serialize, Deserialize)]
    //     struct Claims {
    //         sub: String,
    //         exp: usize,
    //     }
    //
    //     // 現在のタイムスタンプから1時間の有効期限を設定
    //     let expiration = (Utc::now().timestamp() + 3600) as usize;
    //     let user_id = "user123"; // ユーザーID
    //
    //     // JWT を生成（RS256）
    //     let claims = Claims {
    //         sub: user_id.to_string(),
    //         exp: expiration,
    //     };
    //     let token = jsonwebtoken::encode(
    //         &Header::new(Algorithm::RS256),
    //         &claims,
    //         &EncodingKey::from_rsa_pem(private_key.as_bytes()).unwrap(),
    //     )
    //         .unwrap();
    //
    //     // テスト用 AppState を作成
    //     let test_state = TestAppState {
    //         auth0_domain: "https://your-auth0-domain".to_string(),
    //         public_key: public_key.clone(),
    //     };
    //     let shared_state = Arc::new(test_state);
    //
    //     // Router 設定
    //     let app = Router::new()
    //         .route("/me", get(me)) // モックハンドラを設定
    //         .with_state(shared_state);
    //
    //     // /me エンドポイントへのリクエストを送信
    //     let response = app
    //         .oneshot(
    //             Request::builder()
    //                 .uri("/me")
    //                 .method("GET")
    //                 .header("Authorization", format!("Bearer {}", token))
    //                 .body(Body::empty())
    //                 .unwrap(),
    //         )
    //         .await
    //         .expect("Response not found");
    //
    //     // ステータスコードが 200 OK であることを確認
    //     assert_eq!(response.status(), StatusCode::OK);
    //
    //     // レスポンスボディを確認
    //     let body = body_to_string(response.into_body())
    //         .await
    //         .expect("Failed to read body");
    //
    //     // レスポンスが予想したユーザ情報を含むことを確認
    //     assert!(
    //         body.contains(&format!("\"sub\":\"{}\"", user_id)),
    //         "Response body did not include expected user ID: {}",
    //         body
    //     );
    // }
    //
    // /// /me は未認証ユーザに401 Unauthorizedエラーを返すことをテストする
    // #[tokio::test]
    // async fn it_me_returns_401_for_unauthenticated_user() {
    //     // テスト用のAppStateを設定
    //     let test_state = TestAppState {
    //         auth0_domain: "https://your-auth0-domain".to_string(),
    //         public_key: "your_test_public_key".to_string(), // 必要に応じた公開鍵
    //     };
    //     let shared_state = Arc::new(test_state);
    //
    //     // Router 設定
    //     let app = Router::new()
    //         .route("/me", axum::routing::get(me)) // `me` ハンドラをルートに指定
    //         .with_state(shared_state);
    //
    //     // 認証なしでリクエストを送信
    //     let response = app
    //         .oneshot(
    //             Request::builder()
    //                 .uri("/me")
    //                 .method("GET")
    //                 .body(Body::empty())
    //                 .unwrap(),
    //         )
    //         .await
    //         .unwrap();
    //
    //     // ステータスコードが 401 Unauthorized であることを確認
    //     assert_eq!(
    //         response.status(),
    //         StatusCode::UNAUTHORIZED,
    //         "Expected 401 Unauthorized for unauthenticated user"
    //     );
    //
    //     // レスポンスボディを確認（必要に応じて）
    //     let body = body_to_string(response.into_body())
    //         .await
    //         .expect("Failed to read body");
    //     assert!(
    //         body.contains("Unauthorized"),
    //         "Response body did not contain expected unauthorized message: {}",
    //         body
    //     );
    // }
    //
    // /// 不正なリクエストパラメータ時に適切なエラーレスポンスを返すことをテストする
    // #[tokio::test]
    // async fn it_returns_error_for_invalid_request_parameters() {
    //     // 作成するリクエスト: `params.code` が無い(空の)クエリパラメータ
    //     let request = Request::builder()
    //         .uri("/callback?code=") // 空の `code`
    //         .header("Content-Type", "application/x-www-form-urlencoded")
    //         .body(Body::empty())
    //         .unwrap();
    //
    //     // テスト用AppStateをArcで包む
    //     let mock_state = Arc::new(TestAppState {
    //         auth0_domain: "https://your-auth0-domain".to_string(),
    //         public_key: "your_test_public_key".to_string(),
    //     });
    //
    //     // ルーターを構築して、callbackハンドラをGETメソッドに紐付け
    //     let app = Router::new()
    //         .route("/callback", get(callback))
    //         .with_state(mock_state);
    //
    //     // リクエストを送信
    //     let response = app.oneshot(request).await.unwrap();
    //
    //     // ステータスコードが 400 Bad Request であることを確認
    //     assert_eq!(
    //         response.status(),
    //         StatusCode::BAD_REQUEST,
    //         "Expected 400 Bad Request for invalid request parameters."
    //     );
    //
    //     // エラーレスポンスの内容を確認
    //     let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
    //         .await
    //         .expect("Failed to read response body");
    //     let body_text = String::from_utf8(body.to_vec()).unwrap();
    //
    //     assert!(
    //         body_text.contains("Missing code parameter"),
    //         "Response body does not contain the expected error message: {}",
    //         body_text
    //     );
    // }
    //
    // /// 内部サーバーエラー発生時に500 Internal Server Errorを返すことをテストする
    // #[tokio::test]
    // async fn it_returns_500_on_internal_server_error() {
    //     // モック状態
    //     let mock_state = Arc::new(TestAppState {
    //         auth0_domain: "https://your-auth0-domain".to_string(),
    //         public_key: "your_test_public_key".to_string(),
    //     });
    //
    //     let app = Router::new()
    //         .route("/callback", axum::routing::get(callback))
    //         .with_state(mock_state);
    //
    //     // リクエストを作成
    //     let request = Request::builder()
    //         .uri("/callback?code=test_code")
    //         .header("Content-Type", "application/x-www-form-urlencoded")
    //         .body(Body::empty())
    //         .unwrap();
    //
    //     // Router にリクエストを送信
    //     let response = app.oneshot(request).await.unwrap();
    //
    //     // ステータスコードの検証（500 エラー）
    //     assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    //
    //     // レスポンスボディの検証
    //     let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
    //         .await
    //         .unwrap();
    //     let body_text = String::from_utf8(body.to_vec()).unwrap();
    //
    //     assert!(
    //         body_text.contains("Token request failed"), // エラーメッセージを一致させる
    //         "Response body does not contain the expected error message: {}",
    //         body_text
    //     );
    // }
}
