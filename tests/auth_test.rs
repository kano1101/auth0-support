#[cfg(test)]
mod auth_tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::{Extension, Router};
    use auth0_support::auth::auth::{callback, login};
    use auth0_support::traits::traits::ClaimsTrait;
    use auth0_support::config::config::{TestConfig, ConfigGetTrait};
    use auth0_support::errors::errors::AppError;
    use chrono::Utc;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde::{Serialize};
    use std::fs::File;
    use std::io::Read;
    use std::sync::Arc;
    use http::header;
    use tower::util::ServiceExt;
    use auth0_support::auth::crypt::CryptState;
    use wiremock::{MockServer, Mock, ResponseTemplate};
    use wiremock::matchers::{method, path};
    use serde_json::json;


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
        let config = Arc::new(TestConfig::from_env().expect("環境変数が取得できませんでした。"));
        let config: Arc<dyn ConfigGetTrait> = config;

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
        assert!(location.starts_with(&config.domain()), "リダイレクトURLがAuth0になっていない");
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
        let mut config = Arc::new(TestConfig::from_env().expect("環境変数の取得に失敗しました。"));
        Arc::make_mut(&mut config).domain = format!("http://{}", local_addr);
        let config: Arc<dyn ConfigGetTrait> = config;

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

        // WireMock サーバーを起動
        let mock_server = MockServer::start().await;

        // Auth0 のトークン取得エンドポイントをモック
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test_access_token",
            "id_token": "test_id_token",
            "token_type": "Bearer"
        })))
            .mount(&mock_server)
            .await;

        let mut config = Arc::new(TestConfig::from_env().expect("環境変数が取得できませんでした。"));
        Arc::make_mut(&mut config).domain = mock_server.uri();
        Arc::make_mut(&mut config).client_id = "test_client_id".to_string();
        Arc::make_mut(&mut config).client_secret = "test_client_secret".to_string();
        Arc::make_mut(&mut config).callback_url = "http://localhost:3000/callback".to_string();
        Arc::make_mut(&mut config).audience = "test_audience".to_string();
        Arc::make_mut(&mut config).jwt_secret = "test_secret".to_string();
        let config: Arc<dyn ConfigGetTrait> = config;

        let app = Router::new()
            .route("/callback", get(callback))
            .layer(Extension(config.clone()))
            .layer(tower_cookies::CookieManagerLayer::new());

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

        // 期待するステータスコードが 400（BAD_REQUEST）であることを確認
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_auth0_callback_invalid_state() {
        let _ = tracing_subscriber::fmt::try_init();

        // WireMock サーバーを起動し、トークンエンドポイントをモック
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/oauth/token"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "test_access_token",
                "id_token": "test_id_token",
                "token_type": "Bearer"
            })),
            )
            .mount(&mock_server)
            .await;

        let mut config = Arc::new(TestConfig::from_env().expect("環境変数が取得できませんでした。"));
        Arc::make_mut(&mut config).domain = mock_server.uri();
        Arc::make_mut(&mut config).client_id = "test_client_id".to_string();
        Arc::make_mut(&mut config).client_secret = "test_client_secret".to_string();
        Arc::make_mut(&mut config).callback_url = "http://localhost:3000/callback".to_string();
        Arc::make_mut(&mut config).audience = "test_audience".to_string();
        Arc::make_mut(&mut config).fallback_uri = "http://localhost:3000".to_string();
        Arc::make_mut(&mut config).allowed_redirect_uris = vec!["http://localhost:3000".to_string()];
        Arc::make_mut(&mut config).jwt_secret = "test_secret".to_string();
        let config: Arc<dyn ConfigGetTrait> = config;

        let app = axum::Router::new()
            .route("/callback", axum::routing::get(callback))
            .layer(axum::Extension(config.clone()))
            .layer(tower_cookies::CookieManagerLayer::new());

        let response = app
            .oneshot(
                http::Request::builder()
                    .uri("/callback?code=test_auth_code&state=INVALID_STATE")
                    .method("GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // state の復号に失敗した場合、デフォルトのリダイレクト先（http://localhost:3000）にリダイレクト
        assert_eq!(response.status(), http::StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn test_auth0_callback_unauthorized_redirect_uri() {
        let _ = tracing_subscriber::fmt::try_init();

        // WireMockサーバーを起動
        let mock_server = MockServer::start().await;

        // Auth0のトークン取得エンドポイントをモック
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "test_access_token",
            "id_token": "test_id_token",
            "token_type": "Bearer"
        })))
            .mount(&mock_server)
            .await;

        let mut config = Arc::new(TestConfig::from_env().expect("環境変数が取得できませんでした。"));
        Arc::make_mut(&mut config).domain = mock_server.uri();
        Arc::make_mut(&mut config).client_id = "test_client_id".to_string();
        Arc::make_mut(&mut config).client_secret = "test_client_secret".to_string();
        Arc::make_mut(&mut config).callback_url = "http://localhost:3000/callback".to_string();
        Arc::make_mut(&mut config).audience = "test_audience".to_string();
        Arc::make_mut(&mut config).jwt_secret = "test_secret".to_string();
        Arc::make_mut(&mut config).fallback_uri = "http://unauthorized".to_string();
        Arc::make_mut(&mut config).allowed_redirect_uris = vec!["http://localhost:3000".to_string()];
        let config: Arc<dyn ConfigGetTrait> = config;

        let app = Router::new()
            .route("/callback", get(callback))
            .layer(Extension(config.clone()))
            .layer(tower_cookies::CookieManagerLayer::new());

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

        // 期待するステータスコードが400（BAD_REQUEST）であることを確認
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_auth0_callback_auth0_token_request_failure() {
        let _ = tracing_subscriber::fmt::try_init();

        let config = Arc::new(TestConfig::from_env().expect("環境変数が取得できませんでした。"));
        let config: Arc<dyn ConfigGetTrait> = config;

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
    #[tokio::test]
    async fn test_auth0_callback_sets_cookies() {
        let _ = tracing_subscriber::fmt::try_init();

        // WireMock サーバーを起動し、トークンエンドポイントをモック
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/oauth/token"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test_access_token",
            "id_token": "test_id_token",
            "token_type": "Bearer"
        })),
            )
            .mount(&mock_server)
            .await;

        // Config をテスト用にセットアップ
        let mut config = Arc::new(TestConfig::from_env().expect("環境変数が取得できませんでした。"));
        Arc::make_mut(&mut config).domain = mock_server.uri();
        Arc::make_mut(&mut config).client_id = "test_client_id".to_string();
        Arc::make_mut(&mut config).client_secret = "test_client_secret".to_string();
        Arc::make_mut(&mut config).callback_url = "http://localhost:3000/callback".to_string();
        Arc::make_mut(&mut config).audience = "test_audience".to_string();
        Arc::make_mut(&mut config).fallback_uri = "http://localhost:3000".to_string();
        Arc::make_mut(&mut config).allowed_redirect_uris = vec!["http://localhost:3000".to_string()];
        Arc::make_mut(&mut config).jwt_secret = "test_secret".to_string();
        let config: Arc<dyn ConfigGetTrait> = config;

        let app = axum::Router::new()
            .route("/callback", axum::routing::get(callback))
            .layer(axum::Extension(config.clone()))
            .layer(tower_cookies::CookieManagerLayer::new());

        // 有効な state を生成
        let crypt_state = CryptState::new(config.clone());
        let valid_encrypted_state = crypt_state.encrypt_state("http://localhost:3000", None)
            .expect("state の生成に失敗しました。");

        let response = app
            .oneshot(
                http::Request::builder()
                    .uri(&format!("/callback?code=test_auth_code&state={}", valid_encrypted_state))
                    .method("GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // ステータスコードが 303 (SEE OTHER) であることを確認
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        // `Set-Cookie` ヘッダーを取得
        let cookies: Vec<String> = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();

        // `access_token` と `id_token` が含まれているか確認
        assert!(
            cookies.iter().any(|cookie| cookie.starts_with("access_token=")),
            "access_token が Cookie に設定されていない"
        );
        assert!(
            cookies.iter().any(|cookie| cookie.starts_with("id_token=")),
            "id_token が Cookie に設定されていない"
        );
    }
}
