use axum::body::Body;
use axum::{http::Request, middleware::Next, response::Response};
use http::header::CONTENT_TYPE;
use http::HeaderValue;

/// 後処理ミドルウェアの例
/// リクエストを処理した後、レスポンスに対して追加の処理（ログ出力、ヘッダー追加など）を行います。
pub async fn after_middleware(req: Request<Body>, next: Next) -> Response {
    tracing::debug!("After middlewares called. Received request: {}", req.uri());
    // 内部ハンドラを実行しレスポンスを取得
    let mut response = next.run(req).await;
    tracing::debug!("After middlewares process started");
    // ヘッダーに charset 指定を追加
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert("x-post-middlewares", "true".parse().unwrap());

    tracing::debug!("After middlewares proceeded.");
    tracing::debug!("Response status = {}", response.status());
    tracing::debug!("Response header: {:?}", response.headers());
    response
}
