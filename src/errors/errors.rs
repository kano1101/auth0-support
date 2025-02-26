// src/errors/errors.rs

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response, Redirect},
    Json,
};
use serde_json::json;
use thiserror::Error;

// エラー型の定義
#[derive(Error)]
pub enum AppError {
    #[error("Bad Request: {0}")]
    BadRequest(String),

    #[error("Internal Server Error: {0}")]
    InternalServerError(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("DBError: {0}")]
    DBError(String),

    #[error("Redirect")]
    Redirect(Redirect),
}

// `IntoResponse` の実装
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::BadRequest(message) => {
                (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response()
            }
            AppError::InternalServerError(message) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": message })),
            )
                .into_response(),
            AppError::Unauthorized(message) => {
                (StatusCode::UNAUTHORIZED, Json(json!({ "error": message }))).into_response()
            }
            AppError::DBError(message) => {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": message }))).into_response()
            }
            AppError::Redirect(redirect) => redirect.into_response(), // Redirect をそのままレスポンスとして返す
        }
    }
}

impl std::fmt::Debug for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::BadRequest(msg) => {
                eprintln!("AppError::BadRequest: {}", msg); // ログ出力
                write!(f, "BadRequest: {}", msg)
            }
            AppError::InternalServerError(msg) => {
                eprintln!("AppError::InternalServerError: {}", msg); // ログ出力
                write!(f, "InternalServerError: {}", msg)
            }
            AppError::Unauthorized(msg) => {
                eprintln!("AppError::Unauthorized: {}", msg); // ログ出力
                write!(f, "Unauthorized: {}", msg)
            }
            AppError::DBError(msg) => {
                eprintln!("AppError::DBError: {}", msg); // ログ出力
                write!(f, "DBError: {}", msg)
            }
            AppError::Redirect(redirect) => {
                eprintln!("AppError::Redirect: {:?}", redirect); // ログ出力
                write!(f, "Redirect: {:?}", redirect)
            }
        }
    }
}
