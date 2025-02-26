use std::sync::Arc;
use axum::Extension;
use axum::extract::Query;
use axum::response::{IntoResponse, Redirect, Response};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use tower_cookies::{Cookie, Cookies};
use tower_cookies::cookie::SameSite;
use crate::auth::crypt::CryptState;
use crate::errors::errors::AppError;
use crate::utils::utils::{build_token_request_params, extract_access_token, extract_id_token, handle_token_error, is_allowed_redirect};
use crate::auth::redirect_to_login::redirect_to_login;
use crate::config::config::{Config, ConfigGetTrait};

// JWTで使用する秘密鍵（本番では環境変数等で安全に管理）
#[derive(Debug, Deserialize)]
pub struct AuthCallbackParams {
    #[allow(dead_code)]
    code: String,
    state: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginParams {
    #[allow(dead_code)]
    redirect_uri: Option<String>,
}
pub async fn login(
    Query(params): Query<LoginParams>,
    Extension(config): Extension<Arc<Config>>,
) -> Result<Response, AppError> {
    tracing::debug!("login called.");
    let original_redirect_uri = params
        .redirect_uri
        .clone()
        .unwrap_or_else(|| "http://localhost:3000".to_string());

    let response = redirect_to_login(&original_redirect_uri, config);
    tracing::debug!("login returning after login_util::login.");
    Ok(response.into_response())
}
pub async fn logout(
    cookies: Cookies,
    Extension(config): Extension<Arc<dyn ConfigGetTrait>>,
) -> Result<Response, AppError> {
    tracing::debug!("logout called.");

    // ローカルのトークンCookieを削除
    let removal_cookie = Cookie::build(("access_token", ""))
        .path("/")
        .max_age(tower_cookies::cookie::time::Duration::seconds(0))
        .build();
    cookies.remove(removal_cookie);

    let removal_cookie2 = Cookie::build(("id_token", ""))
        .path("/")
        .max_age(tower_cookies::cookie::time::Duration::seconds(0))
        .build();
    cookies.remove(removal_cookie2);

    // Auth0 のログアウトエンドポイントへリダイレクト
    // returnTo に指定する URL は Auth0 の許可リストに登録されている必要があります
    let logout_url = format!(
        "{}/v2/logout?client_id={}&returnTo={}",
        config.auth0_domain(),
        config.client_id(),
        "http://localhost:3000" // ログアウト後に戻る URL
    );
    Ok(Redirect::to(&logout_url).into_response())
}

pub async fn callback(
    Query(params): Query<AuthCallbackParams>,
    Extension(config): Extension<Arc<Config>>,
    cookies: Cookies,
) -> Result<Response, AppError> {
    tracing::debug!("callback called.");

    if params.code.is_empty() {
        return Err(AppError::BadRequest("Missing code parameter".into()));
    }

    let crypt_state = CryptState::new(config.clone());

    let original_redirect_uri = crypt_state
        .decrypt_and_verify_state(&params.state) // state を復号
        .unwrap_or_else(|_| "http://localhost:3000".to_string()) // エラー時はデフォルト値
        .to_string();

    if !is_allowed_redirect(&original_redirect_uri, vec!["http://localhost:3000", "http://localhost:8000"]) {
        return Err(AppError::BadRequest("Unauthorized redirect URI".into()));
    }

    let token_endpoint = format!("{}/oauth/token", config.auth0_domain());

    let token_request_params = build_token_request_params(
        &config.client_id(),
        &config.client_secret(),
        &params.code,
        &config.callback_url(),
    );

    let client = Client::new();
    let res = client
        .post(&token_endpoint)
        .form(&token_request_params)
        .send()
        .await
        .map_err(|e| AppError::InternalServerError(format!("Token request failed: {}", e)))?;

    let status = res.status();
    let body_text = res.text().await.map_err(|e| {
        AppError::InternalServerError(format!("Failed to read response body: {}", e))
    })?;

    if !status.is_success() {
        if let Ok(tokens) = serde_json::from_str::<Value>(&body_text) {
            if let Some(error_code) = tokens.get("error").and_then(|e| e.as_str()) {
                return handle_token_error(error_code);
            }
        }
        return Err(AppError::InternalServerError(format!(
            "Non-success status: {}, body: {}",
            status, body_text
        )));
    }

    let tokens: Value = serde_json::from_str(&body_text).map_err(|e| {
        AppError::InternalServerError(format!("Failed to parse token response as JSON: {}", e))
    })?;

    if let Some(error_code) = tokens.get("error").and_then(|e| e.as_str()) {
        return handle_token_error(error_code);
    }

    if !status.is_success() {
        return Err(AppError::InternalServerError(format!(
            "Token endpoint returned non-success status: {}. Body: {}",
            status, tokens
        )));
    }

    let access_token = extract_access_token(&tokens)?;
    let id_token = extract_id_token(&tokens)?;

    let (is_secure, http_only, same_site) = if config.testing_mode() {
        tracing::info!("プロダクションモードで実行中");
        println!("プロダクションモードで実行中");
        (true, true, SameSite::None)
    } else {
        tracing::info!("テストモードで実行中");
        println!("テストモードで実行中");
        (false, false, SameSite::Lax)
    };

    // tracing::debug!("Initial cookies: {:?}", cookies);

    // Cookie に保存
    cookies.add(
        Cookie::build(("access_token", access_token.clone()))
            .path("/") // これがないとクッキーをブロックされます
            .secure(is_secure)
            .http_only(http_only)
            .same_site(same_site)
            .build(),
    );
    cookies.add(
        Cookie::build(("id_token", id_token))
            .path("/")
            .secure(is_secure)
            .http_only(http_only)
            .same_site(same_site)
            .build(),
    );

    tracing::debug!("Callback returning after adding cookies.");

    // 元のURLにリダイレクト
    Ok(Redirect::to(&original_redirect_uri).into_response())
}
