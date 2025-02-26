use crate::config::config::ConfigGetTrait;
use crate::errors::errors::AppError;
use crate::utils::utils::{decode_id_token, decode_jwt, get_props_for_decode};
use crate::auth::redirect_to_login::redirect_to_login;
use crate::traits::traits::ClaimsTrait;
use axum::{extract::FromRequestParts, http::request::Parts};
use chrono::{DateTime, NaiveDateTime, Utc};
use headers::HeaderMap;
use http::header;
use serde_json::Value;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::de::DeserializeOwned;
pub struct RequireAuthBeforeMiddleware<Claims, Profile> {
    _phantom: std::marker::PhantomData<(Claims, Profile)>,
}

use tower_cookies::Cookies;

impl<S, Claims, Profile> FromRequestParts<S> for RequireAuthBeforeMiddleware<Claims, Profile>
where
    S: Send + Sync,
    Claims: Clone + DeserializeOwned + Send + Sync + 'static + ClaimsTrait,
    Profile: Clone + DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        tracing::trace!("Before middlewares called.");

        let cookies = Cookies::from_request_parts(parts, state)
            .await
            .map_err(|_| AppError::Unauthorized("Could not get cookies".to_string()))?;

        let access_token = cookies
            .get("access_token")
            .map(token_in_cookies_to_string)
            .ok_or(AppError::Unauthorized("Found no access token".to_string()));
        let id_token = cookies
            .get("id_token")
            .map(token_in_cookies_to_string)
            .ok_or(AppError::Unauthorized("Found no id token".to_string()));

        if access_token.is_err() || id_token.is_err() {
            if let Err(e) = access_token {
                tracing::error!("access_token error: {}", e);
            }
            if let Err(e) = id_token {
                tracing::error!("id_token error: {}", e);
            }
            let config = parts
                .extensions
                .get::<Arc<dyn ConfigGetTrait>>()
                .ok_or_else(|| AppError::Unauthorized("Missing config extension".to_string()))?
                .clone();

            let headers = parts.headers.clone();

            let original_redirect_uri = extract_redirect_uri(&headers, config.clone());

            let response = AppError::Redirect(redirect_to_login(&original_redirect_uri, config));
            tracing::debug!(
                "Before middleware_redirect returning after login_util::login and fire! original_redirect_uri: {}",
                original_redirect_uri
            );
            return Err(response);
        }

        let config = parts
            .extensions
            .get::<Arc<dyn ConfigGetTrait>>()
            .ok_or_else(|| AppError::Unauthorized("Missing config extension".to_string()))?
            .clone();

        let access_token = access_token?;
        let id_token = id_token?;

        match extract_exp_from_jwt(&access_token) {
            Some(exp) => {
                #[allow(deprecated)]
                let exp = DateTime::<Utc>::from_utc(
                    NaiveDateTime::from_timestamp_opt(exp as i64, 0).unwrap(),
                    Utc,
                );
                tracing::debug!("exp: {}", exp)
            }
            None => tracing::debug!("exp の取得に失敗"),
        }

        // claims、profileを復元するための認証鍵を取得する
        let decode_props = get_props_for_decode(&access_token, config.clone()).await?;

        let claims = decode_jwt(&access_token, &decode_props)?;
        let claims: Claims = is_valid_claims(claims).await?;
        // expが期限切れの際はis_valid_claimsの戻り値がErrのためここに到達しない
        tracing::info!("access_tokenのexpの有効期限に問題ありません。");

        let maybe_profile = decode_id_token(&id_token, &decode_props);
        let profile: Profile =
            maybe_profile.map_err(|_| AppError::Unauthorized("No profile found".to_string()))?;

        parts.extensions.insert(claims);
        parts.extensions.insert(profile);

        tracing::trace!("middlewares successful.");

        Ok(RequireAuthBeforeMiddleware { _phantom: std::marker::PhantomData })
    }
}
fn extract_exp_from_jwt(token: &str) -> Option<usize> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None; // JWT の形式が正しくない
    }

    // Base64URL デコード（padding なし）
    let payload_bytes = base64::decode_config(parts[1], base64::URL_SAFE_NO_PAD).ok()?;
    let payload = String::from_utf8(payload_bytes).ok()?;

    // JSON 解析
    let payload_json: Value = serde_json::from_slice((&payload).as_ref()).ok()?;

    // `exp` を取得
    payload_json.get("exp")?.as_u64().map(|v| v as usize)
}

fn extract_redirect_uri(headers: &HeaderMap, config: Arc<dyn ConfigGetTrait>) -> String {
    headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string()) // 末尾の `/` を削除
        .unwrap_or(config.fallback_uri().to_string())
}

fn token_in_cookies_to_string(cookie: tower_cookies::Cookie) -> String {
    cookie.value().trim_matches('"').to_string()
}

/// JWT の署名検証やクレーム検証を行う
async fn is_valid_claims<Claims: ClaimsTrait>(claims: Claims) -> Result<Claims, AppError> {
    tracing::trace!("is_valid_claims called");
    // さらに有効期限の確認（decode で自動検証される場合もある）
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;
    let exp = claims.get_exp();
    if exp > now {
        Ok(claims)
    } else {
        tracing::error!("Token expired: exp={} now={}", exp, now);
        Err(AppError::Unauthorized("Token expired".to_string()))
    }
}

// #[allow(dead_code)]
// async fn process_id_token(id_token: &str, config: &Config) -> Result<(), AppError> {
//     tracing::trace!("process_id_token called");
//     // DecodeProps を生成する。get_props_for_decode は公開鍵を取得し、デコードに必要な情報をまとめます。
//     let decode_props = get_props_for_decode(id_token, config).await?;
//
//     // IDトークンをデコードする。decode_id_token は Profile 型（email や name を含む）を返す
//     let profile = decode_id_token(id_token, &decode_props)?;
//
//     tracing::debug!("Decoded profile: {:?}", profile);
//     // ここで profile.email や profile.name を使えます。
//     Ok(())
// }
