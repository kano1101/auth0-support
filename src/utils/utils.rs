use std::sync::Arc;
use crate::config::config::Config;
use crate::errors::errors::AppError;
use crate::utils::jwks::fetch_public_key;
use jsonwebtoken::{
    decode, decode_header, Algorithm, DecodingKey, Header, Validation,
};

use axum::response::Response;
use serde::de::DeserializeOwned;
use serde_json::Value;

pub fn handle_token_error(error_code: &str) -> Result<Response, AppError> {
    match error_code {
        "invalid_grant" => Err(AppError::BadRequest(
            "Invalid authorization code".to_string(),
        )),
        _ => Err(AppError::InternalServerError(format!(
            "Unknown error from token endpoint: {}",
            error_code
        ))),
    }
}

pub fn build_token_request_params(
    client_id: &str,
    client_secret: &str,
    code: &str,
    callback_url: &str,
) -> Vec<(String, String)> {
    vec![
        ("grant_type".into(), "authorization_code".into()),
        ("client_id".into(), client_id.into()),
        ("client_secret".into(), client_secret.into()),
        ("code".into(), code.into()),
        ("redirect_uri".into(), callback_url.into()),
    ]
}

pub fn is_allowed_redirect(uri: &str, allowed_redirect_uris: Vec<&str>) -> bool {
    // 許可したいリダイレクト先の URI をここに追加・編集する
    allowed_redirect_uris.contains(&uri)
}

pub fn extract_access_token(tokens: &Value) -> Result<String, AppError> {
    tokens
        .get("access_token")
        .and_then(|t| Some(t.to_string()))
        .ok_or_else(|| AppError::InternalServerError("access_token not found".into()))
}

pub fn extract_id_token(tokens: &Value) -> Result<String, AppError> {
    tokens
        .get("id_token")
        .and_then(|t| Some(t.to_string()))
        .ok_or_else(|| AppError::InternalServerError("id_token not found".into()))
}

pub struct DecodeProps {
    decoding_key: DecodingKey,
    audience: Vec<String>,
    #[allow(dead_code)]
    auth0_domain: Vec<String>,
}

pub async fn get_props_for_decode(
    access_token: &str,
    config: Arc<Config>,
) -> Result<DecodeProps, AppError> {
    tracing::trace!("get_props_for_decode called");
    let decoding_key = get_decoding_key(access_token, config.clone()).await?;
    let audience = vec![config.audience().to_string()];
    let auth0_domain = vec![config.auth0_domain().to_string()];
    Ok(DecodeProps {
        decoding_key,
        audience,
        auth0_domain,
    })
}

async fn get_decoding_key(access_token: &str, config: Arc<Config>) -> Result<DecodingKey, AppError> {
    tracing::trace!("get_decoding_key called");
    // ここでは公開鍵をあらかじめ取得済みまたはキャッシュ済みと仮定する
    // 本来は Auth0 の JWKS エンドポイントから kid をキーに公開鍵を取得します
    // JWTのヘッダーからkidを抽出
    let kid = extract_kid(access_token)?;
    // 公開鍵を取得（kidに基づいて）
    let (public_key_n, public_key_e) = fetch_public_key(&config.auth0_domain(), &kid).await?;

    // DecodingKey を生成
    let decoding_key = DecodingKey::from_rsa_components(&public_key_n, &public_key_e)
        .map_err(|_| AppError::Unauthorized("Invalid RSA key".to_string()))?;

    Ok(decoding_key)
}

fn extract_kid(token: &str) -> Result<String, AppError> {
    tracing::trace!("extract_kid called");
    let header: Header = decode_header(token)
        .map_err(|e| AppError::Unauthorized(format!("Failed to decode JWT header: {}", e)))?;
    if let Some(kid) = header.kid {
        Ok(kid)
    } else {
        Err(AppError::Unauthorized(
            "No kid found in JWT header".to_string(),
        ))
    }
}

pub fn decode_id_token<Profile: DeserializeOwned>(id_token: &str, decode_props: &DecodeProps) -> Result<Profile, AppError> {
    tracing::trace!("decode_id_token called");
    let decoding_key = &decode_props.decoding_key;
    let audience: Vec<&str> = decode_props.audience.iter().map(String::as_str).collect();
    let _audience: &[&str] = &audience;
    // tracing::warn!("audience(id): {:?}", audience);
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["saQoAaCmOzUu5eQoZ2XVJXzI8tSpPow4"]);
    // validation.set_audience(audience);
    // validation.set_issuer(issuer);
    decode::<Profile>(id_token, decoding_key, &validation)
        .map(|data| data.claims)
        .map_err(|e| AppError::Unauthorized(format!("Failed to decode id token: {}", e)))
}

pub fn decode_jwt<Claims: DeserializeOwned>(access_token: &str, decode_props: &DecodeProps) -> Result<Claims, AppError> {
    tracing::trace!("decode_jwt called");
    let decoding_key = &decode_props.decoding_key;
    // tracing::warn!("decoding_key: {:?}", decoding_key);
    let audience: Vec<&str> = decode_props.audience.iter().map(String::as_str).collect();
    let audience: &[&str] = &audience;
    // tracing::warn!("audience(access): {:?}", audience);
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;
    validation.set_audience(audience);
    // validation.set_issuer(issuer);

    decode::<Claims>(access_token, decoding_key, &validation)
        .map(|data| data.claims)
        .map_err(|e| AppError::Unauthorized(format!("Failed to decode access token: {}", e)))
}
