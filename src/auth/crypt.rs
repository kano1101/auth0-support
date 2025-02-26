use crate::errors::errors::AppError;
use crate::config::config::ConfigGetTrait;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize)]
struct StateClaims {
    // original_redirect_uriのことを指している
    redirect_uri: String,
    // その他必要なクレーム（例: nonce, expなど）
    exp: usize,
}

pub struct CryptState {
    config: Arc<dyn ConfigGetTrait>,
}

impl CryptState {
    pub fn new(config: Arc<dyn ConfigGetTrait>) -> Self {
        CryptState {
            config,
        }
    }
    #[allow(dead_code)]
    pub fn encrypt_state(&self, redirect_uri: &str, exp: Option<usize>) -> Result<String, AppError> {
        // 有効期限を設定（例: 10分後）
        let expiration = exp.unwrap_or_else(|| chrono::Utc::now().timestamp() as usize + 600);
        let claims = StateClaims {
            redirect_uri: redirect_uri.to_string(),
            exp: expiration,
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.jwt_secret().as_ref()),
        )
            .map_err(|e| AppError::InternalServerError(format!("JWT encode error: {}", e)))
    }
    pub fn decrypt_and_verify_state(&self, token: &str) -> Result<String, AppError> {
        let token_data: TokenData<StateClaims> = decode(
            token,
            &DecodingKey::from_secret(self.config.jwt_secret().as_ref()),
            &Validation::default(),
        )
            .map_err(|e| AppError::BadRequest(format!("Invalid state token: {}", e)))?;
        Ok(token_data.claims.redirect_uri)
    }
}

