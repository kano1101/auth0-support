use reqwest::Client;
use serde::Deserialize;
use crate::errors::errors::AppError;

#[derive(Deserialize)]
pub struct Jwks {
    #[allow(dead_code)]
    pub keys: Vec<Jwk>,
}

#[derive(Deserialize)]
pub struct Jwk {
    pub kty: String,        // Key Type, e.g., "RSA"
    pub kid: String,        // Key ID
    #[serde(rename = "use")]
    #[allow(dead_code)]
    pub use_field: String,  // Public Key Use, e.g., "sig"
    pub n: String,          // Modulus
    pub e: String,          // Exponent
}

pub async fn fetch_public_key(auth0_domain: &str, kid: &str) -> Result<(String, String), AppError> {
    let jwks_url = format!("{}/.well-known/jwks.json", auth0_domain);
    let client = Client::new();
    let res = client
        .get(&jwks_url)
        .send()
        .await
        .map_err(|e| AppError::InternalServerError(format!("Failed to fetch JWKS: {}", e)))?;

    // let status = res.status();
    let body_text = res.text().await.map_err(|e| {
        AppError::InternalServerError(format!("Failed to read JWKS response body: {}", e))
    })?;

    let jwks: Jwks = serde_json::from_str(&body_text).map_err(|e| {
        eprintln!("Failed to parse JWKS JSON: {}", e); // エラーメッセージを詳細に出力
        AppError::InternalServerError(format!("Failed to parse JWKS: {}", e))
    })?;

    // 指定されたkidに一致するキーを選択
    if let Some(jwk) = jwks.keys.iter().find(|key| key.kid == kid) {
        if jwk.kty != "RSA" {
            return Err(AppError::InternalServerError("JWK is not RSA type".to_string()));
        }
        Ok((jwk.n.clone(), jwk.e.clone()))
    } else {
        Err(AppError::InternalServerError(format!("No matching JWK found for kid: {}", kid)))
    }
}
