// src/config/config.rs

use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    domain: String,
    client_id: String,
    client_secret: String,
    callback_url: String,
    audience: String,
    jwt_secret: String,
    fallback_uri: String,
    allowed_redirect_uris: Vec<String>,
    testing_mode: bool,
}

impl Config {
    // 通常の環境変数から Config を作成（変更不可）
    pub fn from_env() -> Result<Self, env::VarError> {
        dotenv::dotenv().ok();
        Ok(Self {
            domain: env::var("AUTH0_DOMAIN")?,
            client_id: env::var("AUTH0_CLIENT_ID")?,
            client_secret: env::var("AUTH0_CLIENT_SECRET")?,
            audience: env::var("AUTH0_AUDIENCE")?,
            jwt_secret: env::var("JWT_SECRET")?,
            callback_url: env::var("AUTH0_CALLBACK_URL")?,
            fallback_uri: env::var("FALLBACK_URI")?,
            allowed_redirect_uris: env::var("ALLOWED_REDIRECT_URIS")?
                .split(',')
                .map(String::from)
                .collect(),
            testing_mode: env::var("TESTING_MODE")
                .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"))
                .unwrap_or(false),
        })
    }
    
    pub fn auth0_domain(&self) -> &str {
        &self.domain
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn client_secret(&self) -> &str {
        &self.client_secret
    }

    pub fn callback_url(&self) -> &str {
        &self.callback_url
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    pub fn jwt_secret(&self) -> &str {
        &self.jwt_secret
    }

    pub fn fallback_uri(&self) -> &str {
        &self.fallback_uri
    }

    pub fn allowed_redirect_uris(&self) -> Vec<&str> {
        self.allowed_redirect_uris.iter().map(|s| s.as_str()).collect()
    }

    pub fn testing_mode(&self) -> bool {
        self.testing_mode
    }
}
