// src/config/config.rs

use std::env;

pub trait ConfigGetTrait: Send + Sync {
    fn domain(&self) -> &str;
    fn client_id(&self) -> &str;
    fn client_secret(&self) -> &str;
    fn audience(&self) -> &str;
    fn jwt_secret(&self) -> &str;
    fn callback_url(&self) -> &str;
    fn fallback_uri(&self) -> &str;
    fn allowed_redirect_uris(&self) -> Vec<&str>;
    fn testing_mode(&self) -> bool;
}

#[derive(Clone)]
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
#[derive(Clone)]
pub struct TestConfig {
    pub domain: String,
    pub client_id: String,
    pub client_secret: String,
    pub callback_url: String,
    pub audience: String,
    pub jwt_secret: String,
    pub fallback_uri: String,
    pub allowed_redirect_uris: Vec<String>,
    pub testing_mode: bool,
}

impl Config {
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
}
impl TestConfig {
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
}

impl ConfigGetTrait for Config {
    fn domain(&self) -> &str {
        &self.domain
    }

    fn client_id(&self) -> &str {
        &self.client_id
    }

    fn client_secret(&self) -> &str {
        &self.client_secret
    }

    fn audience(&self) -> &str {
        &self.audience
    }

    fn jwt_secret(&self) -> &str {
        &self.jwt_secret
    }

    fn callback_url(&self) -> &str {
        &self.callback_url
    }

    fn fallback_uri(&self) -> &str {
        &self.fallback_uri
    }

    fn allowed_redirect_uris(&self) -> Vec<&str> {
        self.allowed_redirect_uris.iter().map(|s| s.as_str()).collect()
    }

    fn testing_mode(&self) -> bool {
        self.testing_mode
    }
}
impl ConfigGetTrait for TestConfig {
    fn domain(&self) -> &str {
        &self.domain
    }

    fn client_id(&self) -> &str {
        &self.client_id
    }

    fn client_secret(&self) -> &str {
        &self.client_secret
    }

    fn audience(&self) -> &str {
        &self.audience
    }

    fn jwt_secret(&self) -> &str {
        &self.jwt_secret
    }

    fn callback_url(&self) -> &str {
        &self.callback_url
    }

    fn fallback_uri(&self) -> &str {
        &self.fallback_uri
    }

    fn allowed_redirect_uris(&self) -> Vec<&str> {
        self.allowed_redirect_uris.iter().map(|s| s.as_str()).collect()
    }

    fn testing_mode(&self) -> bool {
        self.testing_mode
    }
}
