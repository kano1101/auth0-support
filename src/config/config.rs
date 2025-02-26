// src/config/config.rs

use std::env;

pub trait ConfigGetTrait: Send + Sync {
    fn auth0_domain(&self) -> &str;
    fn client_id(&self) -> &str;
    fn client_secret(&self) -> &str;
    fn callback_url(&self) -> &str;
    fn audience(&self) -> &str;
    fn jwt_secret(&self) -> &str;
    fn testing_mode(&self) -> bool;
}

#[derive(Debug, Clone)]
pub struct Config {
    auth0_domain: String,
    client_id: String,
    client_secret: String,
    callback_url: String,
    audience: String,
    jwt_secret: String,
    testing_mode: bool,
}
#[cfg(any(test, feature = "integration-tests"))]
#[derive(Debug, Clone)]
pub struct TestConfig {
    pub auth0_domain: String,
    pub client_id: String,
    pub client_secret: String,
    pub callback_url: String,
    pub audience: String,
    pub jwt_secret: String,
    pub testing_mode: bool,
}
#[cfg(not(any(test, feature = "integration-tests")))]
#[derive(Debug, Clone)]
pub(crate) struct TestConfig {
    pub auth0_domain: String,
    pub client_id: String,
    pub client_secret: String,
    pub callback_url: String,
    pub audience: String,
    pub jwt_secret: String,
    pub testing_mode: bool,
}

#[derive(Debug, Clone)]
pub struct ConfigBuilder;

impl ConfigBuilder {
    pub fn new_as_production() -> Result<Config, env::VarError> {
        Config::from_env()
    }

    #[cfg(any(test, feature = "integration-tests"))]
    pub fn new_as_test() -> Result<TestConfig, env::VarError> {
        TestConfig::from_env()
    }

    #[cfg(not(any(test, feature = "integration-tests")))]
    pub(crate) fn new_as_test() -> Result<TestConfig, env::VarError> {
        TestConfig::from_env()
    }
}

impl Config {
    // 通常の環境変数から Config を作成（変更不可）
    pub fn from_env() -> Result<Self, env::VarError> {
        dotenv::dotenv().ok();
        Ok(Self {
            auth0_domain: env::var("AUTH0_DOMAIN")?,
            client_id: env::var("AUTH0_CLIENT_ID")?,
            client_secret: env::var("AUTH0_CLIENT_SECRET")?,
            callback_url: env::var("AUTH0_CALLBACK_URL")?,
            audience: env::var("AUTH0_AUDIENCE")?,
            jwt_secret: env::var("JWT_SECRET")?,
            testing_mode: false, // 通常は変更不可
        })
    }
}
impl ConfigGetTrait for Config {
// Getter メソッド
    fn auth0_domain(&self) -> &str {
        &self.auth0_domain
    }

    fn client_id(&self) -> &str {
        &self.client_id
    }

    fn client_secret(&self) -> &str {
        &self.client_secret
    }

    fn callback_url(&self) -> &str {
        &self.callback_url
    }

    fn audience(&self) -> &str {
        &self.audience
    }

    fn jwt_secret(&self) -> &str {
        &self.jwt_secret
    }

    fn testing_mode(&self) -> bool {
        self.testing_mode
    }
}
impl TestConfig {
// テスト環境用の Config を作成（変更可能）
    pub fn from_env() -> Result<Self, env::VarError> {
        dotenv::dotenv().ok();
        Ok(Self {
            auth0_domain: env::var("AUTH0_DOMAIN")?,
            client_id: env::var("AUTH0_CLIENT_ID")?,
            client_secret: env::var("AUTH0_CLIENT_SECRET")?,
            callback_url: env::var("AUTH0_CALLBACK_URL")?,
            audience: env::var("AUTH0_AUDIENCE")?,
            jwt_secret: env::var("JWT_SECRET")?,
            testing_mode: true, // テスト環境では変更可能にする
        })
    }
}
impl ConfigGetTrait for TestConfig {
    fn auth0_domain(&self) -> &str {
        &self.auth0_domain
    }

    fn client_id(&self) -> &str {
        &self.client_id
    }

    fn client_secret(&self) -> &str {
        &self.client_secret
    }

    fn callback_url(&self) -> &str {
        &self.callback_url
    }

    fn audience(&self) -> &str {
        &self.audience
    }

    fn jwt_secret(&self) -> &str {
        &self.jwt_secret
    }

    fn testing_mode(&self) -> bool {
        self.testing_mode
    }
}