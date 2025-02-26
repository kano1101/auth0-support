use std::sync::Arc;
use axum::response::Redirect;
use crate::auth::crypt::CryptState;
use crate::config::config::Config;

pub fn redirect_to_login(original_redirect_uri: &str, config: Arc<Config>) -> Redirect {
    tracing::debug!("redirect_to_login called.");
    let exp = (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp() as usize;

    let crypt_state = CryptState::new(config.clone());
    let state_token = crypt_state
        .encrypt_state(&original_redirect_uri, Some(exp))
        .expect("Failed to generate state token");

    let auth_url = build_auth0_login_url(
        &config.auth0_domain(),
        &config.client_id(),
        &config.callback_url(),
        &config.audience(),
        &state_token,
    );

    tracing::debug!("redirect_to_login proceeded. auth_url: {}", auth_url);
    Redirect::temporary(&auth_url)
}

/// Auth0のログインURLを構築
fn build_auth0_login_url(
    domain: &str,
    client_id: &str,
    callback_url: &str,
    audience: &str,
    state_token: &str,
) -> String {
    format!(
        "{}/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid profile email&audience={}&state={}",
        domain, client_id, callback_url, audience, state_token
    )
}
