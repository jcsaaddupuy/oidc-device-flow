use crate::config::ProviderConfig;
use crate::error::{OdfError, Result};
use crate::oidc::device::save_login_result;
use crate::oidc::discovery;
use crate::store::TokenStore;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct RefreshResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    token_type: Option<String>,
    expires_in: Option<u64>,
    scope: Option<String>,
}

/// Refresh an access token using the stored refresh token.
pub async fn refresh_token(
    name: &str,
    config: &ProviderConfig,
    store: &dyn TokenStore,
) -> Result<LoginResult> {
    let refresh_token = store
        .get_refresh_token(name)?
        .ok_or_else(|| OdfError::Auth("No refresh token available".into()))?;

    let endpoint = resolve_token_endpoint(name, config).await?;

    let client = build_client(config.insecure)?;
    let params = [
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh_token),
        ("client_id", config.client_id.clone()),
    ];

    let resp = client.post(&endpoint).form(&params).send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(OdfError::Auth(format!(
            "Token refresh failed ({}): {}",
            status, body
        )));
    }

    let data: RefreshResponse = resp.json().await?;
    let result = LoginResult {
        access_token: data.access_token,
        refresh_token: data.refresh_token,
        token_type: data.token_type.unwrap_or_else(|| "Bearer".into()),
        expires_in: data.expires_in.unwrap_or(3600),
        scope: data.scope.unwrap_or_default(),
    };

    save_login_result(name, store, &result)?;
    Ok(result)
}

// Re-use LoginResult from device module
pub use crate::oidc::device::LoginResult;

async fn resolve_token_endpoint(name: &str, config: &ProviderConfig) -> Result<String> {
    if let Some(ref ep) = config.token_endpoint {
        return Ok(ep.clone());
    }
    let issuer = config
        .issuer_url
        .as_ref()
        .ok_or_else(|| OdfError::Config("Neither issuer_url nor token_endpoint set".into()))?;
    let doc = discovery::discover(name, issuer, config.insecure).await?;
    Ok(doc.token_endpoint)
}

fn build_client(insecure: bool) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();
    if insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    Ok(builder.build()?)
}
