use crate::config::ProviderConfig;
use crate::error::{OdfError, Result};
use crate::oidc::discovery;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct IntrospectResponse {
    active: bool,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    exp: Option<i64>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    username: Option<String>,
}

/// Result of token introspection.
#[allow(dead_code)]
pub struct IntrospectResult {
    pub active: bool,
    pub scope: Option<String>,
    pub expires_at: Option<i64>,
    pub client_id: Option<String>,
    pub username: Option<String>,
}

/// Introspect a token against the provider's introspection endpoint.
/// Returns None if the provider doesn't advertise an introspection endpoint.
pub async fn introspect(
    name: &str,
    config: &ProviderConfig,
    access_token: &str,
) -> Result<Option<IntrospectResult>> {
    let endpoint = match resolve_introspection_endpoint(name, config).await? {
        Some(ep) => ep,
        None => return Ok(None),
    };

    let client = build_client(config.insecure)?;
    let params = [("token", access_token.to_string())];

    let resp = client.post(&endpoint).form(&params).send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(OdfError::Introspect(format!(
            "Introspection failed ({}): {}",
            status, body
        )));
    }

    let data: IntrospectResponse = resp.json().await?;
    Ok(Some(IntrospectResult {
        active: data.active,
        scope: data.scope,
        expires_at: data.exp,
        client_id: data.client_id,
        username: data.username,
    }))
}

async fn resolve_introspection_endpoint(name: &str, config: &ProviderConfig) -> Result<Option<String>> {
    if config.token_endpoint.is_some() {
        // If no explicit introspection endpoint, try discovery
        if let Some(ref issuer) = config.issuer_url {
            let doc = discovery::discover(name, issuer, config.insecure).await?;
            Ok(doc.introspection_endpoint)
        } else {
            Ok(None)
        }
    } else if let Some(ref issuer) = config.issuer_url {
        let doc = discovery::discover(name, issuer, config.insecure).await?;
        Ok(doc.introspection_endpoint)
    } else {
        Ok(None)
    }
}

fn build_client(insecure: bool) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();
    if insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    Ok(builder.build()?)
}
