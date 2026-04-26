use crate::config::ProviderConfig;
use crate::error::{OdfError, Result};
use crate::oidc::discovery;
use crate::store::file::{self, TokenData, TokenMetadata};
use crate::store::TokenStore;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(rename = "verification_uri_complete")]
    verification_uri_complete: Option<String>,
    #[serde(default = "default_interval")]
    interval: u64,
    expires_in: Option<u64>,
}

fn default_interval() -> u64 {
    5
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    token_type: Option<String>,
    expires_in: Option<u64>,
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenErrorResponse {
    error: String,
    #[serde(rename = "error_description")]
    error_description: Option<String>,
}

/// Result of a successful device flow login.
pub struct LoginResult {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: String,
    #[allow(dead_code)]
    pub expires_in: u64,
    pub scope: String,
}

/// Initiate device flow: request device code, return verification info.
pub async fn request_device_code(
    config: &ProviderConfig,
    insecure: bool,
) -> Result<(String, String, String, Option<String>, u64)> {
    let endpoint = resolve_device_auth_endpoint(config, insecure).await?;

    let client = build_client(insecure)?;
    let params = vec![
        ("client_id", config.client_id.clone()),
        ("scope", config.scope_string()),
    ];

    let resp = client.post(&endpoint).form(&params).send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(OdfError::DeviceFlow(format!(
            "Device code request failed ({}): {}",
            status, body
        )));
    }

    let data: DeviceCodeResponse = resp.json().await?;

    Ok((
        data.device_code,
        data.user_code,
        data.verification_uri,
        data.verification_uri_complete,
        data.interval,
    ))
}

/// Poll the token endpoint until the user authorizes or an error occurs.
/// Displays a spinner on TTY, silent otherwise.
pub async fn poll_for_token(
    config: &ProviderConfig,
    device_code: &str,
    interval: u64,
    insecure: bool,
) -> Result<LoginResult> {
    let endpoint = resolve_token_endpoint(config, insecure).await?;
    let client = build_client(insecure)?;

    let spinner = if atty::is(atty::Stream::Stderr) {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::with_template("{spinner} {msg}")
                .unwrap()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        pb.set_message("Waiting for authorization...");
        Some(pb)
    } else {
        None
    };

    let mut interval = interval;
    let mut current_interval = interval;

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(current_interval)).await;

        let params = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code".to_string()),
            ("device_code", device_code.to_string()),
            ("client_id", config.client_id.clone()),
        ];

        let resp = client.post(&endpoint).form(&params).send().await?;
        let body = resp.text().await?;

        // Try to parse as success
        if let Ok(token) = serde_json::from_str::<TokenResponse>(&body) {
            if let Some(spinner) = &spinner {
                spinner.finish_with_message("✓ Authorized");
            }
            return Ok(LoginResult {
                access_token: token.access_token,
                refresh_token: token.refresh_token,
                token_type: token.token_type.unwrap_or_else(|| "Bearer".into()),
                expires_in: token.expires_in.unwrap_or(3600),
                scope: token.scope.unwrap_or_default(),
            });
        }

        // Parse as error
        if let Ok(err) = serde_json::from_str::<TokenErrorResponse>(&body) {
            match err.error.as_str() {
                "authorization_pending" => {
                    if let Some(spinner) = &spinner {
                        spinner.tick();
                    }
                    current_interval = interval;
                    continue;
                }
                "slow_down" => {
                    interval += 5;
                    current_interval = interval;
                    if let Some(spinner) = &spinner {
                        spinner.tick();
                    }
                    continue;
                }
                _ => {
                    if let Some(spinner) = &spinner {
                        spinner.finish_with_message("✗ Authorization failed");
                    }
                    return Err(OdfError::DeviceFlow(format!(
                        "{}: {}",
                        err.error,
                        err.error_description.unwrap_or_default()
                    )));
                }
            }
        }

        // Unknown response
        return Err(OdfError::DeviceFlow(format!("Unexpected token response: {body}")));
    }
}

/// Save login result using the appropriate store backend.
pub fn save_login_result(name: &str, store: &dyn TokenStore, result: &LoginResult) -> Result<()> {
    let expires_at = chrono::Utc::now().timestamp() + result.expires_in as i64;

    if config_store_is_keyring(name)? {
        // Secrets to keyring, metadata to file
        store.set_access_token(name, &result.access_token)?;
        if let Some(ref rt) = result.refresh_token {
            store.set_refresh_token(name, rt)?;
        }
        let meta = TokenMetadata {
            token_type: result.token_type.clone(),
            expires_at,
            scope: result.scope.clone(),
            store: "keyring".into(),
        };
        file::save_metadata(name, &meta)?;
    } else {
        // Everything to file
        let data = TokenData {
            access_token: result.access_token.clone(),
            refresh_token: result.refresh_token.clone(),
            token_type: result.token_type.clone(),
            expires_at,
            scope: result.scope.clone(),
        };
        file::save_token_data(name, &data)?;
    }

    Ok(())
}

fn config_store_is_keyring(name: &str) -> Result<bool> {
    match crate::config::load(name) {
        Ok(cfg) => Ok(cfg.store == "keyring"),
        Err(_) => Ok(false),
    }
}

/// Resolve the device authorization endpoint from config or discovery.
async fn resolve_device_auth_endpoint(config: &ProviderConfig, insecure: bool) -> Result<String> {
    if let Some(ref ep) = config.device_auth_endpoint {
        return Ok(ep.clone());
    }
    let issuer = config
        .issuer_url
        .as_ref()
        .ok_or_else(|| OdfError::Config("Neither issuer_url nor device_auth_endpoint set".into()))?;
    let doc = discovery::discover("__resolve__", issuer, insecure).await?;
    Ok(doc.device_authorization_endpoint)
}

/// Resolve the token endpoint from config or discovery.
async fn resolve_token_endpoint(config: &ProviderConfig, insecure: bool) -> Result<String> {
    if let Some(ref ep) = config.token_endpoint {
        return Ok(ep.clone());
    }
    let issuer = config
        .issuer_url
        .as_ref()
        .ok_or_else(|| OdfError::Config("Neither issuer_url nor token_endpoint set".into()))?;
    let doc = discovery::discover("__resolve__", issuer, insecure).await?;
    Ok(doc.token_endpoint)
}

fn build_client(insecure: bool) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();
    if insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    Ok(builder.build()?)
}
