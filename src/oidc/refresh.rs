use crate::config::ProviderConfig;
use crate::error::{OdfError, Result};
use crate::oidc::device::save_login_result;
use crate::oidc::discovery;
use crate::store::TokenStore;
use crate::store::file;
use fs2::FileExt;
use serde::Deserialize;
use std::fs::OpenOptions;

#[derive(Debug, Deserialize)]
struct RefreshResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    token_type: Option<String>,
    expires_in: Option<u64>,
    scope: Option<String>,
}

/// Acquire an exclusive file lock for token operations.
/// Returns the locked file handle. The lock is released when dropped.
fn acquire_token_lock(name: &str) -> Result<std::fs::File> {
    file::ensure_tokens_dir()?;
    let lock_path = file::tokens_dir()?.join(format!("{name}.lock"));
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(&lock_path)?;
    
    // Exclusive lock (blocking) - waits until lock is available
    file.lock_exclusive()
        .map_err(|e| OdfError::Store(format!("Failed to acquire token lock: {e}")))?;
    
    Ok(file)
}

/// Refresh an access token using the stored refresh token.
/// Uses file locking to prevent race conditions with refresh token rotation.
pub async fn refresh_token(
    name: &str,
    config: &ProviderConfig,
    store: &dyn TokenStore,
) -> Result<LoginResult> {
    // Acquire exclusive lock to prevent concurrent refresh attempts
    let _lock = acquire_token_lock(name)?;
    
    // Re-read the token data under lock to ensure we have latest state
    let token_data = file::load_token_data(name)?
        .ok_or_else(|| OdfError::Auth("No token data found".into()))?;
    
    let refresh_token = token_data.refresh_token
        .ok_or_else(|| OdfError::Auth("No refresh token available".into()))?;

    let endpoint = resolve_token_endpoint(name, config).await?;

    let client = build_client(config.insecure)?;
    
    // Build params - some providers require scope in refresh requests
    let mut params = vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh_token.clone()),
        ("client_id", config.client_id.clone()),
    ];
    
    // Include client_secret if configured (required for confidential clients)
    // Dex and other OIDC providers require this for refresh_token grant
    if let Some(ref secret) = config.client_secret {
        params.push(("client_secret", secret.clone()));
    }
    
    // Include original scopes if configured (some providers require this)
    if !config.scopes.is_empty() {
        let scope_str = config.scope_string();
        params.push(("scope", scope_str));
    }
    
    // Include redirect_uri if configured (required by some providers like Trakt.tv)
    if let Some(ref redirect_uri) = config.redirect_uri {
        params.push(("redirect_uri", redirect_uri.clone()));
    }

    let resp = client.post(&endpoint).form(&params).send().await?;
    
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        
        // Provide more helpful error context
        let hint = match status.as_u16() {
            400 => {
                // Parse OAuth error for better message
                if let Ok(err) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(error) = err.get("error").and_then(|e| e.as_str()) {
                        match error {
                            "invalid_grant" => "Refresh token expired or revoked. Re-login required.".into(),
                            "invalid_client" => "Client ID not recognized.".into(),
                            "unauthorized_client" => "Client not authorized for refresh grant.".into(),
                            "unsupported_grant_type" => "Server doesn't support refresh token grant.".into(),
                            "invalid_scope" => "Requested scope not authorized.".into(),
                            _ => format!("OAuth error: {}", error)
                        }
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                }
            }
            500 => "Server error - may be temporary or configuration issue.".into(),
            _ => String::new(),
        };
        
        let msg = if hint.is_empty() {
            format!("Token refresh failed ({}): {}", status, body)
        } else {
            format!("Token refresh failed ({}): {}\n  Hint: {}", status, body, hint)
        };
        
        return Err(OdfError::Auth(msg));
    }

    let data: RefreshResponse = resp.json().await?;
    
    // CRITICAL: If server doesn't return a new refresh token, preserve the old one.
    // Many OAuth/OIDC providers reuse the same refresh token across refresh operations.
    // For providers using refresh token rotation, they MUST return a new refresh token.
    let new_refresh_token = data.refresh_token.or(Some(refresh_token));
    
    let result = LoginResult {
        access_token: data.access_token,
        refresh_token: new_refresh_token,
        token_type: data.token_type.unwrap_or_else(|| "Bearer".into()),
        expires_in: data.expires_in.unwrap_or(3600),
        scope: data.scope.unwrap_or_default(),
    };

    save_login_result(name, store, &result)?;
    
    // Lock released when _lock goes out of scope
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
