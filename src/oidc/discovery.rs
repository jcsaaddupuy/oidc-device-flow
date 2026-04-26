use crate::error::{OdfError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Cached OIDC discovery document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryDocument {
    pub device_authorization_endpoint: String,
    pub token_endpoint: String,
    pub introspection_endpoint: Option<String>,
    pub issuer: String,
}

/// Cache entry with TTL.
#[derive(Debug, Serialize, Deserialize)]
struct CachedDiscovery {
    doc: DiscoveryDocument,
    fetched_at: i64,
    /// Cache TTL in seconds (default 3600)
    ttl: i64,
}

impl CachedDiscovery {
    fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        now - self.fetched_at > self.ttl
    }
}

pub fn cache_dir_path() -> Result<PathBuf> {
    // Respect XDG_CACHE_HOME if set
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg));
        }
    }
    let dir = dirs::cache_dir()
        .ok_or_else(|| OdfError::Discovery("Cannot determine cache directory".into()))?;
    Ok(dir)
}

pub fn cache_dir() -> Result<PathBuf> {
    Ok(cache_dir_path()?.join("odf").join("discovery"))
}

fn cache_path(name: &str) -> Result<PathBuf> {
    Ok(cache_dir()?.join(format!("{name}.json")))
}

/// Fetch the OIDC discovery document, using cache if fresh.
pub async fn discover(
    name: &str,
    issuer_url: &str,
    insecure: bool,
) -> Result<DiscoveryDocument> {
    // Check cache first
    if let Some(cached) = load_cache(name)? {
        if !cached.is_expired() {
            return Ok(cached.doc);
        }
    }

    // Fetch from issuer
    let url = format!("{}/.well-known/openid-configuration", issuer_url.trim_end_matches('/'));

    let client = build_client(insecure)?;
    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        return Err(OdfError::Discovery(format!(
            "Discovery endpoint returned {}: {}",
            resp.status(),
            resp.url()
        )));
    }

    let doc: serde_json::Value = resp.json().await?;

    let discovery = DiscoveryDocument {
        device_authorization_endpoint: doc["device_authorization_endpoint"]
            .as_str()
            .ok_or_else(|| {
                OdfError::Discovery(
                    "No device_authorization_endpoint in discovery document".into(),
                )
            })?
            .to_string(),
        token_endpoint: doc["token_endpoint"]
            .as_str()
            .ok_or_else(|| OdfError::Discovery("No token_endpoint in discovery document".into()))?
            .to_string(),
        introspection_endpoint: doc["introspection_endpoint"].as_str().map(String::from),
        issuer: doc["issuer"]
            .as_str()
            .unwrap_or(issuer_url)
            .to_string(),
    };

    // Cache it
    let cached = CachedDiscovery {
        doc: discovery.clone(),
        fetched_at: chrono::Utc::now().timestamp(),
        ttl: 3600,
    };
    save_cache(name, &cached)?;

    Ok(discovery)
}

/// Force re-fetch discovery.
#[allow(dead_code)]
pub async fn discover_force(
    name: &str,
    issuer_url: &str,
    insecure: bool,
) -> Result<DiscoveryDocument> {
    let path = cache_path(name)?;
    let _ = fs::remove_file(&path);
    discover(name, issuer_url, insecure).await
}

fn load_cache(name: &str) -> Result<Option<CachedDiscovery>> {
    let path = cache_path(name)?;
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(&path)?;
    let cached: CachedDiscovery = serde_json::from_str(&content)?;
    Ok(Some(cached))
}

fn save_cache(name: &str, cached: &CachedDiscovery) -> Result<()> {
    let dir = cache_dir()?;
    fs::create_dir_all(&dir)?;
    let path = cache_path(name)?;
    let json = serde_json::to_string_pretty(cached)?;
    fs::write(&path, json)?;
    Ok(())
}

/// Build an HTTP client with optional TLS verification skip.
fn build_client(insecure: bool) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();
    if insecure {
        builder = builder
            .danger_accept_invalid_certs(true);
    }
    Ok(builder.build()?)
}
