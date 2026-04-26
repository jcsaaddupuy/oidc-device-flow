use serde::{Deserialize, Serialize};

/// Provider configuration stored in ~/.config/odf/providers/<name>.toml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub client_id: String,
    pub issuer_url: Option<String>,
    pub device_auth_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub scopes: Vec<String>,
    pub audience: Option<String>,
    pub extra_params: Option<toml::Value>,
    /// Skip TLS verification (for self-hosted providers with self-signed certs)
    #[serde(default)]
    pub insecure: bool,
}

impl ProviderConfig {
    /// Resolve the device authorization endpoint.
    /// If explicitly set, use it. Otherwise, requires discovery from issuer_url.
    #[allow(dead_code)]
    pub fn device_auth_endpoint(&self) -> Option<&str> {
        self.device_auth_endpoint.as_deref()
    }

    /// Resolve the token endpoint.
    /// If explicitly set, use it. Otherwise, requires discovery from issuer_url.
    #[allow(dead_code)]
    pub fn token_endpoint(&self) -> Option<&str> {
        self.token_endpoint.as_deref()
    }

    /// Scopes as a space-separated string (OIDC convention)
    pub fn scope_string(&self) -> String {
        self.scopes.join(" ")
    }
}

use crate::error::{OdfError, Result};
use dirs::config_dir;
use std::fs;
use std::path::PathBuf;

pub fn config_dir_path() -> Result<PathBuf> {
    // Respect XDG_CONFIG_HOME if set
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg));
        }
    }
    let dir = config_dir()
        .ok_or_else(|| OdfError::Config("Cannot determine config directory".into()))?;
    Ok(dir)
}

pub fn providers_dir() -> Result<PathBuf> {
    Ok(config_dir_path()?.join("odf").join("providers"))
}

fn provider_path(name: &str) -> Result<PathBuf> {
    // Sanitize name: no path traversal
    if name.contains('/') || name.contains("..") {
        return Err(OdfError::Config(
            "Provider name cannot contain '/' or '..'".into(),
        ));
    }
    Ok(providers_dir()?.join(format!("{name}.toml")))
}

/// Save a provider config. Fails if name already exists unless `force` is true.
pub fn save(name: &str, config: &ProviderConfig, force: bool) -> Result<()> {
    let dir = providers_dir()?;
    fs::create_dir_all(&dir)?;

    let path = provider_path(name)?;
    if path.exists() && !force {
        return Err(OdfError::NameConflict(name.into()));
    }

    let toml_str = toml::to_string_pretty(config)
        .map_err(|e| OdfError::Config(format!("Failed to serialize config: {e}")))?;
    fs::write(&path, toml_str)?;
    Ok(())
}

/// Load a provider config by name.
pub fn load(name: &str) -> Result<ProviderConfig> {
    let path = provider_path(name)?;
    if !path.exists() {
        return Err(OdfError::NotFound(name.into()));
    }
    let content = fs::read_to_string(&path)?;
    let config: ProviderConfig = toml::from_str(&content)?;
    Ok(config)
}

/// List all registered provider names.
pub fn list() -> Result<Vec<String>> {
    let dir = providers_dir()?;
    if !dir.exists() {
        return Ok(vec![]);
    }
    let mut names = vec![];
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "toml") {
            if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                names.push(name.to_string());
            }
        }
    }
    names.sort();
    Ok(names)
}

/// Remove a provider config by name.
pub fn remove(name: &str) -> Result<()> {
    let path = provider_path(name)?;
    if !path.exists() {
        return Err(OdfError::NotFound(name.into()));
    }
    fs::remove_file(&path)?;
    Ok(())
}

/// Check if a provider name already exists.
pub fn exists(name: &str) -> Result<bool> {
    Ok(provider_path(name)?.exists())
}
