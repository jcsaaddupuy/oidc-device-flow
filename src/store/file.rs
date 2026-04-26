use crate::error::{OdfError, Result};
use crate::store::TokenStore;
use dirs::data_local_dir;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// Token metadata stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenMetadata {
    pub token_type: String,
    pub expires_at: i64,
    pub scope: String,
}

/// Full token data as returned by the OIDC token endpoint.
/// Stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenData {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_at: i64,
    pub scope: String,
}

/// Unified token info loaded from disk.
#[derive(Debug)]
#[allow(dead_code)]
pub struct TokenInfo {
    pub expires_at: i64,
    pub scope: String,
    pub token_type: String,
}

pub fn data_dir() -> Result<PathBuf> {
    // Respect XDG_DATA_HOME if set
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg));
        }
    }
    let dir = data_local_dir()
        .ok_or_else(|| OdfError::Store("Cannot determine data directory".into()))?;
    Ok(dir)
}

pub fn tokens_dir() -> Result<PathBuf> {
    Ok(data_dir()?.join("odf").join("tokens"))
}

fn token_path(name: &str) -> Result<PathBuf> {
    if name.contains('/') || name.contains("..") {
        return Err(OdfError::Store("Token name cannot contain '/' or '..'".into()));
    }
    Ok(tokens_dir()?.join(format!("{name}.json")))
}

/// Ensure the tokens directory exists with 0o700 permissions.
fn ensure_tokens_dir() -> Result<PathBuf> {
    let dir = tokens_dir()?;
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        let perms = fs::Permissions::from_mode(0o700);
        fs::set_permissions(&dir, perms)?;
    }
    Ok(dir)
}

/// Atomic write: write to .tmp then rename.
fn atomic_write(path: &PathBuf, content: &str, mode: u32) -> Result<()> {
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, content)?;
    let perms = fs::Permissions::from_mode(mode);
    fs::set_permissions(&tmp_path, perms)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Load unified token info from disk.
pub fn load_token_info(name: &str) -> Result<Option<TokenInfo>> {
    let path = token_path(name)?;
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(&path)?;

    // Try TokenData first
    if let Ok(data) = serde_json::from_str::<TokenData>(&content) {
        return Ok(Some(TokenInfo {
            expires_at: data.expires_at,
            scope: data.scope,
            token_type: data.token_type,
        }));
    }

    // Try TokenMetadata
    if let Ok(meta) = serde_json::from_str::<TokenMetadata>(&content) {
        return Ok(Some(TokenInfo {
            expires_at: meta.expires_at,
            scope: meta.scope,
            token_type: meta.token_type,
        }));
    }

    Err(OdfError::Store(format!("Cannot parse token file for '{name}'")))
}

/// File-backed token store: secrets stored in JSON files with chmod 600.
pub struct FileTokenStore;

impl TokenStore for FileTokenStore {
    fn get_access_token(&self, name: &str) -> Result<Option<String>> {
        let data = load_full_token_data(name)?;
        Ok(data.map(|d| d.access_token))
    }

    fn get_refresh_token(&self, name: &str) -> Result<Option<String>> {
        let data = load_full_token_data(name)?;
        Ok(data.and_then(|d| d.refresh_token))
    }

    fn set_access_token(&self, name: &str, token: &str) -> Result<()> {
        let mut data = load_full_token_data(name)?.unwrap_or(TokenData {
            access_token: String::new(),
            refresh_token: None,
            token_type: "Bearer".into(),
            expires_at: 0,
            scope: String::new(),
        });
        data.access_token = token.to_string();
        save_token_data(name, &data)
    }

    fn set_refresh_token(&self, name: &str, token: &str) -> Result<()> {
        let mut data = load_full_token_data(name)?.unwrap_or(TokenData {
            access_token: String::new(),
            refresh_token: None,
            token_type: "Bearer".into(),
            expires_at: 0,
            scope: String::new(),
        });
        data.refresh_token = Some(token.to_string());
        save_token_data(name, &data)
    }

    fn delete_tokens(&self, name: &str) -> Result<()> {
        let path = token_path(name)?;
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }
}

/// Save full token data atomically with chmod 600.
pub fn save_token_data(name: &str, data: &TokenData) -> Result<()> {
    ensure_tokens_dir()?;
    let path = token_path(name)?;
    let json = serde_json::to_string_pretty(data)?;
    atomic_write(&path, &json, 0o600)
}

/// Load full token data from disk.
fn load_full_token_data(name: &str) -> Result<Option<TokenData>> {
    let path = token_path(name)?;
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(&path)?;
    match serde_json::from_str::<TokenData>(&content) {
        Ok(data) => Ok(Some(data)),
        Err(_) => {
            // File is in metadata-only format — no secrets on disk
            Ok(None)
        }
    }
}

/// Save only metadata (non-secret part) — used when secrets go to keyring.
pub fn save_metadata(name: &str, meta: &TokenMetadata) -> Result<()> {
    ensure_tokens_dir()?;
    let path = token_path(name)?;
    let json = serde_json::to_string_pretty(meta)?;
    atomic_write(&path, &json, 0o600)
}

/// Delete token data for a provider.
pub fn delete_token_file(name: &str) -> Result<()> {
    let path = token_path(name)?;
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}
