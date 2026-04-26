use crate::encryption::{decrypt_from_string, encrypt_to_string, is_encryption_enabled};
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

/// Path for encrypted token (.json.age)
fn encrypted_token_path(name: &str) -> Result<PathBuf> {
    if name.contains('/') || name.contains("..") {
        return Err(OdfError::Store("Token name cannot contain '/' or '..'".into()));
    }
    Ok(tokens_dir()?.join(format!("{name}.json.age")))
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

// ─── TokenStore implementation ───

pub struct FileTokenStore;

impl TokenStore for FileTokenStore {
    fn get_access_token(&self, name: &str) -> Result<Option<String>> {
        let data = load_token_data(name)?;
        Ok(data.map(|d| d.access_token))
    }

    fn get_refresh_token(&self, name: &str) -> Result<Option<String>> {
        let data = load_token_data(name)?;
        Ok(data.and_then(|d| d.refresh_token))
    }

    fn set_access_token(&self, _name: &str, _token: &str) -> Result<()> {
        // Not used - we save full TokenData instead
        Err(OdfError::Store("Use save_token_data instead".into()))
    }

    fn set_refresh_token(&self, _name: &str, _token: &str) -> Result<()> {
        // Not used - we save full TokenData instead
        Err(OdfError::Store("Use save_token_data instead".into()))
    }

    fn delete_tokens(&self, name: &str) -> Result<()> {
        delete_token_files(name)
    }
}

/// Load token info (metadata only, no secrets).
pub fn load_token_info(name: &str) -> Result<Option<TokenInfo>> {
    let data = load_token_data(name)?;
    Ok(data.map(|d| TokenInfo {
        expires_at: d.expires_at,
        scope: d.scope,
        token_type: d.token_type,
    }))
}

/// Save full token data.
/// If encryption is enabled, encrypts before writing to .json.age.
/// Otherwise writes plain JSON to .json.
pub fn save_token_data(name: &str, data: &TokenData) -> Result<()> {
    ensure_tokens_dir()?;
    
    if is_encryption_enabled() {
        let encrypted_path = encrypted_token_path(name)?;
        let plain_path = token_path(name)?;
        
        // Encrypt and save
        let json = serde_json::to_string_pretty(data)?;
        let encrypted = encrypt_to_string(&json)?;
        atomic_write(&encrypted_path, &encrypted, 0o600)?;
        
        // Remove any existing plain file
        if plain_path.exists() {
            fs::remove_file(&plain_path)?;
        }
    } else {
        let path = token_path(name)?;
        let json = serde_json::to_string_pretty(data)?;
        atomic_write(&path, &json, 0o600)?;
        
        // Remove any existing encrypted file
        let encrypted_path = encrypted_token_path(name)?;
        if encrypted_path.exists() {
            fs::remove_file(&encrypted_path)?;
        }
    }
    
    Ok(())
}

/// Delete both encrypted and plain token files for a provider.
pub fn delete_token_files(name: &str) -> Result<()> {
    let plain_path = token_path(name)?;
    let encrypted_path = encrypted_token_path(name)?;
    
    if plain_path.exists() {
        fs::remove_file(&plain_path)?;
    }
    if encrypted_path.exists() {
        fs::remove_file(&encrypted_path)?;
    }
    
    Ok(())
}

/// Load full token data from disk.
/// Tries .json.age (encrypted) first, then .json (plain).
fn load_token_data(name: &str) -> Result<Option<TokenData>> {
    // Try encrypted first
    let encrypted_path = encrypted_token_path(name)?;
    if encrypted_path.exists() {
        let content = fs::read_to_string(&encrypted_path)?;
        let decrypted = decrypt_from_string(&content)?;
        let data: TokenData = serde_json::from_str(&decrypted)?;
        return Ok(Some(data));
    }
    
    // Try plain
    let plain_path = token_path(name)?;
    if !plain_path.exists() {
        return Ok(None);
    }
    
    let content = fs::read_to_string(&plain_path)?;
    match serde_json::from_str::<TokenData>(&content) {
        Ok(data) => Ok(Some(data)),
        Err(_) => {
            // File might be old metadata-only format
            Ok(None)
        }
    }
}

/// Save only metadata (non-secret part).
#[allow(dead_code)]
pub fn save_metadata(name: &str, meta: &TokenMetadata) -> Result<()> {
    ensure_tokens_dir()?;
    let path = token_path(name)?;
    let json = serde_json::to_string_pretty(meta)?;
    atomic_write(&path, &json, 0o600)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_path_no_traversal() {
        assert!(token_path("../../../etc/passwd").is_err());
        assert!(token_path("foo/bar").is_err());
        assert!(token_path("valid-name").is_ok());
    }
}