//! Age encryption support for token storage.
//!
//! Key lookup priority:
//! 1. ODF_AGE_PRIVATE_KEY + ODF_AGE_PUBLIC_KEY env vars
//! 2. ODF_AGE_KEY_FILE env var (path to identity file)
//! 3. ~/.config/odf/encryption/identity (default)

use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;

use crate::error::{OdfError, Result};

/// Age identity file location.
pub fn identity_file_path() -> Result<PathBuf> {
    let config_dir = crate::config::config_dir_path()?;
    Ok(config_dir.join("encryption").join("identity"))
}

/// Check if encryption is enabled (key exists or env vars set).
pub fn is_encryption_enabled() -> bool {
    // Check env vars first
    if std::env::var("ODF_AGE_PRIVATE_KEY").is_ok() {
        return true;
    }
    if std::env::var("ODF_AGE_KEY_FILE").is_ok() {
        return true;
    }
    // Check default file location
    identity_file_path().map(|p| p.exists()).unwrap_or(false)
}

/// x25519 Identity wrapper that stores the secret and public key.
pub struct AgeIdentity {
    /// The secret key (AGE-SECRET-KEY-1...)
    secret: String,
    /// The public key (age1...)
    public: String,
}

impl AgeIdentity {
    /// Generate a new age identity.
    pub fn generate() -> Result<Self> {
        use age::secrecy::ExposeSecret;
        
        let identity = age::x25519::Identity::generate();
        let secret = identity.to_string().expose_secret().to_string();
        let public = identity.to_public().to_string();
        Ok(Self { secret, public })
    }
    
    /// Parse from secret key string.
    pub fn from_secret(secret: &str) -> Result<Self> {
        let secret = secret.trim().to_string();
        
        // Parse the secret key as x25519 identity
        let x25519_identity = age::x25519::Identity::from_str(&secret)
            .map_err(|e| OdfError::Config(format!("Failed to parse identity: {}", e)))?;
        
        // Derive the public key
        let public = x25519_identity.to_public().to_string();
        
        Ok(Self { secret, public })
    }
    
    /// Get the secret key (AGE-SECRET-KEY-1...)
    pub fn secret(&self) -> &str {
        &self.secret
    }
    
    /// Get the public key (age1...)
    pub fn public(&self) -> &str {
        &self.public
    }
    
    /// Get recipient for encryption.
    pub fn recipient(&self) -> age::x25519::Recipient {
        age::x25519::Recipient::from_str(&self.public)
            .expect("Public key should be valid")
    }
    
    /// Get identity for decryption.
    pub fn x25519_identity(&self) -> age::x25519::Identity {
        age::x25519::Identity::from_str(&self.secret)
            .expect("Secret key should be valid")
    }
}

/// Load identity from env vars or file.
pub fn load_identity() -> Result<AgeIdentity> {
    // Priority 1: Inline env vars
    if let Ok(private_key) = std::env::var("ODF_AGE_PRIVATE_KEY") {
        if let Ok(public_key) = std::env::var("ODF_AGE_PUBLIC_KEY") {
            return Ok(AgeIdentity {
                secret: private_key.trim().to_string(),
                public: public_key.trim().to_string(),
            });
        }
        // Derive public key from private key
        return AgeIdentity::from_secret(&private_key);
    }

    // Priority 2: Custom key file
    if let Ok(key_file) = std::env::var("ODF_AGE_KEY_FILE") {
        return load_identity_from_file(&PathBuf::from(key_file));
    }

    // Priority 3: Default file location
    let path = identity_file_path()?;
    if path.exists() {
        return load_identity_from_file(&path);
    }

    Err(OdfError::Config("No age identity found. Run 'odf config encryption generate' or set ODF_AGE_PRIVATE_KEY".into()))
}

/// Load identity from file.
fn load_identity_from_file(path: &PathBuf) -> Result<AgeIdentity> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| OdfError::Config(format!("Failed to read identity file {}: {}", path.display(), e)))?;
    AgeIdentity::from_secret(&content)
}

/// Encrypt plaintext to bytes.
pub fn encrypt(plaintext: &str) -> Result<Vec<u8>> {
    let identity = load_identity()?;
    let recipient = identity.recipient();
    
    let encryptor = age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
        .map_err(|e| OdfError::Config(format!("Failed to create encryptor: {}", e)))?;
    
    let mut encrypted = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted)
        .map_err(|e| OdfError::Config(format!("Failed to wrap output: {}", e)))?;
    
    writer.write_all(plaintext.as_bytes())
        .map_err(|e| OdfError::Config(format!("Failed to write plaintext: {}", e)))?;
    
    writer.finish()
        .map_err(|e| OdfError::Config(format!("Failed to finalize encryption: {}", e)))?;
    
    Ok(encrypted)
}

/// Decrypt ciphertext to string.
pub fn decrypt(ciphertext: &[u8]) -> Result<String> {
    let identity = load_identity()?;
    let x25519_identity = identity.x25519_identity();
    
    let decryptor = age::Decryptor::new(ciphertext)
        .map_err(|e| OdfError::Config(format!("Failed to parse encrypted data: {}", e)))?;
    
    let mut decrypted = String::new();
    let mut reader = decryptor.decrypt(std::iter::once(&x25519_identity as &dyn age::Identity))
        .map_err(|e| OdfError::Config(format!("Decryption failed: {}", e)))?;
    
    reader.read_to_string(&mut decrypted)
        .map_err(|e| OdfError::Config(format!("Failed to read decrypted data: {}", e)))?;
    
    Ok(decrypted)
}

/// Encrypt to base64 string for storage.
pub fn encrypt_to_string(plaintext: &str) -> Result<String> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    
    let encrypted = encrypt(plaintext)?;
    Ok(STANDARD.encode(&encrypted))
}

/// Decrypt from base64 string.
pub fn decrypt_from_string(ciphertext: &str) -> Result<String> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    
    let decoded = STANDARD.decode(ciphertext.trim())
        .map_err(|e| OdfError::Config(format!("Failed to decode base64: {}", e)))?;
    
    decrypt(&decoded)
}

/// Save identity to file with proper permissions (600).
pub fn save_identity(path: &PathBuf, identity: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| OdfError::Config(format!("Failed to create directory: {}", e)))?;
    }
    
    // Write with restrictive permissions
    std::fs::write(path, identity)
        .map_err(|e| OdfError::Config(format!("Failed to write identity file: {}", e)))?;
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| OdfError::Config(format!("Failed to set permissions: {}", e)))?;
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_identity() {
        let identity = AgeIdentity::generate().unwrap();
        assert!(identity.secret().starts_with("AGE-SECRET-KEY-1"));
        assert!(identity.public().starts_with("age1"));
    }

    #[test]
    fn test_encrypt_decrypt() {
        let identity = AgeIdentity::generate().unwrap();
        
        // Set env vars for this test
        // SAFETY: Single-threaded test, no races
        unsafe {
            std::env::set_var("ODF_AGE_PRIVATE_KEY", identity.secret());
            std::env::set_var("ODF_AGE_PUBLIC_KEY", identity.public());
        }
        
        let plaintext = "this is a secret token";
        let encrypted = encrypt_to_string(plaintext).unwrap();
        
        // Verify it's base64 encoded and longer
        assert!(encrypted.len() > plaintext.len());
        
        let decrypted = decrypt_from_string(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
        
        // SAFETY: Single-threaded test, cleaning up
        unsafe {
            std::env::remove_var("ODF_AGE_PRIVATE_KEY");
            std::env::remove_var("ODF_AGE_PUBLIC_KEY");
        }
    }
}