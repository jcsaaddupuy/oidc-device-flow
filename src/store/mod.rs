pub mod file;
#[cfg(feature = "keyring")]
pub mod keyring_store;

use crate::error::Result;

/// Abstraction over token storage backends.
/// Secrets (access_token, refresh_token) go through this trait.
/// Metadata (expires_at, scope, token_type) always goes to the file store.
pub trait TokenStore: Send + Sync {
    fn get_access_token(&self, name: &str) -> Result<Option<String>>;
    fn get_refresh_token(&self, name: &str) -> Result<Option<String>>;
    fn set_access_token(&self, name: &str, token: &str) -> Result<()>;
    fn set_refresh_token(&self, name: &str, token: &str) -> Result<()>;
    fn delete_tokens(&self, name: &str) -> Result<()>;
}
