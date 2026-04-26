pub mod file;

use crate::error::Result;

/// Token store trait — only file-backed storage now.
pub trait TokenStore: Send + Sync {
    fn get_access_token(&self, name: &str) -> Result<Option<String>>;
    fn get_refresh_token(&self, name: &str) -> Result<Option<String>>;
    fn set_access_token(&self, name: &str, token: &str) -> Result<()>;
    fn set_refresh_token(&self, name: &str, token: &str) -> Result<()>;
    fn delete_tokens(&self, name: &str) -> Result<()>;
}

/// Always returns the file store.
pub fn get_store(_name: &str) -> Result<Box<dyn TokenStore>> {
    Ok(Box::new(file::FileTokenStore))
}
