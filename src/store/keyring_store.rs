use crate::error::Result;
use crate::store::TokenStore;

/// OS keychain-backed token store.
/// Key convention: "odf/<name>/access_token", "odf/<name>/refresh_token"
pub struct KeyringTokenStore;

const SERVICE_NAME: &str = "odf";

fn access_key(name: &str) -> String {
    format!("{name}/access_token")
}

fn refresh_key(name: &str) -> String {
    format!("{name}/refresh_token")
}

impl TokenStore for KeyringTokenStore {
    fn get_access_token(&self, name: &str) -> Result<Option<String>> {
        let entry = keyring::Entry::new(SERVICE_NAME, &access_key(name))?;
        match entry.get_password() {
            Ok(token) => Ok(Some(token)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn get_refresh_token(&self, name: &str) -> Result<Option<String>> {
        let entry = keyring::Entry::new(SERVICE_NAME, &refresh_key(name))?;
        match entry.get_password() {
            Ok(token) => Ok(Some(token)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn set_access_token(&self, name: &str, token: &str) -> Result<()> {
        let entry = keyring::Entry::new(SERVICE_NAME, &access_key(name))?;
        entry.set_password(token)?;
        Ok(())
    }

    fn set_refresh_token(&self, name: &str, token: &str) -> Result<()> {
        let entry = keyring::Entry::new(SERVICE_NAME, &refresh_key(name))?;
        entry.set_password(token)?;
        Ok(())
    }

    fn delete_tokens(&self, name: &str) -> Result<()> {
        let access = keyring::Entry::new(SERVICE_NAME, &access_key(name))?;
        let refresh = keyring::Entry::new(SERVICE_NAME, &refresh_key(name))?;
        // Best-effort: ignore NoEntry errors
        let _ = access.delete_credential();
        let _ = refresh.delete_credential();
        Ok(())
    }
}

/// Probe whether the OS keyring is available.
/// Tries a round-trip set/get/delete on a test entry.
pub fn probe_keyring() -> bool {
    let test_key = "__odf_probe__";
    let entry = match keyring::Entry::new(SERVICE_NAME, test_key) {
        Ok(e) => e,
        Err(_) => return false,
    };
    match entry.set_password("probe") {
        Ok(()) => {
            let _ = entry.delete_credential();
            true
        }
        Err(_) => false,
    }
}
