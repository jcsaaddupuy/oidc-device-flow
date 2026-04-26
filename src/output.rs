use serde::Serialize;

/// Output format for token command.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TokenFormat {
    /// Bare token string (default) — pipes cleanly into curl -H
    Raw,
    /// "Bearer <token>" — direct use
    Header,
    /// "ODF_TOKEN_<name>=<token>" — eval-friendly
    Env,
}

/// Whether stdout is a real terminal (not piped/redirected).
pub fn is_stdout_tty() -> bool {
    atty::is(atty::Stream::Stdout)
}

/// Redact a token for TTY display: keep first 8 and last 4 chars.
/// Tokens shorter than 16 chars are fully redacted.
pub fn redact_token(token: &str) -> String {
    if token.len() < 16 {
        return "****".to_string();
    }
    format!("{}...{}", &token[..8], &token[token.len()-4..])
}

/// Format a token for output. When `reveal` is false and stdout is a TTY,
/// the token is redacted to prevent accidental leaks.
pub fn format_token(name: &str, token: &str, format: TokenFormat, reveal: bool) -> String {
    let display_token = if reveal || !is_stdout_tty() {
        token.to_string()
    } else {
        redact_token(token)
    };
    match format {
        TokenFormat::Raw => display_token,
        TokenFormat::Header => format!("Bearer {display_token}"),
        TokenFormat::Env => {
            let safe_name = name
                .chars()
                .map(|c| if c.is_alphanumeric() { c } else { '_' })
                .collect::<String>();
            format!("ODF_TOKEN_{safe_name}={display_token}")
        }
    }
}

/// JSON response envelope — every JSON output includes type + version.
#[derive(Serialize)]
pub struct Envelope<T: Serialize> {
    #[serde(rename = "type")]
    pub type_: &'static str,
    pub version: u32,
    #[serde(flatten)]
    pub data: T,
}

impl<T: Serialize> Envelope<T> {
    pub fn new(type_: &'static str, data: T) -> Self {
        Self {
            type_,
            version: 1,
            data,
        }
    }

    pub fn to_json(&self) -> crate::error::Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    #[allow(dead_code)]
    pub fn to_json_pretty(&self) -> crate::error::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

// ─── JSON output types (no tokens except where explicitly intended) ───

/// `odf add` — no secrets
#[derive(Serialize)]
pub struct AddOutput {
    pub name: String,
    pub issuer_url: Option<String>,
    pub insecure: bool,
}

/// `odf login` (URL phase) — no secrets
#[derive(Serialize)]
pub struct LoginUrlOutput {
    pub url: String,
    pub user_code: String,
    pub interval: u64,
}

/// `odf login` (complete phase) — contains token, ONLY when --print-url
#[derive(Serialize)]
pub struct LoginCompleteOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    pub expires_at: i64,
    pub scope: String,
    pub sensitive: bool,
}

/// `odf token --json` — contains token, ONLY when explicitly requested
#[derive(Serialize)]
pub struct TokenOutput {
    pub access_token: String,
    pub expires_at: i64,
    pub scope: String,
    pub expired: bool,
    pub sensitive: bool,
}

/// `odf token --all --json` — contains tokens for all providers
#[derive(Serialize)]
pub struct TokenAllOutput {
    pub providers: Vec<TokenAllEntry>,
    pub sensitive: bool,
}

#[derive(Serialize)]
pub struct TokenAllEntry {
    pub access_token: String,
    pub expires_at: i64,
    pub expired: bool,
}

/// `odf refresh` — no secrets
#[derive(Serialize)]
pub struct RefreshOutput {
    pub expires_at: i64,
    pub scope: String,
}

/// `odf status` — no secrets
#[derive(Serialize)]
pub struct StatusOutput {
    pub name: String,
    pub valid: bool,
    pub expires_at: Option<i64>,
    pub scope: Option<String>,
    pub refreshable: bool,
    pub introspected: Option<IntrospectInfo>,
}

/// `odf list` — no secrets
#[derive(Serialize)]
pub struct ListOutput {
    pub providers: Vec<ListEntry>,
}

#[derive(Serialize)]
pub struct ListEntry {
    pub name: String,
    pub has_token: bool,
    pub expired: bool,
    pub refreshable: bool,
}

/// `odf config` — no secrets
#[derive(Serialize)]
pub struct ConfigOutput {
    pub paths: ConfigPaths,
    pub exists: ConfigExists,
    pub counts: ConfigCounts,
}

#[derive(Serialize)]
pub struct ConfigPaths {
    pub config_base: std::path::PathBuf,
    pub providers: std::path::PathBuf,
    pub data_base: std::path::PathBuf,
    pub tokens: std::path::PathBuf,
    pub cache_base: std::path::PathBuf,
    pub discovery_cache: std::path::PathBuf,
}

#[derive(Serialize)]
pub struct ConfigExists {
    pub providers_dir: bool,
    pub tokens_dir: bool,
    pub discovery_cache: bool,
}

#[derive(Serialize)]
pub struct ConfigCounts {
    pub providers: usize,
    pub tokens: usize,
}

/// `odf introspect` — no secrets
#[derive(Serialize)]
pub struct IntrospectInfo {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub username: Option<String>,
}

/// `odf ensure` — contains token, ONLY when explicitly requested
#[derive(Serialize)]
pub struct EnsureOutput {
    pub access_token: String,
    pub expires_at: i64,
    pub scope: String,
    pub action: &'static str, // "valid" | "refreshed" | "login_required"
    pub sensitive: bool,
}

/// JSON error output — emitted to stderr when --output=json
#[derive(Serialize)]
pub struct ErrorOutput {
    #[serde(rename = "type")]
    pub type_: &'static str,
    pub version: u32,
    pub error: String,
    pub message: String,
    pub exit_code: i32,
}

impl ErrorOutput {
    pub fn new(error_type: &str, message: String, exit_code: i32) -> Self {
        Self {
            type_: "error",
            version: 1,
            error: error_type.to_string(),
            message,
            exit_code,
        }
    }

    pub fn from_odf_error(err: &crate::error::OdfError) -> Self {
        let error_type = match err {
            crate::error::OdfError::Auth(_) | crate::error::OdfError::ExpiredNoRefresh => "AuthError",
            crate::error::OdfError::DeviceFlow(_) => "DeviceFlowError",
            crate::error::OdfError::Network(_) | crate::error::OdfError::Http(_) | crate::error::OdfError::Discovery(_) => "NetworkError",
            crate::error::OdfError::NotFound(_) => "NotFoundError",
            crate::error::OdfError::NameConflict(_) => "NameConflictError",
            _ => "Error",
        };
        Self::new(error_type, err.to_string(), err.exit_code())
    }

    pub fn to_json(&self) -> crate::error::Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_short_token() {
        assert_eq!(redact_token("short"), "****");
        assert_eq!(redact_token("1234567890123"), "****");
    }

    #[test]
    fn test_redact_long_token() {
        let tok = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjA2N";
        let redacted = redact_token(tok);
        assert!(redacted.starts_with("eyJhbGci"));
        assert!(redacted.contains("..."));
        assert!(redacted.ends_with("jA2N"));
        assert_eq!(redacted.len(), 8 + 3 + 4); // first8 + ... + last4
    }

    #[test]
    fn test_format_token_reveal_vs_redact() {
        // With reveal=true, always full token regardless of TTY
        assert_eq!(format_token("test", "abcdefghijklmnop", TokenFormat::Raw, true),
                   "abcdefghijklmnop");
        // With reveal=false + non-TTY (tests run piped), still full token
        // because is_stdout_tty() returns false → we show full token
        assert_eq!(format_token("test", "abcdefghijklmnop", TokenFormat::Raw, false),
                   "abcdefghijklmnop");
        // Redaction only kicks in when is_stdout_tty() == true && reveal == false
        // We can't easily test the TTY path in unit tests, but test redact_token directly
        assert_eq!(redact_token("abcdefghijklmnop"), "abcdefgh...mnop");
    }
}
