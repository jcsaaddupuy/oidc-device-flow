use thiserror::Error;

#[derive(Error, Debug)]
pub enum OdfError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Network error: {0}")]
    #[allow(dead_code)]
    Network(String),

    #[error("Token store error: {0}")]
    Store(String),

    #[error("Provider not found: {0}")]
    NotFound(String),

    #[error("Name already exists: {0}")]
    NameConflict(String),

    #[error("Token expired and no refresh token available")]
    ExpiredNoRefresh,

    #[error("OIDC discovery error: {0}")]
    Discovery(String),

    #[error("Device flow error: {0}")]
    DeviceFlow(String),

    #[error("Introspection error: {0}")]
    Introspect(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML error: {0}")]
    Toml(#[from] toml::de::Error),
}

impl OdfError {
    /// Exit code for this error variant.
    /// 0 = success, 1 = generic, 2 = auth, 3 = network
    pub fn exit_code(&self) -> i32 {
        match self {
            OdfError::Auth(_) | OdfError::ExpiredNoRefresh | OdfError::DeviceFlow(_) => 2,
            OdfError::Network(_) | OdfError::Http(_) | OdfError::Discovery(_) => 3,
            _ => 1,
        }
    }
}

pub type Result<T> = std::result::Result<T, OdfError>;
