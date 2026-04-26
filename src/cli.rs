use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "odf", version, about = "OIDC Device Flow CLI — manage tokens for any CLI tool")]
pub struct Cli {
    /// Output format for all commands
    #[arg(long, value_enum, global = true, default_value = "text")]
    pub output: OutputFormat,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Clone, ValueEnum, Debug)]
pub enum OutputFormat {
    Text,
    Json,
}

impl OutputFormat {
    pub fn is_json(&self) -> bool {
        matches!(self, OutputFormat::Json)
    }
}

#[derive(Subcommand)]
pub enum Command {
    /// Register a new OIDC provider
    Add(AddCmd),
    /// Authenticate with a provider (device flow)
    Login(LoginCmd),
    /// Print the access token for a provider
    Token(TokenCmd),
    /// Refresh the access token for a provider
    Refresh(RefreshCmd),
    /// Show token status and expiry
    Status(StatusCmd),
    /// List all registered providers and token health
    List(ListCmd),
    /// Remove a provider and its tokens
    Remove(RemoveCmd),
    /// Export provider configuration (no secrets)
    ConfigExport(ConfigExportCmd),
    /// Show configuration paths and status
    Config(ConfigCmd),
    /// Ensure a valid token exists (check → refresh → login prompt)
    Ensure(EnsureCmd),
    /// Force-refresh OIDC discovery cache
    Discover(DiscoverCmd),
}

#[derive(clap::Args)]
pub struct AddCmd {
    /// Name for this provider (used in all other commands)
    pub name: String,

    /// OIDC issuer URL (enables auto-discovery)
    #[arg(long)]
    pub issuer_url: Option<String>,

    /// Client ID registered with the OIDC provider
    #[arg(long)]
    pub client_id: String,

    /// Explicit device authorization endpoint (skip discovery)
    #[arg(long)]
    pub device_auth_endpoint: Option<String>,

    /// Explicit token endpoint (skip discovery)
    #[arg(long)]
    pub token_endpoint: Option<String>,

    /// Scopes to request (comma-separated)
    #[arg(long, value_delimiter = ',')]
    pub scopes: Vec<String>,

    /// Audience to request (some providers require this)
    #[arg(long)]
    pub audience: Option<String>,

    #[arg(long)]

    /// Extra parameters to include in token requests (key=value)
    #[arg(long, value_parser = parse_key_value)]
    pub extra_params: Option<toml::Value>,

    /// Overwrite existing provider config
    #[arg(long)]
    pub force: bool,

    /// Create or update provider (no error if name exists)
    #[arg(long)]
    pub update: bool,

    /// Skip TLS certificate verification (for self-hosted providers)
    #[arg(long)]
    pub insecure: bool,
}

#[derive(clap::Args)]
pub struct LoginCmd {
    /// Provider name to authenticate with
    pub name: String,

    /// Print the verification URL to stdout (for CI/automation) instead of opening a browser
    #[arg(long)]
    pub print_url: bool,

    /// Don't open the browser, just print the URL to stderr
    #[arg(long)]
    pub no_browser: bool,

    /// Re-login even if a valid token already exists
    #[arg(long)]
    pub force: bool,
}

#[derive(clap::Args)]
pub struct TokenCmd {
    /// Provider name (optional with --all)
    #[arg(conflicts_with = "all")]
    pub name: Option<String>,

    /// Output format
    #[arg(long, value_enum, default_value = "raw")]
    pub format: TokenFormatArg,

    /// Don't auto-refresh expired tokens
    #[arg(long)]
    pub no_auto_refresh: bool,

    /// Exit-code only: 0=valid, 2=expired/no token (no output)
    #[arg(long)]
    pub check: bool,

    /// Output tokens for all providers
    #[arg(long)]
    pub all: bool,
    /// Show full token even on a terminal (default: redacted on TTY)
    #[arg(long)]
    pub reveal: bool,
}

#[derive(clap::Args)]
pub struct RefreshCmd {
    /// Provider name
    pub name: String,
}

#[derive(clap::Args)]
pub struct StatusCmd {
    /// Provider name
    pub name: String,

    /// Verify token with provider's introspection endpoint
    #[arg(long)]
    pub verify: bool,
}

#[derive(clap::Args)]
pub struct ListCmd;

#[derive(clap::Args)]
pub struct RemoveCmd {
    /// Provider name to remove
    pub name: String,

    /// Succeed silently if provider not found
    #[arg(long)]
    pub ignore_missing: bool,
}

#[derive(clap::Args)]
pub struct ConfigCmd;

#[derive(clap::Args)]
pub struct ConfigExportCmd {
    /// Provider name (omit to export all)
    pub name: Option<String>,
}

#[derive(clap::Args)]
pub struct EnsureCmd {
    /// Provider name
    pub name: String,

    /// Output format for the token
    #[arg(long, value_enum, default_value = "raw")]
    pub format: TokenFormatArg,
    /// Show full token even on a terminal (default: redacted on TTY)
    #[arg(long)]
    pub reveal: bool,
}

#[derive(clap::Args)]
pub struct DiscoverCmd {
    /// Provider name
    pub name: String,
}

#[derive(Clone, ValueEnum)]
pub enum TokenFormatArg {
    Raw,
    Header,
    Env,
}

impl TokenCmd {
    pub fn format(&self) -> crate::output::TokenFormat {
        match self.format {
            TokenFormatArg::Raw => crate::output::TokenFormat::Raw,
            TokenFormatArg::Header => crate::output::TokenFormat::Header,
            TokenFormatArg::Env => crate::output::TokenFormat::Env,
        }
    }
}

impl EnsureCmd {
    pub fn format(&self) -> crate::output::TokenFormat {
        match self.format {
            TokenFormatArg::Raw => crate::output::TokenFormat::Raw,
            TokenFormatArg::Header => crate::output::TokenFormat::Header,
            TokenFormatArg::Env => crate::output::TokenFormat::Env,
        }
    }
}

fn parse_key_value(s: &str) -> Result<toml::Value, String> {
    let mut map = toml::map::Map::new();
    for pair in s.split(',') {
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| format!("Invalid key=value: {pair}"))?;
        map.insert(k.to_string(), toml::Value::String(v.to_string()));
    }
    Ok(toml::Value::Table(map))
}

pub fn parse() -> Cli {
    Cli::parse()
}
