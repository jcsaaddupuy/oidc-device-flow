mod cli;
mod config;
mod encryption;
mod error;
mod oidc;
mod output;
mod store;
mod term;

use error::{OdfError, Result};
use term::style;

/// Set up panic hook to silently exit on broken pipe errors.
/// This happens when piping output to a command that exits early.
fn setup_panic_hook() {
    std::panic::set_hook(Box::new(|panic_info| {
        // Check if this is a broken pipe error
        if let Some(msg) = panic_info.payload().downcast_ref::<&str>() {
            if msg.contains("Broken pipe") || msg.contains("failed printing to stdout") {
                std::process::exit(0);
            }
        }
        // For other panics, use default behavior
        eprintln!("{}", panic_info);
        std::process::exit(101);
    }));
}

#[tokio::main]
async fn main() {
    setup_panic_hook();
    term::init_colors();
    let cli = cli::parse();
    let json = cli.output.is_json();

    let result = match cli.command {
        cli::Command::Add(cmd) => cmd_add(json, cmd).await,
        cli::Command::Login(cmd) => cmd_login(json, cmd).await,
        cli::Command::Token(cmd) => cmd_token(json, cmd).await,
        cli::Command::RefreshToken(cmd) => cmd_refresh_token(json, cmd).await,
        cli::Command::Refresh(cmd) => cmd_refresh(json, cmd).await,
        cli::Command::Status(cmd) => cmd_status(json, cmd).await,
        cli::Command::List(_) => cmd_list(json).await,
        cli::Command::Remove(cmd) => cmd_remove(json, cmd).await,
        cli::Command::ConfigExport(cmd) => cmd_config_export(cmd).await,
        cli::Command::Config(_) => cmd_config(json).await,
        cli::Command::Encryption(cmd) => cmd_encryption(json, cmd).await,
        cli::Command::Ensure(cmd) => cmd_ensure(json, cmd).await,
        cli::Command::Discover(cmd) => cmd_discover(json, cmd).await,
    };

    match result {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            let code = e.exit_code();
            if json {
                let err_out = output::ErrorOutput::from_odf_error(&e);
                match err_out.to_json() {
                    Ok(j) => eprintln!("{j}"),
                    Err(_) => eprintln!("Error: {e}"),
                }
            } else {
                eprintln!("Error: {e}");
            }
            std::process::exit(code);
        }
    }
}

// ─── odf add ───────────────────────────────────────────────────────────

async fn cmd_add(json: bool, cmd: cli::AddCmd) -> Result<()> {
    let force = cmd.force || cmd.update;

    if !force && config::exists(&cmd.name)? {
        return Err(OdfError::NameConflict(cmd.name));
    }

    let cfg = config::ProviderConfig {
        client_id: cmd.client_id.clone(),
        client_secret: cmd.client_secret.clone(),
        issuer_url: cmd.issuer_url.clone(),
        device_auth_endpoint: cmd.device_auth_endpoint,
        token_endpoint: cmd.token_endpoint,
        redirect_uri: cmd.redirect_uri,
        scopes: cmd.scopes,
        audience: cmd.audience,
        extra_params: cmd.extra_params,
        insecure: cmd.insecure,
    };

    config::save(&cmd.name, &cfg, force)?;

    if json {
        let out = output::Envelope::new("add", output::AddOutput {
            name: cmd.name,
            issuer_url: cmd.issuer_url,
            insecure: cmd.insecure,
        });
        println!("{}", out.to_json()?);
    } else {
        println!("Provider '{}' added.", cmd.name);
    }

    Ok(())
}

// ─── odf login ─────────────────────────────────────────────────────────

async fn cmd_login(json: bool, cmd: cli::LoginCmd) -> Result<()> {
    let cfg = config::load(&cmd.name)?;

    // If not --force, check if a valid token already exists
    if !cmd.force {
        let store = store::get_store(&cmd.name)?;
        if store.get_access_token(&cmd.name)?.is_some() {
            let info = store::file::load_token_info(&cmd.name)?;
            let expired = info.as_ref().map_or(true, |i| chrono::Utc::now().timestamp() > i.expires_at);
            if !expired {
                if json {
                    // Don't print token for already-valid login
                    let out = output::Envelope::new("login", output::LoginCompleteOutput {
                        access_token: None,
                        expires_at: info.as_ref().map(|i| i.expires_at).unwrap_or(0),
                        scope: info.as_ref().map(|i| i.scope.clone()).unwrap_or_default(),
                        sensitive: false,
                    });
                    println!("{}", out.to_json()?);
                } else {
                    let term_mode = term::detect_term_mode();
                    if term_mode.supports_color() {
                        eprintln!("  {} Already logged in. Use {}.", 
                            style::warning("!"), 
                            style::dim("--force to re-authenticate")
                        );
                    } else {
                        eprintln!("  Already logged in. Use --force to re-authenticate.");
                    }
                }
                return Ok(());
            }
        }
    }

    // TTY check
    if !cmd.print_url && !cmd.no_browser
        && !atty::is(atty::Stream::Stdout)
        && !atty::is(atty::Stream::Stderr)
    {
        return Err(OdfError::Auth(
            "No TTY detected. Use --print-url or --no-browser for non-interactive usage.".into(),
        ));
    }

    // Step 1: Request device code
    let (device_code, user_code, verification_uri, verification_uri_complete, interval) =
        oidc::device::request_device_code(&cmd.name, &cfg, cfg.insecure).await?;

    let display_url = verification_uri_complete.unwrap_or_else(|| verification_uri.clone());

    if cmd.print_url {
        // CI mode: URL phase
        if json {
            let out = output::Envelope::new("login_url", output::LoginUrlOutput {
                url: display_url,
                user_code: user_code.clone(),
                interval,
            });
            println!("{}", out.to_json()?);
        } else {
            println!("{display_url}");
        }
    } else {
        let term_mode = term::detect_term_mode();
        if term_mode.supports_color() {
            eprintln!("  {}: {}", style::label("Verify at"), style::url(&display_url));
            eprintln!("  {}: {}", style::label("User code"), style::user_code(&user_code));
        } else {
            eprintln!("  Verify at: {display_url}");
            eprintln!("  User code: {user_code}");
        }
        if !cmd.no_browser {
            if let Err(e) = open::that(&display_url) {
                if term_mode.supports_color() {
                    eprintln!("  {} Could not open browser: {e}", style::warning("!"));
                } else {
                    eprintln!("  Could not open browser: {e}");
                }
            }
        }
    }

    // Step 2: Poll for token
    let result = oidc::device::poll_for_token(&cmd.name, &cfg, &device_code, interval, cfg.insecure).await?;

    // Step 3: Save tokens
    let store = store::get_store(&cmd.name)?;
    let expires_at = chrono::Utc::now().timestamp() + result.expires_in as i64;
    let access_token = result.access_token.clone();
    let scope = result.scope.clone();
    oidc::device::save_login_result(&cmd.name, store.as_ref(), &result)?;

    if cmd.print_url {
        // CI mode: return token so AI gets it in one round-trip
        if json {
            let out = output::Envelope::new("login", output::LoginCompleteOutput {
                access_token: Some(access_token),
                expires_at,
                scope,
                sensitive: true,
            });
            println!("{}", out.to_json()?);
        } else if output::is_stdout_tty() {
            println!("{}", output::redact_token(&access_token));
        } else {
            println!("{access_token}");
        }
    } else if json {
        // Interactive login: no token in output
        let out = output::Envelope::new("login", output::LoginCompleteOutput {
            access_token: None,
            expires_at,
            scope,
            sensitive: false,
        });
        println!("{}", out.to_json()?);
    } else {
        let term_mode = term::detect_term_mode();
        if term_mode.supports_color() {
            eprintln!("  {} Token saved.", style::success("✓"));
        } else {
            eprintln!("  Token saved.");
        }
    }

    Ok(())
}

// ─── odf token ─────────────────────────────────────────────────────────

async fn cmd_token(json: bool, cmd: cli::TokenCmd) -> Result<()> {
    // --check: exit-code only, no output
    if cmd.check {
        return cmd_token_check(&cmd).await;
    }

    // --all: all providers
    if cmd.all {
        return cmd_token_all(json, &cmd).await;
    }

    let name = cmd.name.as_ref().ok_or_else(|| {
        OdfError::Config("Provider name required unless --all is specified".into())
    })?;

    let cfg = config::load(name)?;
    let store = store::get_store(name)?;
    let info = store::file::load_token_info(name)?;
    let expired = info.as_ref().map_or(true, |i| chrono::Utc::now().timestamp() > i.expires_at);

    // Auto-refresh if expired and refresh token available
    if expired && !cmd.no_auto_refresh {
        if store.get_refresh_token(name)?.is_some() {
            let result = oidc::refresh::refresh_token(name, &cfg, store.as_ref()).await?;
            if json {
                let out = output::Envelope::new("token", output::TokenOutput {
                    access_token: result.access_token,
                    expires_at: chrono::Utc::now().timestamp() + result.expires_in as i64,
                    scope: result.scope,
                    expired: false,
                    sensitive: true,
                });
                println!("{}", out.to_json()?);
            } else {
                let formatted = output::format_token(name, &result.access_token, cmd.format(), cmd.reveal);
                print!("{formatted}");
            }
            return Ok(());
        } else if info.is_some() {
            return Err(OdfError::ExpiredNoRefresh(name.clone()));
        }
    }

    let token = store
        .get_access_token(name)?
        .ok_or_else(|| OdfError::Auth("No token found. Run 'odf login' first.".into()))?;

    if json {
        let expires_at = info.as_ref().map(|i| i.expires_at).unwrap_or(0);
        let scope = info.as_ref().map(|i| i.scope.clone()).unwrap_or_default();
        let out = output::Envelope::new("token", output::TokenOutput {
            access_token: token,
            expires_at,
            scope,
            expired,
            sensitive: true,
        });
        println!("{}", out.to_json()?);
    } else {
        let formatted = output::format_token(name, &token, cmd.format(), cmd.reveal);
        print!("{formatted}");
    }

    Ok(())
}

/// `odf token --check` — exit-code only, no output
async fn cmd_token_check(cmd: &cli::TokenCmd) -> Result<()> {
    let name = cmd.name.as_ref().ok_or_else(|| {
        OdfError::Config("Provider name required".into())
    })?;
    let store = store::get_store(name)?;
    if store.get_access_token(name)?.is_none() {
        return Err(OdfError::Auth("No token".into()));
    }
    let info = store::file::load_token_info(name)?;
    let expired = info.as_ref().map_or(true, |i| chrono::Utc::now().timestamp() > i.expires_at);
    if expired {
        if !cmd.no_auto_refresh && store.get_refresh_token(name)?.is_some() {
            let cfg = config::load(name)?;
            let _ = oidc::refresh::refresh_token(name, &cfg, store.as_ref()).await?;
            return Ok(());
        }
        return Err(OdfError::ExpiredNoRefresh(name.clone()));
    }
    Ok(())
}

/// `odf token --all`
async fn cmd_token_all(json: bool, cmd: &cli::TokenCmd) -> Result<()> {
    let names = config::list()?;
    if names.is_empty() {
        if json {
            let out = output::Envelope::new("token_all", output::TokenAllOutput {
                providers: vec![],
                sensitive: true,
            });
            println!("{}", out.to_json()?);
        }
        return Ok(());
    }

    let mut entries = Vec::new();
    for name in &names {
        let store = store::get_store(name)?;
        if let Some(token) = store.get_access_token(name)? {
            let info = store::file::load_token_info(name)?;
            let expires_at = info.as_ref().map(|i| i.expires_at).unwrap_or(0);
            let expired = info.as_ref().map_or(true, |i| chrono::Utc::now().timestamp() > i.expires_at);
            if json {
                entries.push(output::TokenAllEntry {
                    access_token: token,
                    expires_at,
                    expired,
                });
            } else {
                let formatted = output::format_token(name, &token, cmd.format(), cmd.reveal);
                println!("{formatted}");
            }
        }
    }

    if json {
        let out = output::Envelope::new("token_all", output::TokenAllOutput {
            providers: entries,
            sensitive: true,
        });
        println!("{}", out.to_json()?);
    }

    Ok(())
}

// ─── odf refresh ───────────────────────────────────────────────────────

async fn cmd_refresh(json: bool, cmd: cli::RefreshCmd) -> Result<()> {
    let cfg = config::load(&cmd.name)?;
    let store = store::get_store(&cmd.name)?;

    let result = oidc::refresh::refresh_token(&cmd.name, &cfg, store.as_ref()).await?;
    let expires_at = chrono::Utc::now().timestamp() + result.expires_in as i64;

    if json {
        let out = output::Envelope::new("refresh", output::RefreshOutput {
            expires_at,
            scope: result.scope,
        });
        println!("{}", out.to_json()?);
    } else {
        let term_mode = term::detect_term_mode();
        let time_str = chrono::DateTime::from_timestamp(expires_at, 0)
            .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| expires_at.to_string());
        if term_mode.supports_color() {
            eprintln!("  {} Token refreshed. Expires at {}", style::success("✓"), style::dim(&time_str));
        } else {
            eprintln!("  Token refreshed. Expires at {}", time_str);
        }
    }

    Ok(())
}

// ─── odf refresh-token ───────────────────────────────────────────────────

async fn cmd_refresh_token(json: bool, cmd: cli::RefreshTokenCmd) -> Result<()> {
    let _cfg = config::load(&cmd.name)?;
    
    let refresh_token = store::file::get_refresh_token(&cmd.name)?
        .ok_or_else(|| OdfError::Auth(format!(
            "No refresh token for '{}'. Run 'odf login {}' first.",
            cmd.name, cmd.name
        )))?;

    if json {
        let out = output::Envelope::new("refresh_token", output::RefreshTokenOutput {
            refresh_token: refresh_token.clone(),
            sensitive: true,
        });
        println!("{}", out.to_json()?);
    } else {
        // Apply same redaction logic as access token
        let formatted = output::format_token(&cmd.name, &refresh_token, output::TokenFormat::Raw, cmd.reveal);
        print!("{formatted}");
    }

    Ok(())
}

// ─── odf status ────────────────────────────────────────────────────────

async fn cmd_status(json: bool, cmd: cli::StatusCmd) -> Result<()> {
    let cfg = config::load(&cmd.name)?;
    let store = store::get_store(&cmd.name)?;

    let info = store::file::load_token_info(&cmd.name)?;

    let (expires_at, scope, token_type) = match &info {
        Some(i) => (Some(i.expires_at), Some(i.scope.clone()), Some(i.token_type.clone())),
        None => (None, None, None),
    };

    let has_token = store.get_access_token(&cmd.name)?.is_some();
    let refreshable = store.get_refresh_token(&cmd.name)?.is_some();
    let expired = expires_at.map_or(true, |exp| chrono::Utc::now().timestamp() > exp);
    let valid = has_token && !expired;

    let introspected = if cmd.verify && has_token {
        let token = store.get_access_token(&cmd.name)?.unwrap();
        match oidc::introspect::introspect(&cmd.name, &cfg, &token).await? {
            Some(info) => Some(output::IntrospectInfo {
                active: info.active,
                scope: info.scope,
                client_id: info.client_id,
                username: info.username,
            }),
            None => {
                if !json {
                    eprintln!("  Warning: Provider does not advertise an introspection endpoint.");
                }
                None
            }
        }
    } else {
        None
    };

    if json {
        let out = output::Envelope::new("status", output::StatusOutput {
            name: cmd.name.clone(),
            valid,
            expires_at,
            scope,
            refreshable,
            introspected,
        });
        println!("{}", out.to_json()?);
    } else {
        println!("Provider: {}", cmd.name);
        println!("  Token:   {}", if has_token { "present" } else { "none" });
        println!("  Valid:   {}", if valid { "yes" } else { "no" });
        if let Some(exp) = expires_at {
            let dt = chrono::DateTime::from_timestamp(exp, 0)
                .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| exp.to_string());
            println!("  Expires: {dt}");
        }
        if let Some(ref s) = scope {
            println!("  Scope:   {s}");
        }
        if let Some(ref t) = token_type {
            println!("  Type:    {t}");
        }
        println!("  Refresh: {}", if refreshable { "yes" } else { "no" });
        if let Some(ref info) = introspected {
            println!("  Introspection:");
            println!("    Active:    {}", info.active);
            if let Some(ref cid) = info.client_id {
                println!("    Client ID: {cid}");
            }
            if let Some(ref u) = info.username {
                println!("    Username:  {u}");
            }
        }
    }

    Ok(())
}

// ─── odf list ──────────────────────────────────────────────────────────

async fn cmd_list(json: bool) -> Result<()> {
    let names = config::list()?;

    if names.is_empty() {
        if json {
            let out = output::Envelope::new("list", output::ListOutput { providers: vec![] });
            println!("{}", out.to_json()?);
        } else {
            println!("No providers configured. Use 'odf add' to add one.");
        }
        return Ok(());
    }

    let mut entries = Vec::new();
    for name in &names {
        let store = store::get_store(name)?;
        let has_token = store.get_access_token(name)?.is_some();
        let info = store::file::load_token_info(name)?;
        let expired = info.as_ref().map_or(true, |i| chrono::Utc::now().timestamp() > i.expires_at);
        let refreshable = store.get_refresh_token(name)?.is_some();
        entries.push(output::ListEntry {
            name: name.clone(),
            has_token,
            expired,
            refreshable,
        });
    }

    if json {
        let out = output::Envelope::new("list", output::ListOutput { providers: entries });
        println!("{}", out.to_json()?);
    } else {
        println!("{:<20} {:<10} {:<10} {:<10}", "NAME", "TOKEN", "EXPIRED", "REFRESH");
        for e in &entries {
            println!(
                "{:<20} {:<10} {:<10} {:<10}",
                e.name,
                if e.has_token { "yes" } else { "no" },
                if e.expired { "yes" } else { "no" },
                if e.refreshable { "yes" } else { "no" },
            );
        }
    }

    Ok(())
}

// ─── odf remove ────────────────────────────────────────────────────────

async fn cmd_remove(json: bool, cmd: cli::RemoveCmd) -> Result<()> {
    if cmd.ignore_missing && !config::exists(&cmd.name)? {
        if json {
            println!("{{\"type\":\"remove\",\"version\":1,\"name\":\"{}\",\"status\":\"not_found\"}}", cmd.name);
        }
        return Ok(());
    }

    let store = store::get_store(&cmd.name)?;
    config::remove(&cmd.name)?;
    store.delete_tokens(&cmd.name)?;
    store::file::delete_token_files(&cmd.name)?;

    if json {
        println!("{{\"type\":\"remove\",\"version\":1,\"name\":\"{}\",\"status\":\"removed\"}}", cmd.name);
    } else {
        println!("Provider '{}' removed.", cmd.name);
    }

    Ok(())
}

// ─── odf config-export ─────────────────────────────────────────────────

async fn cmd_config_export(cmd: cli::ConfigExportCmd) -> Result<()> {
    if let Some(ref name) = cmd.name {
        let cfg = config::load(name)?;
        let toml_str = toml::to_string_pretty(&cfg)
            .map_err(|e| OdfError::Config(format!("Serialization error: {e}")))?;
        print!("{toml_str}");
    } else {
        let names = config::list()?;
        for name in &names {
            println!("--- {name} ---");
            let cfg = config::load(name)?;
            let toml_str = toml::to_string_pretty(&cfg)
                .map_err(|e| OdfError::Config(format!("Serialization error: {e}")))?;
            println!("{toml_str}");
        }
    }
    Ok(())
}

// ─── odf config ────────────────────────────────────────────────────────

async fn cmd_config(json: bool) -> Result<()> {
    let config_base = config::config_dir_path()?;
    let providers = config::providers_dir()?;
    let data_base = store::file::data_dir()?;
    let tokens = store::file::tokens_dir()?;
    let cache_base = oidc::discovery::cache_dir_path()?;
    let discovery_cache = oidc::discovery::cache_dir()?;

    let providers_exist = providers.exists();
    let tokens_exist = tokens.exists();
    let discovery_exist = discovery_cache.exists();

    let provider_count = if providers_exist { config::list()?.len() } else { 0 };
    let token_count = if tokens_exist { std::fs::read_dir(&tokens)?.count() } else { 0 };


    if json {
        let out = output::Envelope::new("config", output::ConfigOutput {
            paths: output::ConfigPaths {
                config_base,
                providers,
                data_base,
                tokens,
                cache_base,
                discovery_cache,
            },
            exists: output::ConfigExists {
                providers_dir: providers_exist,
                tokens_dir: tokens_exist,
                discovery_cache: discovery_exist,
            },
            counts: output::ConfigCounts {
                providers: provider_count,
                tokens: token_count,
            },
        });
        println!("{}", out.to_json()?);
    } else {
        println!("Paths:");
        println!("  Config:          {}", config_base.display());
        println!("  Providers:       {}", providers.display());
        println!("  Data:            {}", data_base.display());
        println!("  Tokens:          {}", tokens.display());
        println!("  Cache:           {}", cache_base.display());
        println!("  Discovery cache: {}", discovery_cache.display());
        println!();
        println!("Status:");
        println!("  Providers dir:   {}", if providers_exist { "exists" } else { "not created" });
        println!("  Tokens dir:      {}", if tokens_exist { "exists" } else { "not created" });
        println!("  Discovery cache: {}", if discovery_exist { "exists" } else { "not created" });
        println!("  Provider count:  {}", provider_count);
        println!("  Token count:     {}", token_count);
    }

    Ok(())
}

// ─── odf ensure ────────────────────────────────────────────────────────

async fn cmd_ensure(json: bool, cmd: cli::EnsureCmd) -> Result<()> {
    let cfg = config::load(&cmd.name)?;
    let store = store::get_store(&cmd.name)?;

    let has_token = store.get_access_token(&cmd.name)?.is_some();

    if has_token {
        let info = store::file::load_token_info(&cmd.name)?;
        let expired = info.as_ref().map_or(true, |i| chrono::Utc::now().timestamp() > i.expires_at);

        if !expired {
            // Token is valid
            let token = store.get_access_token(&cmd.name)?.unwrap();
            let expires_at = info.as_ref().map(|i| i.expires_at).unwrap_or(0);
            let scope = info.as_ref().map(|i| i.scope.clone()).unwrap_or_default();

            if json {
                let out = output::Envelope::new("ensure", output::EnsureOutput {
                    access_token: token,
                    expires_at,
                    scope,
                    action: "valid",
                    sensitive: true,
                });
                println!("{}", out.to_json()?);
            } else {
                let token = store.get_access_token(&cmd.name)?.unwrap();
                let formatted = output::format_token(&cmd.name, &token, cmd.format(), cmd.reveal);
                print!("{formatted}");
            }
            return Ok(());
        }

        // Token expired — try refresh
        if store.get_refresh_token(&cmd.name)?.is_some() {
            let result = oidc::refresh::refresh_token(&cmd.name, &cfg, store.as_ref()).await?;
            let expires_at = chrono::Utc::now().timestamp() + result.expires_in as i64;

            if json {
                let out = output::Envelope::new("ensure", output::EnsureOutput {
                    access_token: result.access_token,
                    expires_at,
                    scope: result.scope,
                    action: "refreshed",
                    sensitive: true,
                });
                println!("{}", out.to_json()?);
            } else {
                let token = store.get_access_token(&cmd.name)?.unwrap();
                let formatted = output::format_token(&cmd.name, &token, cmd.format(), cmd.reveal);
                print!("{formatted}");
            }
            return Ok(());
        }

        return Err(OdfError::ExpiredNoRefresh(cmd.name.clone()));
    }

    // No token at all
    Err(OdfError::Auth(format!("No token for '{}'. Run 'odf login {}' first.", cmd.name, cmd.name)))
}

// ─── odf discover ──────────────────────────────────────────────────────

async fn cmd_discover(json: bool, cmd: cli::DiscoverCmd) -> Result<()> {
    let cfg = config::load(&cmd.name)?;

    let issuer = cfg.issuer_url.as_ref()
        .ok_or_else(|| OdfError::Discovery(format!("Provider '{}' has no issuer_url set", cmd.name)))?;

    let doc = oidc::discovery::discover_force(&cmd.name, issuer, cfg.insecure).await?;

    if json {
        let out = serde_json::json!({
            "type": "discover",
            "version": 1,
            "issuer": doc.issuer,
            "device_authorization_endpoint": doc.device_authorization_endpoint,
            "token_endpoint": doc.token_endpoint,
            "introspection_endpoint": doc.introspection_endpoint,
        });
        println!("{}", serde_json::to_string(&out)?);
    } else {
        println!("Issuer:             {}", doc.issuer);
        println!("Device auth:        {}", doc.device_authorization_endpoint);
        println!("Token endpoint:     {}", doc.token_endpoint);
        if let Some(ref ep) = doc.introspection_endpoint {
            println!("Introspection:      {ep}");
        } else {
            println!("Introspection:      (not advertised)");
        }
    }

    Ok(())
}

// ─── odf encryption ─────────────────────────────────────────────────────

async fn cmd_encryption(json: bool, cmd: cli::EncryptionCmd) -> Result<()> {
    match cmd.command {
        cli::EncryptionSubcommand::Generate(gen_cmd) => cmd_encryption_generate(json, gen_cmd),
        cli::EncryptionSubcommand::Status(_) => cmd_encryption_status(json),
        cli::EncryptionSubcommand::Export(_) => cmd_encryption_export(json),
        cli::EncryptionSubcommand::Migrate(mig_cmd) => cmd_encryption_migrate(json, mig_cmd),
    }
}

fn cmd_encryption_generate(json: bool, cmd: cli::EncryptionGenerateCmd) -> Result<()> {
    use crate::encryption::{AgeIdentity, save_identity, identity_file_path};
    
    let key_path = identity_file_path()?;
    
    // Check if key already exists
    if key_path.exists() && !cmd.force {
        return Err(OdfError::Config(format!(
            "Encryption key already exists at {}. Use --force to overwrite.",
            key_path.display()
        )));
    }
    
    // Generate new identity
    let identity = AgeIdentity::generate()?;
    let secret = identity.secret().to_string();
    let public = identity.public().to_string();
    
    // Save identity
    save_identity(&key_path, &secret)?;
    
    if json {
        let out = output::Envelope::new("encryption_generate", output::EncryptionGenerateOutput {
            public_key: public.clone(),
            key_file: key_path.display().to_string(),
        });
        println!("{}", out.to_json()?);
    } else {
        println!("Generated age encryption key:");
        println!("  Key file: {}", key_path.display());
        println!("  Public key: {}", public);
        println!();
        println!("Share the public key with your team to encrypt tokens for shared use.");
        println!("Keep the key file secure - it can decrypt all stored tokens.");
    }
    
    Ok(())
}

fn cmd_encryption_status(json: bool) -> Result<()> {
    use crate::encryption::{is_encryption_enabled, load_identity, identity_file_path};
    use std::fs;
    
    let key_path = identity_file_path()?;
    let enabled = is_encryption_enabled();
    
    let (public_key, key_file) = if enabled {
        let key_display = if let Ok(key) = std::env::var("ODF_AGE_PRIVATE_KEY") {
            format!("(from ODF_AGE_PRIVATE_KEY, {} chars)", key.len())
        } else if let Ok(path) = std::env::var("ODF_AGE_KEY_FILE") {
            format!("{} (from ODF_AGE_KEY_FILE)", path)
        } else {
            key_path.display().to_string()
        };
        
        let pub_key = load_identity().ok().map(|id| id.public().to_string());
        (pub_key, Some(key_display))
    } else {
        (None, None)
    };
    
    // Count encrypted vs plain tokens
    let tokens_dir = store::file::tokens_dir()?;
    let mut encrypted_count = 0;
    let mut plain_count = 0;
    
    if tokens_dir.exists() {
        for entry in fs::read_dir(&tokens_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".json.age") {
                encrypted_count += 1;
            } else if name.ends_with(".json") {
                plain_count += 1;
            }
        }
    }
    
    if json {
        let out = output::Envelope::new("encryption_status", output::EncryptionStatusOutput {
            enabled,
            key_file,
            public_key,
            encrypted_tokens: encrypted_count,
            plain_tokens: plain_count,
        });
        println!("{}", out.to_json()?);
    } else {
        println!("Encryption: {}", if enabled { "enabled" } else { "disabled" });
        if let Some(ref kf) = key_file {
            println!("Key file: {}", kf);
        }
        if let Some(ref pk) = public_key {
            println!("Public key: {}", pk);
        }
        println!("Tokens: {} encrypted, {} plain", encrypted_count, plain_count);
    }
    
    Ok(())
}

fn cmd_encryption_export(json: bool) -> Result<()> {
    use crate::encryption::load_identity;
    
    let identity = load_identity()?;
    let public_key = identity.public().to_string();
    
    if json {
        let out = output::Envelope::new("encryption_export", output::EncryptionExportOutput {
            public_key: public_key.clone(),
        });
        println!("{}", out.to_json()?);
    } else {
        println!("{}", public_key);
    }
    
    Ok(())
}

fn cmd_encryption_migrate(json: bool, cmd: cli::EncryptionMigrateCmd) -> Result<()> {
    use crate::encryption::{is_encryption_enabled, encrypt_to_string};
    use std::fs;
    
    if !is_encryption_enabled() {
        return Err(OdfError::Config(
            "Encryption not enabled. Run 'odf encryption generate' first.".into()
        ));
    }
    
    let tokens_dir = store::file::tokens_dir()?;
    if !tokens_dir.exists() {
        if json {
            let out = output::Envelope::new("encryption_migrate", output::EncryptionMigrateOutput {
                migrated: 0,
                skipped: 0,
                tokens: vec![],
            });
            println!("{}", out.to_json()?);
        } else {
            println!("No tokens to migrate.");
        }
        return Ok(());
    }
    
    let mut migrated = Vec::new();
    let mut skipped = Vec::new();
    
    for entry in fs::read_dir(&tokens_dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        
        // Only migrate .json files (not .json.age)
        if !name.ends_with(".json") {
            continue;
        }
        
        // Skip if already encrypted
        let encrypted_path = path.with_extension("json.age");
        if encrypted_path.exists() {
            skipped.push(name);
            continue;
        }
        
        // Read token data
        let content = fs::read_to_string(&path)?;
        
        // Encrypt
        let encrypted = encrypt_to_string(&content)?;
        
        if cmd.dry_run {
            migrated.push(name);
        } else {
            // Write encrypted
            fs::write(&encrypted_path, &encrypted)?;
            // Remove plain
            fs::remove_file(&path)?;
            migrated.push(name);
        }
    }
    
    if json {
        let out = output::Envelope::new("encryption_migrate", output::EncryptionMigrateOutput {
            migrated: migrated.len(),
            skipped: skipped.len(),
            tokens: migrated.clone(),
        });
        println!("{}", out.to_json()?);
    } else {
        if cmd.dry_run {
            println!("Dry run - would migrate {} tokens:", migrated.len());
        } else {
            println!("Migrated {} tokens:", migrated.len());
        }
        for name in &migrated {
            println!("  - {}", name);
        }
        if !skipped.is_empty() {
            println!("Skipped {} (already encrypted):", skipped.len());
            for name in &skipped {
                println!("  - {}", name);
            }
        }
    }
    
    Ok(())
}
