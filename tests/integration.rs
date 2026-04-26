use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

/// Helper to create an odf command with isolated config/token dirs.
fn odf_cmd(home: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("odf").unwrap();
    cmd.env("HOME", home.path());
    cmd.env("XDG_CONFIG_HOME", home.path().join(".config"));
    cmd.env("XDG_DATA_HOME", home.path().join(".local/share"));
    cmd.env("XDG_CACHE_HOME", home.path().join(".cache"));
    cmd
}

#[test]
fn test_add_provider() {
    let home = TempDir::new().unwrap();

    odf_cmd(&home)
        .arg("add")
        .arg("testprov")
        .arg("--issuer-url")
        .arg("https://example.com")
        .arg("--client-id")
        .arg("myclient")
        .arg("--scopes")
        .arg("openid,profile")
        .arg("--store")
        .arg("file")
        .assert()
        .success()
        .stdout(predicate::str::contains("Provider 'testprov' added."));
}

#[test]
fn test_add_json() {
    let home = TempDir::new().unwrap();

    odf_cmd(&home)
        .arg("--output")
        .arg("json")
        .arg("add")
        .arg("testprov")
        .arg("--issuer-url")
        .arg("https://example.com")
        .arg("--client-id")
        .arg("myclient")
        .arg("--store")
        .arg("file")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"type\":\"add\""))
        .stdout(predicate::str::contains("\"name\":\"testprov\""))
        .stdout(predicate::str::contains("\"store\":\"file\""));
}

#[test]
fn test_add_name_clash() {
    let home = TempDir::new().unwrap();

    odf_cmd(&home)
        .arg("add")
        .arg("myprov")
        .arg("--client-id")
        .arg("abc")
        .arg("--store")
        .arg("file")
        .assert()
        .success();

    odf_cmd(&home)
        .arg("add")
        .arg("myprov")
        .arg("--client-id")
        .arg("abc")
        .arg("--store")
        .arg("file")
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));

    odf_cmd(&home)
        .arg("add")
        .arg("myprov")
        .arg("--client-id")
        .arg("abc")
        .arg("--store")
        .arg("file")
        .arg("--force")
        .assert()
        .success();
}

#[test]
fn test_add_update_idempotent() {
    let home = TempDir::new().unwrap();

    odf_cmd(&home)
        .arg("add")
        .arg("myprov")
        .arg("--client-id")
        .arg("abc")
        .arg("--store")
        .arg("file")
        .assert()
        .success();

    // --update should not error on existing name
    odf_cmd(&home)
        .arg("add")
        .arg("myprov")
        .arg("--client-id")
        .arg("xyz")
        .arg("--store")
        .arg("file")
        .arg("--update")
        .assert()
        .success();
}

#[test]
fn test_list_empty() {
    let home = TempDir::new().unwrap();

    odf_cmd(&home)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("No providers configured"));
}

#[test]
fn test_list_json() {
    let home = TempDir::new().unwrap();

    odf_cmd(&home)
        .arg("add")
        .arg("alpha")
        .arg("--client-id")
        .arg("a")
        .arg("--store")
        .arg("file")
        .assert()
        .success();

    odf_cmd(&home)
        .arg("--output")
        .arg("json")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"type\":\"list\""))
        .stdout(predicate::str::contains("\"name\":\"alpha\""));
}

#[test]
fn test_remove_provider() {
    let home = TempDir::new().unwrap();

    odf_cmd(&home)
        .arg("add")
        .arg("temp")
        .arg("--client-id")
        .arg("t")
        .arg("--store")
        .arg("file")
        .assert()
        .success();

    odf_cmd(&home)
        .arg("remove")
        .arg("temp")
        .assert()
        .success()
        .stdout(predicate::str::contains("removed"));

    odf_cmd(&home)
        .arg("status")
        .arg("temp")
        .assert()
        .failure();
}

#[test]
fn test_remove_ignore_missing() {
    let home = TempDir::new().unwrap();

    odf_cmd(&home)
        .arg("remove")
        .arg("nonexistent")
        .arg("--ignore-missing")
        .assert()
        .success();
}

#[test]
fn test_config_export() {
    let home = TempDir::new().unwrap();

    odf_cmd(&home)
        .arg("add")
        .arg("myprov")
        .arg("--client-id")
        .arg("abc123")
        .arg("--issuer-url")
        .arg("https://auth.example.com")
        .arg("--scopes")
        .arg("openid,profile")
        .arg("--store")
        .arg("file")
        .assert()
        .success();

    odf_cmd(&home)
        .arg("config-export")
        .arg("myprov")
        .assert()
        .success()
        .stdout(predicate::str::contains("client_id = \"abc123\""))
        .stdout(predicate::str::contains("issuer_url = \"https://auth.example.com\""));
}

#[test]
fn test_token_no_token() {
    let home = TempDir::new().unwrap();

    odf_cmd(&home)
        .arg("add")
        .arg("empty")
        .arg("--client-id")
        .arg("e")
        .arg("--store")
        .arg("file")
        .assert()
        .success();

    odf_cmd(&home)
        .arg("token")
        .arg("empty")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("No token found"));
}

#[test]
fn test_token_check_valid() {
    let home = TempDir::new().unwrap();

    odf_cmd(&home)
        .arg("add")
        .arg("checkprov")
        .arg("--client-id")
        .arg("c")
        .arg("--store")
        .arg("file")
        .assert()
        .success();

    // Write a valid token
    let tokens_dir = home.path().join(".local/share/odf/tokens");
    std::fs::create_dir_all(&tokens_dir).unwrap();
    let token_data = serde_json::json!({
        "access_token": "valid-tok",
        "token_type": "Bearer",
        "expires_at": 1893456000i64,
        "scope": "openid"
    });
    std::fs::write(tokens_dir.join("checkprov.json"), serde_json::to_string_pretty(&token_data).unwrap()).unwrap();

    odf_cmd(&home)
        .arg("token")
        .arg("checkprov")
        .arg("--check")
        .assert()
        .success();
    // No output for --check
}

#[test]
fn test_token_check_no_token() {
    let home = TempDir::new().unwrap();

    odf_cmd(&home)
        .arg("add")
        .arg("checkempty")
        .arg("--client-id")
        .arg("c")
        .arg("--store")
        .arg("file")
        .assert()
        .success();

    odf_cmd(&home)
        .arg("token")
        .arg("checkempty")
        .arg("--check")
        .assert()
        .failure()
        .code(2);
}

#[test]
fn test_token_with_file_store() {
    let home = TempDir::new().unwrap();

    odf_cmd(&home)
        .arg("add")
        .arg("fileprov")
        .arg("--client-id")
        .arg("fc")
        .arg("--store")
        .arg("file")
        .assert()
        .success();

    let tokens_dir = home.path().join(".local/share/odf/tokens");
    std::fs::create_dir_all(&tokens_dir).unwrap();
    let token_data = serde_json::json!({
        "access_token": "test-token-abc",
        "refresh_token": "test-refresh-def",
        "token_type": "Bearer",
        "expires_at": 1893456000i64,
        "scope": "openid profile"
    });
    std::fs::write(tokens_dir.join("fileprov.json"), serde_json::to_string_pretty(&token_data).unwrap()).unwrap();

    // raw format
    odf_cmd(&home)
        .arg("token")
        .arg("fileprov")
        .assert()
        .success()
        .stdout("test-token-abc");

    // header format
    odf_cmd(&home)
        .arg("token")
        .arg("fileprov")
        .arg("--format")
        .arg("header")
        .assert()
        .success()
        .stdout("Bearer test-token-abc");

    // env format
    odf_cmd(&home)
        .arg("token")
        .arg("fileprov")
        .arg("--format")
        .arg("env")
        .assert()
        .success()
        .stdout("ODF_TOKEN_fileprov=test-token-abc");
}

#[test]
fn test_token_json() {
    let home = TempDir::new().unwrap();

    odf_cmd(&home)
        .arg("add")
        .arg("jsonprov")
        .arg("--client-id")
        .arg("jc")
        .arg("--store")
        .arg("file")
        .assert()
        .success();

    let tokens_dir = home.path().join(".local/share/odf/tokens");
    std::fs::create_dir_all(&tokens_dir).unwrap();
    let token_data = serde_json::json!({
        "access_token": "json-token-xyz",
        "token_type": "Bearer",
        "expires_at": 1893456000i64,
        "scope": "openid"
    });
    std::fs::write(tokens_dir.join("jsonprov.json"), serde_json::to_string_pretty(&token_data).unwrap()).unwrap();

    odf_cmd(&home)
        .arg("--output")
        .arg("json")
        .arg("token")
        .arg("jsonprov")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"type\":\"token\""))
        .stdout(predicate::str::contains("\"access_token\":\"json-token-xyz\""))
        .stdout(predicate::str::contains("\"sensitive\":true"));
}

#[test]
fn test_status_json() {
    let home = TempDir::new().unwrap();

    odf_cmd(&home)
        .arg("add")
        .arg("jsontest")
        .arg("--client-id")
        .arg("j")
        .arg("--store")
        .arg("file")
        .assert()
        .success();

    let tokens_dir = home.path().join(".local/share/odf/tokens");
    std::fs::create_dir_all(&tokens_dir).unwrap();
    let token_data = serde_json::json!({
        "access_token": "json-token",
        "token_type": "Bearer",
        "expires_at": 1893456000i64,
        "scope": "openid"
    });
    std::fs::write(tokens_dir.join("jsontest.json"), serde_json::to_string_pretty(&token_data).unwrap()).unwrap();

    // JSON status should NOT contain the access_token
    odf_cmd(&home)
        .arg("--output")
        .arg("json")
        .arg("status")
        .arg("jsontest")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"type\":\"status\""))
        .stdout(predicate::str::contains("\"valid\":true"))
        .stdout(predicate::str::contains("access_token").not());
}

#[test]
fn test_json_error_format() {
    let home = TempDir::new().unwrap();

    // Request a nonexistent provider in JSON mode
    odf_cmd(&home)
        .arg("--output")
        .arg("json")
        .arg("status")
        .arg("nonexistent")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("\"type\":\"error\""))
        .stderr(predicate::str::contains("\"exit_code\""));
}

#[test]
fn test_config_command() {
    let home = TempDir::new().unwrap();

    odf_cmd(&home)
        .arg("config")
        .assert()
        .success()
        .stdout(predicate::str::contains("Paths:"))
        .stdout(predicate::str::contains("Providers:"))
        .stdout(predicate::str::contains("Tokens:"))
        .stdout(predicate::str::contains("Keyring:"));
}

#[test]
fn test_config_command_json() {
    let home = TempDir::new().unwrap();

    odf_cmd(&home)
        .arg("--output")
        .arg("json")
        .arg("config")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"type\":\"config\""))
        .stdout(predicate::str::contains("\"keyring\""))
        .stdout(predicate::str::contains("\"counts\""));
}

#[test]
fn test_add_with_insecure() {
    let home = TempDir::new().unwrap();

    odf_cmd(&home)
        .arg("add")
        .arg("selfsigned")
        .arg("--client-id")
        .arg("ss")
        .arg("--issuer-url")
        .arg("https://dex.local")
        .arg("--insecure")
        .arg("--store")
        .arg("file")
        .assert()
        .success();

    odf_cmd(&home)
        .arg("config-export")
        .arg("selfsigned")
        .assert()
        .success()
        .stdout(predicate::str::contains("insecure = true"));
}

#[test]
fn test_ensure_valid() {
    let home = TempDir::new().unwrap();

    odf_cmd(&home)
        .arg("add")
        .arg("ensureprov")
        .arg("--client-id")
        .arg("ec")
        .arg("--store")
        .arg("file")
        .assert()
        .success();

    let tokens_dir = home.path().join(".local/share/odf/tokens");
    std::fs::create_dir_all(&tokens_dir).unwrap();
    let token_data = serde_json::json!({
        "access_token": "ensure-token",
        "token_type": "Bearer",
        "expires_at": 1893456000i64,
        "scope": "openid"
    });
    std::fs::write(tokens_dir.join("ensureprov.json"), serde_json::to_string_pretty(&token_data).unwrap()).unwrap();

    // Text mode: prints bare token
    odf_cmd(&home)
        .arg("ensure")
        .arg("ensureprov")
        .assert()
        .success()
        .stdout("ensure-token");

    // JSON mode: includes action and sensitive flag
    odf_cmd(&home)
        .arg("--output")
        .arg("json")
        .arg("ensure")
        .arg("ensureprov")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"type\":\"ensure\""))
        .stdout(predicate::str::contains("\"action\":\"valid\""))
        .stdout(predicate::str::contains("\"sensitive\":true"));
}

#[test]
fn test_ensure_no_token() {
    let home = TempDir::new().unwrap();

    odf_cmd(&home)
        .arg("add")
        .arg("ensureempty")
        .arg("--client-id")
        .arg("ee")
        .arg("--store")
        .arg("file")
        .assert()
        .success();

    odf_cmd(&home)
        .arg("ensure")
        .arg("ensureempty")
        .assert()
        .failure()
        .code(2);
}

#[test]
fn test_token_redaction_in_pipe() {
    let home = TempDir::new().unwrap();

    odf_cmd(&home)
        .arg("add")
        .arg("redactprov")
        .arg("--client-id")
        .arg("rc")
        .arg("--store")
        .arg("file")
        .assert()
        .success();

    // Write a token long enough for redaction
    let tokens_dir = home.path().join(".local/share/odf/tokens");
    std::fs::create_dir_all(&tokens_dir).unwrap();
    let token_data = serde_json::json!({
        "access_token": "abcdefghijklmnop_long_token_xyz",
        "token_type": "Bearer",
        "expires_at": 1893456000i64,
        "scope": "openid"
    });
    std::fs::write(tokens_dir.join("redactprov.json"), serde_json::to_string_pretty(&token_data).unwrap()).unwrap();

    // When piped (non-TTY, as assert_cmd runs), full token should be output
    odf_cmd(&home)
        .arg("token")
        .arg("redactprov")
        .assert()
        .success()
        .stdout(predicate::str::contains("abcdefghijklmnop_long_token_xyz"));

    // --reveal should also output full token
    odf_cmd(&home)
        .arg("token")
        .arg("redactprov")
        .arg("--reveal")
        .assert()
        .success()
        .stdout(predicate::str::contains("abcdefghijklmnop_long_token_xyz"));
}

