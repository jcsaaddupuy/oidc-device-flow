# odf — OIDC Device Flow CLI

Manage OIDC tokens for any CLI tool using the device authorization grant.

## Install

```bash
cargo install --git https://github.com/autonomous-toaster/oidc-device-flow
```

## Quick Start

```bash
# Register a provider
odf add github --issuer-url https://github.com --client-id Iv1.abc123 --scopes openid,profile,email

# Authenticate (opens browser)
odf login github

# Use the token
curl -H "Authorization: Bearer $(odf token github)" https://api.github.com/user
```

## Commands

| Command | Description |
|---|---|
| `odf add <name> [options]` | Register a new OIDC provider |
| `odf login <name>` | Authenticate via device flow |
| `odf token <name>` | Print access token (auto-refreshes if expired) |
| `odf refresh <name>` | Force refresh the token |
| `odf status <name>` | Show token health, expiry, scopes |
| `odf list` | List all providers and token status |
| `odf remove <name>` | Remove provider and its tokens |
| `odf config export [name]` | Export provider config as TOML (no secrets) |

## Examples

### Self-hosted OIDC (Dex) with self-signed certs

```bash
odf add searxng \
  --issuer-url https://dex.example.com \
  --client-id searxng \
  --scopes openid,profile,email,groups \
  --insecure

odf login searxng
curl -s "https://searxng.example.com/search?q=hello&format=json" \
  -H "Authorization: Bearer $(odf token searxng)" --insecure | jq '.results[].title'
```

### Multiple providers

```bash
odf add github-read --issuer-url https://github.com --client-id Iv1.abc --scopes read
odf add github-write --issuer-url https://github.com --client-id Iv1.abc --scopes write,repo
odf token github-read   # different scope, different token
```

### CI / Automation

```bash
# Print URL for out-of-band authorization (no TTY needed)
URL=$(odf login myapp --print-url)
echo "Authorize at: $URL" | slack-notify

# Structured JSON output
odf login myapp --print-url --json
# {"url":"https://...","user_code":"ABCD-1234","interval":5}
```

### Token output formats

```bash
# Bare token (default) — pipes cleanly
curl -H "Authorization: Bearer $(odf token myapp)" https://api.example.com/me

# Header format
eval "$(odf token myapp --format header)"
# prints: Bearer eyJ...

# Env format — load multiple providers
eval "$(odf token github --format env)"
eval "$(odf token aws --format env)"
# $ODF_TOKEN_github, $ODF_TOKEN_aws available
```

### Explicit endpoints (no discovery)

```bash
odf add legacy \
  --device-auth-endpoint https://auth.example.com/device/code \
  --token-endpoint https://auth.example.com/token \
  --client-id my-client \
  --scopes openid
```

### Token storage

By default, `odf` uses the OS keychain (macOS Keychain, Windows Credential Manager, Linux secret-service).
Falls back to file-based storage if keyring is unavailable.

```bash
# Force file-based storage
odf add myapp --store file --client-id abc --issuer-url https://...

# Force keyring
odf add myapp --store keyring --client-id abc --issuer-url https://...
```

### Verify token with introspection

```bash
odf status myapp --verify
# Queries the provider's introspection endpoint to check server-side validity
```

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Generic error |
| 2 | Auth error (expired token, no refresh token) |
| 3 | Network error |

## Configuration

- Provider configs: `~/.config/odf/providers/<name>.toml`
- Token data: `~/.local/share/odf/tokens/<name>.json` (chmod 600)
- Discovery cache: `~/.cache/odf/discovery/<name>.json`

## Building without keyring

```bash
cargo install --no-default-features  # pure file-based token storage
```
