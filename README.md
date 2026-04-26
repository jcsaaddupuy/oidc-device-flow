# odf — OIDC Device Flow CLI

Manage OIDC tokens for any CLI tool using the device authorization grant.
Designed for automation and AI-assistant workflows.

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

### Microsoft Entra ID (Azure AD)

```bash
# Register Entra ID provider
# Replace <tenant-id>, <client-id> with your values
odf add entra \
  --issuer-url https://login.microsoftonline.com/<tenant-id>/v2.0 \
  --client-id <client-id> \
  --scopes "openid,profile,User.Read"

# Authenticate
odf login entra

# Use the token with Microsoft Graph API
curl -H "Authorization: Bearer $(odf token entra)" \
  https://graph.microsoft.com/v1.0/me
```


## Commands

| Command | Description |
|---|---|
| `odf add <name> [options]` | Register a new OIDC provider |
| `odf login <name>` | Authenticate via device flow |
| `odf token <name>` | Print access token (auto-refreshes if expired) |
| `odf ensure <name>` | Get a valid token: check → refresh → print |
| `odf refresh <name>` | Force refresh the token |
| `odf status <name>` | Show token health, expiry, scopes |
| `odf list` | List all providers and token status |
| `odf remove <name>` | Remove provider and its tokens |
| `odf config` | Show configuration paths and status |
| `odf config export [name]` | Export provider config as TOML (no secrets) |
| `odf discover <name>` | Force-refresh OIDC discovery cache |

## Token Safety

Tokens are sensitive. `odf` protects against accidental leaks:

**TTY-guarded output** — when stdout is a terminal, tokens are redacted:

```
$ odf token myapp
eyJhbGci...nrng
```

When captured or piped, the full token flows so commands work transparently:

```bash
curl -H "Authorization: Bearer $(odf token myapp)" https://api.example.com/me  # full token
odf token myapp | wc -c   # full token
odf token myapp > /tmp/t  # redacted (file redirect)
```

Use `--reveal` to show the full token on a terminal:

```
$ odf token myapp --reveal
eyJhbGciOiJSUzI1NiIsImtpZCI6IjA2NWJkYzE2...
```

**No token in non-token commands** — `odf status`, `odf list`, `odf refresh`, and `odf config` never include the access token value, even in JSON mode.

**JSON mode always includes the full token** (it's for programmatic consumers) but marks it with `"sensitive": true`:

```json
{"type":"token","version":1,"access_token":"eyJ...","sensitive":true}
```

## AI-Friendly Features

### Global `--output` flag

All commands support `--output json` for structured, machine-parseable output:

```bash
odf --output json list
odf --output json status myapp
odf --output json ensure myapp
```

Every JSON response is wrapped in an envelope with `type` and `version`:

```json
{"type":"status","version":1,"name":"myapp","valid":true,...}
```

### JSON errors on stderr

When `--output json` is active, errors go to stderr as structured JSON:

```json
{"type":"error","version":1,"error":"AuthError","message":"No token found","exit_code":2}
```

### `odf ensure` — one command for automation

Check if a token is valid, refresh if expired, print it. Exit 2 if no token.

```bash
# In a script:
TOKEN=$(odf ensure myapp) || { echo "Login required"; exit 1; }
curl -H "Authorization: Bearer $TOKEN" https://api.example.com/me
```

### `odf token --check` — exit-code-only validity

No output. Just the exit code. Perfect for shell conditionals:

```bash
if odf token myapp --check; then
  echo "Token is valid"
else
  echo "Token expired or missing"
fi
```

### `odf login --print-url` — CI-friendly

Prints the verification URL to stdout. When the token is granted, prints the token too — one round-trip for automation:

```bash
URL=$(odf login myapp --print-url)
# ...user authorizes...
# token appears on stdout after polling completes
```

### Idempotent operations

```bash
odf add myapp --update --client-id abc --issuer-url https://...  # no error if exists
odf remove myapp --ignore-missing  # succeed silently if not found
```

### `odf token --all` — batch all providers

```bash
# Env format for all providers
eval "$(odf token --all --format env)"
# $ODF_TOKEN_github, $ODF_TOKEN_aws, etc.
```

## Examples

### Microsoft Entra ID (Azure AD)

```bash
# Register Entra ID provider
# Replace <tenant-id>, <client-id> with your values
odf add entra \
  --issuer-url https://login.microsoftonline.com/<tenant-id>/v2.0 \
  --client-id <client-id> \
  --scopes "openid,profile,User.Read"

# Authenticate
odf login entra

# Use the token with Microsoft Graph API
curl -H "Authorization: Bearer $(odf token entra)" \
  https://graph.microsoft.com/v1.0/me
```

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

### Token output formats

```bash
# Bare token (default) — pipes cleanly
curl -H "Authorization: Bearer $(odf token myapp)" https://api.example.com/me

# Header format
eval "$(odf token myapp --format header)"  # prints: Bearer eyJ...

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

- Provider configs: `~/.config/odf/providers/<name>.toml` (or `~/Library/Application Support/odf/providers/` on macOS)
- Token data: `~/.local/share/odf/tokens/<name>.json` (chmod 600)
- Discovery cache: `~/.cache/odf/discovery/<name>.json`

All paths respect `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME` environment variables.