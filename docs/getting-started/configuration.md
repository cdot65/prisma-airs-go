# Configuration

All clients can be configured via environment variables, constructor options, or a combination of both. Constructor options take precedence over environment variables.

## Runtime API — Scanning (API Key Auth)

| Variable | Description | Required |
|----------|-------------|----------|
| `PANW_AI_SEC_API_KEY` | API key for HMAC-SHA256 signing | Yes (or use `PANW_AI_SEC_API_TOKEN`) |
| `PANW_AI_SEC_API_TOKEN` | Bearer token (alternative to API key) | No |
| `PANW_AI_SEC_API_ENDPOINT` | Override default scan endpoint | No |

```go
// From environment variables
cfg := aisec.NewConfig() // reads PANW_AI_SEC_* env vars

// Explicit configuration
cfg := aisec.NewConfig(
    aisec.WithAPIKey("your-api-key"),
    aisec.WithEndpoint("https://service.api.aisecurity.paloaltonetworks.com"),
)
```

## Runtime API — Management (OAuth2)

| Variable | Description | Required |
|----------|-------------|----------|
| `PANW_MGMT_CLIENT_ID` | OAuth2 client ID | Yes |
| `PANW_MGMT_CLIENT_SECRET` | OAuth2 client secret | Yes |
| `PANW_MGMT_TSG_ID` | Tenant service group ID | Yes |
| `PANW_MGMT_ENDPOINT` | Override management API endpoint | No |
| `PANW_MGMT_TOKEN_ENDPOINT` | Override OAuth2 token endpoint | No |

```go
// From environment variables
client, err := runtime.NewClient(runtime.Opts{})

// Explicit configuration
client, err := runtime.NewClient(runtime.Opts{
    ClientID:     "your-client-id",
    ClientSecret: "your-client-secret",
    TsgID:        "1234567890",
})
```

## Model Security API (OAuth2)

Falls back to `PANW_MGMT_*` variables if service-specific variables are not set.

| Variable | Fallback | Description |
|----------|----------|-------------|
| `PANW_MODEL_SEC_CLIENT_ID` | `PANW_MGMT_CLIENT_ID` | OAuth2 client ID |
| `PANW_MODEL_SEC_CLIENT_SECRET` | `PANW_MGMT_CLIENT_SECRET` | OAuth2 client secret |
| `PANW_MODEL_SEC_TSG_ID` | `PANW_MGMT_TSG_ID` | Tenant service group ID |
| `PANW_MODEL_SEC_DATA_ENDPOINT` | — | Override data plane endpoint |
| `PANW_MODEL_SEC_MGMT_ENDPOINT` | — | Override management plane endpoint |
| `PANW_MODEL_SEC_TOKEN_ENDPOINT` | `PANW_MGMT_TOKEN_ENDPOINT` | Override token endpoint |

## Red Team API (OAuth2)

Falls back to `PANW_MGMT_*` variables if service-specific variables are not set.

| Variable | Fallback | Description |
|----------|----------|-------------|
| `PANW_RED_TEAM_CLIENT_ID` | `PANW_MGMT_CLIENT_ID` | OAuth2 client ID |
| `PANW_RED_TEAM_CLIENT_SECRET` | `PANW_MGMT_CLIENT_SECRET` | OAuth2 client secret |
| `PANW_RED_TEAM_TSG_ID` | `PANW_MGMT_TSG_ID` | Tenant service group ID |
| `PANW_RED_TEAM_DATA_ENDPOINT` | — | Override data plane endpoint |
| `PANW_RED_TEAM_MGMT_ENDPOINT` | — | Override management plane endpoint |
| `PANW_RED_TEAM_TOKEN_ENDPOINT` | `PANW_MGMT_TOKEN_ENDPOINT` | Override token endpoint |

## Regional Endpoints

### Scan API

| Region | Endpoint |
|--------|----------|
| US (default) | `https://service.api.aisecurity.paloaltonetworks.com` |
| EU | `https://service-de.api.aisecurity.paloaltonetworks.com` |
| India | `https://service-in.api.aisecurity.paloaltonetworks.com` |
| Singapore | `https://service-sg.api.aisecurity.paloaltonetworks.com` |

### Runtime (Management) / Model Security / Red Team

All OAuth2-based APIs share the same base domains. Override using the endpoint environment variables above.
