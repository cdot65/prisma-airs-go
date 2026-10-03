# Configuration

All clients can be configured via environment variables, constructor options, or a combination of both. OAuth constructor options take precedence over environment variables. Runtime
scan options use environment fallbacks for empty credentials; the scan endpoint
uses its environment override when the configured value equals the SDK default.

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

## Custom HTTP client

Every client accepts your own `*http.Client` for timeouts, proxies, custom transports or tracing.
It carries both API and OAuth token traffic. Without one, the SDK uses a default client with no
overall timeout (bound requests with the `context` you pass), pooled connections, and a 30-second
limit on token requests that have no deadline of their own.

```go
hc := &http.Client{Timeout: 45 * time.Second}

scanner := runtime.NewScanner(aisec.NewConfig(aisec.WithHTTPClient(hc)))
client, err := runtime.NewClient(runtime.Opts{HTTPClient: hc})
// modelsecurity.Opts, redteam.Opts, gateway.Opts, and agentguard.Opts share this field.
```

Endpoint resolution for the OAuth services is: option → environment variable → default, and
trailing slashes are ignored.

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

## AI Gateway management (SCM OAuth)

Use `gateway.NewClient(gateway.Opts{})` with `PANW_AI_GW_*` credentials, or
provide `ClientID`, `ClientSecret`, and `TsgID` explicitly. These credentials fall
back to `PANW_MGMT_*`. `DataEndpoint` and `AdminEndpoint` override the two Gateway
CRUD planes. SDK v0.8.0 adds `IAMEndpoint` and workspace
provisioning. Its separate `InferenceOpts` requires an explicit runtime endpoint
and API key; SCM credentials are never reused for inference.
See the [workspace and inference examples](../examples/gateway-workspaces-inference.md).
See [Gateway management](../services/ai-gateway-api.md) for schemas and lifecycle
semantics and [environment variables](../reference/environment-variables.md) for
all overrides.

## Skill scanning (AgentGuard public preview) (SCM OAuth)

Use `agentguard.NewClient(agentguard.Opts{})` with both service base URLs in
`PANW_AGENT_GUARD_DATA_ENDPOINT` and `PANW_AGENT_GUARD_MGMT_ENDPOINT`, or set
`DataEndpoint` and `MgmtEndpoint` explicitly. The preview has no URL defaults.
Credentials use `PANW_AGENT_GUARD_*` with `PANW_MGMT_*` fallback; API endpoint
overrides are service-specific. See [AgentGuard](../services/agentguard-api.md).
