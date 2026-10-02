# Authentication

Choose credentials by the operation you want to perform. Runtime content
scanning, OAuth service management, and Gateway management are separate paths.
A credential working on one path does not establish access to another.

## Choose a credential

| Operation | Client | Credential |
| --- | --- | --- |
| Scan prompts, responses, code, and tool events | `runtime.Scanner` | Scanning API key or bearer token |
| Manage Runtime profiles, topics, and API keys | `runtime.Client` | OAuth client ID, secret, TSG ID |
| Read models and scans; manage model policy | `modelsecurity.Client` | OAuth client ID, secret, TSG ID |
| Manage red-team targets, jobs, reports, and brokers | `redteam.Client` | OAuth client ID, secret, TSG ID |
| Manage Gateway resources in existing workspaces | `gateway.Client` | SCM OAuth client ID, secret, TSG ID |

## Runtime scanning

`aisec.NewConfig()` reads `PANW_AI_SEC_API_KEY` and `PANW_AI_SEC_API_TOKEN`.
An API key uses the SDK's HMAC signing path. A bearer token uses the token path;
choose the credential appropriate to your scan endpoint. If both values are
configured, the transport sends both headers. Constructor options
such as `aisec.WithAPIKey` override the corresponding environment value.

A scanning bearer token is supplied by the caller. The scanner does not perform
the management client's OAuth refresh lifecycle for that token.

Use an existing profile name or profile ID as supported by `runtime.AiProfile`.
The [first-scan walkthrough](index.md) uses a name.

## OAuth management

Runtime management reads `PANW_MGMT_CLIENT_ID`, `PANW_MGMT_CLIENT_SECRET`, and
`PANW_MGMT_TSG_ID`. The other services first read their own prefix, then management
fallbacks:

| Client | Primary prefix | Fallback |
| --- | --- | --- |
| `runtime.NewClient` | `PANW_MGMT_` | — |
| `modelsecurity.NewClient` | `PANW_MODEL_SEC_` | `PANW_MGMT_` |
| `redteam.NewClient` | `PANW_RED_TEAM_` | `PANW_MGMT_` |
| `gateway.NewClient` | `PANW_AI_GW_` | `PANW_MGMT_` |

Explicit constructor values take precedence. A management token-endpoint override
is also a fallback for the other OAuth services. API endpoint overrides remain
service-specific. See [environment variables](../reference/environment-variables.md)
for exact names.

```go
client, err := gateway.NewClient(gateway.Opts{})
if err != nil {
    return err
}
```

Gateway uses SCM OAuth and adds `x-tsg-id` to API requests. Data and admin planes
share the same token cache. Your TSG and workspace scope must authorize the
requested operation; the SDK does not grant access or create workspaces.

## Keep credentials separate from examples

The examples read environment variables or constructor options. Supply secret
values through your existing secret-store integration. Keep one-time API-key and
deployment credentials out of logs and Terraform diagnostics. Capture them from
the create or rotate receipt when your application needs to store them.

Use an injected HTTP client for your proxy, transport, or tracing setup. Reuse
clients and set request deadlines with contexts. [Configuration](configuration.md)
shows the transport options, and [OAuth lifecycle](../services/oauth-lifecycle.md)
explains caching, refresh, and the bounded retry after a 401 or 403.
