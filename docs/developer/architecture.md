# SDK architecture

The Go SDK provides independent clients for Runtime Security, Model Security,
Red Team, and AI Gateway management. Import only the packages your application
needs; the runtime module uses the Go standard library and supports Go 1.22+.

```mermaid
flowchart LR
    App[Go application or Terraform provider] --> Scan[Runtime Scanner]
    App --> Runtime[Runtime management Client]
    App --> Model[Model Security Client]
    App --> RedTeam[Red Team Client]
    App --> Gateway[Gateway management Client]
    Scan --> HMAC[API key or bearer transport]
    Runtime --> OAuth[Shared OAuth request pipeline]
    Model --> OAuth
    RedTeam --> OAuth
    Gateway --> OAuth
```

## Authentication and transport

Runtime scans accept API keys or bearer tokens. Management clients use OAuth2
client credentials with shared token caching, proactive refresh, concurrent
deduplication, and bounded authorization retries. Gateway uses SCM OAuth with
an `x-tsg-id` header on API requests. Its data and admin planes share the token
cache; Red Team's Network Broker has an independent API endpoint.

Constructor options override service-specific environment variables, followed
by management fallbacks where supported. Every request accepts a context, and
all API and token traffic uses the configured HTTP client. See
[configuration](../getting-started/configuration.md),
[environment variables](../reference/environment-variables.md), and
[OAuth lifecycle](../services/oauth-lifecycle.md).

## Contracts and compatibility

Established interfaces remain available alongside additive complete response
methods and generated `schema` packages. Nullable updates use `aisec.Optional[T]`
to distinguish omission, null, and a value. Explicit false, zero, and empty
collections remain distinct update intents. Gateway configuration documents
preserve dynamic JSON and unknown fields.

HTTP errors carry status and wrapped causes through `AISecSDKError`; match
sentinels with `errors.Is`. Response interpretation rejects malformed JSON and
partial results while keeping endpoint-specific text/empty delete exceptions.
See [API reference](../reference/api-reference.md) and
[error handling](../reference/error-handling.md).

## SDK and provider responsibilities

SDK methods perform explicit API operations. The caller owns refresh,
reconciliation, timeouts, dependency ordering, and state. Gateway workspaces
must already exist; this client covers management CRUD and lifecycle helpers.
Inference, streaming, workspace provisioning, and Terraform resource
implementation are separate concerns.

Before adding a capability, consult the pinned inputs in `specs/manifest.json`
and the public HTTP contract tests. Current evidence is recorded separately in
[live verification](live-verification.md) and [feature reviews](feature-quality.md).
The [release guide](releases.md) explains source, example binaries, checksums,
and reproducible builds.
