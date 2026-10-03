# API Reference

The Go SDK provides independent clients for five service domains. This reference
is generated from the public Go declarations, so established interfaces and
additive complete-response methods appear together. Schema catalogs link to
full versioned field declarations and codec methods.

## Choose a package

| Package | Entry point | Reference |
| --- | --- | --- |
| `aisec` | `NewConfig`, options, errors, nullable values, `Paginate`, `CollectAll` | [Core SDK](generated/aisec.md) |
| `aisec/runtime` | `NewScanner`, `NewClient` | [Runtime Security](generated/runtime.md) |
| `aisec/modelsecurity` | `NewClient` | [Model Security](generated/modelsecurity.md) |
| `aisec/redteam` | `NewClient` | [Red Team](generated/redteam.md) |
| `aisec/gateway` | `NewClient`, `NewInferenceClient`, `NewModelPricingClient` | [AI Gateway](generated/gateway.md) |
| `aisec/agentguard` | `NewClient` | [Skill scanning](generated/agentguard.md) |

```go
import (
    "github.com/cdot65/prisma-airs-go/aisec"
    "github.com/cdot65/prisma-airs-go/aisec/runtime"
    "github.com/cdot65/prisma-airs-go/aisec/modelsecurity"
    "github.com/cdot65/prisma-airs-go/aisec/redteam"
    "github.com/cdot65/prisma-airs-go/aisec/gateway"
    "github.com/cdot65/prisma-airs-go/aisec/agentguard"
)
```

## Current schema catalogs

| Domain | Catalog |
| --- | --- |
| Model Security | [Models, request fields, and complete responses](generated/modelsecurity-schema.md) |
| Red Team | [Targets, jobs, reports, adapters, and broker models](generated/redteam-schema.md) |
| Gateway management | [CRUD requests, receipts, reads, documents, and unions](generated/gateway-schema.md) |
| Skill scanning (AgentGuard preview) | [Scans, findings, instances, rules, and overrides](generated/agentguard-schema.md) |

| TypeScript parity (v0.8.0) | [Workspace/IAM, inference, telemetry, DLP and dashboard models](generated/parity-schema.md) |

Generated current-schema models preserve nullable values and unknown fields
where the contract allows them. Read [provider patterns](../guides/provider-patterns.md)
for omission, explicit null, empty values, receipts, and state.

## Request conventions

Every API method takes `context.Context`. OAuth clients reuse token caching and
refresh; Runtime scanning uses an API key or caller-supplied bearer token.
OAuth constructor options override the corresponding environment configuration.
Runtime scan configuration uses its documented environment fallbacks. See
[authentication](../getting-started/authentication.md) and
[configuration](../getting-started/configuration.md).

An API method returns a typed response and an error. HTTP failures and response
decoding failures use `*aisec.AISecSDKError`, with status and wrapped causes.
Match HTTP sentinels with `errors.Is`; see [error handling](error-handling.md).

## Compatibility and scope

Established convenience interfaces remain available. Additive methods returning
complete schema responses are listed beside them in the generated service
reference. Use the return type that covers the service fields your caller needs.

SDK v0.8.0 adds Gateway workspace/IAM provisioning,
telemetry, inference, SSE and a caller-supplied Realtime socket adapter.
Runtime adds DLP and dashboard clients. These APIs are separate from Terraform
resource reconciliation. See the [parity coverage record](../developer/typescript-parity.md)
for source pins, tests and service verification limits. Service guides explain routing:

- [Runtime scan](../services/scan-api.md) and [management](../services/runtime-api.md)
- [Model Security](../services/model-security-api.md)
- [Red Team](../services/red-team-api.md)
- [Gateway management](../services/ai-gateway-api.md)
- [AgentGuard public preview](../services/agentguard-api.md)

The [live verification record](../developer/live-verification.md) and
[feature reviews](../developer/feature-quality.md) describe evidence and limits.

## Reference maintenance

`go run scripts/generate_api_reference.go` regenerates these pages from the
checked-in source. Documentation CI runs the same tool with `-check` to catch
stale output. The public [Go package documentation](https://pkg.go.dev/github.com/cdot65/prisma-airs-go@v0.8.0/aisec)
provides complete source-linked declarations for the published release.
