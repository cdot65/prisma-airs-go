# AI Gateway management

`aisec/gateway` covers twelve resource families and all 88 CRUD/lifecycle
operations selected from the pinned October 2026 Gateway specification. It uses
SCM OAuth with the `x-tsg-id` header. An existing workspace is required for
workspace resources. Credentials resolve from constructor options, then
`PANW_AI_GW_*`, then `PANW_MGMT_*`.

```go
import (
    "context"
    "github.com/cdot65/prisma-airs-go/aisec/gateway"
    "github.com/cdot65/prisma-airs-go/aisec/gateway/schema"
)

client, err := gateway.NewClient(gateway.Opts{})
if err != nil { return err }
configs, err := client.Configs.List(context.Background(), schema.ConfigsListOptions{
    WorkspaceID: "existing-workspace-uuid",
})
```

| Client | Plane | Operations |
|---|---|---|
| `Configs` | data | CRUD, immutable version history |
| `Guardrails` | data | CRUD, list/sync/upsert MCP server mappings |
| `OrgGuardrails` | admin | CRUD, list/sync/upsert MCP server mappings |
| `Providers` | data | CRUD, explicit workspace query scope |
| `Integrations` | admin | CRUD, model selection, workspace bindings |
| `MCPIntegrations` | admin | CRUD, bindings, capabilities, sync metadata |
| `MCPServers` | data | CRUD, connectivity test, capabilities, user access, connections |
| `APIKeys` | data | CRUD, explicit rotation, service/user ownership routes |
| `UsageLimits` | data | CRUD, list counters, explicit owned-counter reset |
| `RateLimits` | data | CRUD |
| `SecretReferences` | admin | CRUD for external secret references |
| `Deployments` | admin | CRUD with archival delete, connectivity ping |

The data base defaults to `https://api.apps.paloaltonetworks.com/ai_gw/v2`;
the admin base defaults to `https://api.apps.paloaltonetworks.com/ai_gw/admin/v2`.
Override them with `DataEndpoint`, `AdminEndpoint`, or the corresponding
`PANW_AI_GW_DATA_ENDPOINT` / `PANW_AI_GW_ADMIN_ENDPOINT` variables. Org guardrail
paths are relative to the admin base; `/admin/v2` is applied once. `HTTPClient`
overrides both API and token transports. Both planes share one token cache.

## Models and updates

Request, receipt and read models live in `aisec/gateway/schema`. Optional
non-null fields use pointers; optional nullable fields use `aisec.Optional[T]`.
Use `aisec.Value(value)` for a value, `aisec.Null[T]()` for explicit null, and an
unset optional to omit it. Pointer-to-false, pointer-to-zero, and pointer-to-empty
collections remain explicit on the wire. The service validates semantic limits.
`AdditionalFields` preserves unmodeled JSON fields and cannot override known
fields. It supports future service metadata without losing typed current fields.

Configuration fields use `schema.JSONDocument`. Reads preserve either an object
or a JSON-encoded string. `Decode(&value)` reads the object; `NewJSONDocument(value)`
creates a document for writes. Malformed documents return a wrapped SDK error
and no partial result. Whole config documents replace prior nested contents:
include every routing setting you intend to retain when updating a config.

PUT generally updates supplied top-level fields. Nested documents can replace
stored contents. Workspace/deployment bindings merge unless the explicit override
flag selects replacement; explicit removals and empty collections have distinct
semantics. The SDK performs only the requested operation. The Terraform provider
owns refresh, reconciliation, timeouts, dependency ordering and state.

Create responses are receipts. Read the resource explicitly for its current
stored representation. API-key create/rotate and deployment create return
one-time secret material. Capture it once; subsequent reads may return masked
values. The SDK never synthesizes, logs or automatically rotates those secrets.

## SCM compatibility and scope

The generic upstream servers/auth differ from SCM deployment. Source artifacts
remain unchanged; `specs/gateway_scope.json`, the generator and `API_ISSUES.md`
record selection/routing and observed compatibility fields. Config reads and
creation receipts accept both the upstream envelope and flat SCM records. SCM
config listing needs an explicit workspace query absent from the generic spec.

The combined `/api-keys` collection returned 403 live. Use
`APIKeys.ListForKind(ctx, gateway.APIKeyService, options)` and the corresponding
`GetForKind`, `UpdateForKind`, `DeleteForKind`, `RotateForKind` methods. User keys
use `gateway.APIKeyUser`; `Create` takes the kind explicitly. Canonical generic
methods remain available without automatic route fallback or ownership changes.

For org integrations, create with the numeric TSG as `OrganisationID`, then
explicitly grant the new integration access to a workspace through `SetWorkspaces`
before creating a provider/MCP server there. A read's internal organisation UUID
is a different identifier. Workspace-scoped integration creation returned 403 on
the tested tenant. Provider selection must use the matching catalog UUID; Azure
OpenAI and OpenAI are separate provider families.

Deployment delete archives the record; archived deployments can remain listed.
`Ping`/MCP `Test` are explicit connectivity operations. No infrastructure is
installed or provisioned. Inference, streaming, Realtime and workspace/IAM
provisioning are outside this management client.

[Live evidence and limits](../developer/live-verification.md) separate disposable
CRUD verification from mock-only helpers requiring traffic, real third-party
credentials, connected infrastructure or user consent.
