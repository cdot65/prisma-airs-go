# Terraform consumer handoff: SDK v0.6.0

The [v0.6.0 release](https://github.com/cdot65/prisma-airs-go/releases/tag/v0.6.0)
integrates the pinned October API specifications and adds AI Gateway management.
The existing Terraform provider passed race tests and a binary build on Go
1.25.6 through a temporary module override. Its tracked dependency remains
v0.4.1; live Terraform acceptance tests and new provider resources are separate
work.

## Existing resource compatibility

- Runtime profile/topic/API-key resource calls retain their public interfaces.
  Topic force deletion and key regeneration use live-verified current routes.
  Key regeneration returns a replacement key ID; consumers must use the returned
  ID and one-time credentials rather than assume the old ID persists.
- Deprecated Red Team prompt-set `Properties map[string]any` remains available
  on create/update requests with its original `properties,omitempty` JSON field.
  `PropertyNames []string` remains the current field. The SDK does not invent a
  conversion from metadata maps to property-name lists, and current service
  support for the legacy map is not guaranteed.
- Existing response field types remain available. Richer current responses use
  additive precise methods and `schema` packages. Existing provider state does
  not require an automatic schema migration merely to compile with this SDK.
- Match missing resources with `errors.Is(err, aisec.ErrNotFound)` or
  `aisec.IsNotFound(err)`. HTTP failures carry `AISecSDKError.StatusCode`;
  malformed success bodies also return typed errors with their decoding cause.
  Allowed text/empty deletes and JSON-string delete messages remain successful.

## Mapping new capabilities into Terraform

The SDK's nullable updates use `aisec.Optional[T]` to distinguish omitted,
explicit null, and a concrete value. Match Terraform plan intent explicitly;
preserve false, zero, empty lists, and null clears. Unknown planned values need
provider handling before an API request can be constructed.

Model Security adds model/version/file inventory, custom rules and assignment,
and rule/group history. Red Team adds adapters, Network Broker and current
reports/metadata. Network Broker has no delete endpoint; model custom rules are
archived instead of deleted. Do not model nonexistent remote deletion as a
successful destructive operation.

Gateway exposes twelve management CRUD families and explicit lifecycle helpers
using SCM OAuth with tenant headers. Workspaces must already exist. Inference,
streaming, workspace provisioning, and new Terraform resource implementations
are outside this release's scope.

- Configuration documents replace nested stored contents; retain desired routing
  settings when constructing an update. `JSONDocument` preserves an object or a
  JSON-encoded object and supports typed encoding/decoding.
- Partial top-level updates, binding merges, explicit replacement flags, and
  empty collection removals have different semantics. Resource ownership and
  refresh/reconciliation belong to the provider.
- API-key create/rotate and deployment create may return secrets once. Use
  sensitive state where appropriate; read receipts and masked values do not
  synthesize lost credentials. Use explicit service/user API-key methods for
  the SCM routes verified in the release.
- Deployment deletion archives the record. An archived deployment can remain
  listed, so state reconciliation must account for its lifecycle status.

See the [Gateway guide](docs/services/ai-gateway-api.md),
[complete contracts](docs/reference/api-reference.md),
[feature reviews](docs/developer/feature-quality.md), and
[live verification](docs/developer/live-verification.md) before adding resources.
The documented Red Team scan-metadata route currently returns upstream HTTP 422;
its strict live assertion remains failing. Mock-only execution helpers and
tenant-specific limits are explicitly recorded.

## Consumer update procedure

1. Update the provider's dependency to
   `github.com/cdot65/prisma-airs-go v0.6.0` in the provider's own change.
2. Run provider race tests and build, then targeted acceptance tests using
   disposable fixtures for changed resources.
3. Add richer field/state mappings alongside the provider resource changes;
   SDK API availability alone does not implement a Terraform resource.

Release executables are SDK examples, not provider binaries. Their platform
archives and checksums are documented in [release artifacts](docs/developer/releases.md).
