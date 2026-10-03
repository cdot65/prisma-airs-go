# Terraform consumer handoff: SDK v0.7.0

SDK v0.7.0 adds `aisec/agentguard` and `aisec/agentguard/schema` for all 21
AgentGuard public preview operations. Existing service interfaces and models
remain compatible. This release does not update the provider dependency or
implement AgentGuard Terraform resources.

## AgentGuard mapping

Six sub-clients expose scans, statistics, tenant instances, rules, rule instances,
and trusted skill overrides. Both planes use SCM OAuth with `x-tsg-id` and share
a token cache. Credentials resolve through `PANW_AGENT_GUARD_*`, then
`PANW_MGMT_*`; data and management base URLs must be configured explicitly.

Generated models use `aisec.Optional[T]` for omitted/null/value intent. Preserve
explicit false and null clears when mapping planned Terraform values. Instance
metadata permits extensions through `AdditionalFields`. Rule configuration updates
send an atomic map of rule-instance UUIDs to their desired state. Instance
deletion returns a JSON receipt; skill-override deletion returns no content.

Skill scan submission has three steps: reserve an upload URL, send the archive to
signed storage, and complete the upload. Storage transfer, polling, and deadlines
belong to the consumer. Scans have no deletion endpoint, so do not implement
remote scan destruction as a successful API delete.

## Verification and adoption

All 21 operations have HTTP contract tests. A live public skill ZIP was uploaded
unchanged without local extraction, then reached `COMPLETED` / `ALLOWED` with
zero findings and attack chains. Management operations, lookup, CSV, statistics,
and chain detail retain mock-only verification in this Go run.

Update the provider dependency in its own change, run its race tests and build,
and validate any new resource mappings against disposable tenant fixtures.
See the [AgentGuard guide](docs/services/agentguard-api.md),
[models](docs/reference/generated/agentguard-schema.md), and
[live verification](docs/developer/live-verification.md#agentguard-public-preview--2026-10-03).
