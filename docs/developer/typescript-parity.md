# TypeScript SDK parity (v0.9.0)

Go SDK **v0.9.0** retains the parity introduced in v0.8.0 and tracks TypeScript SDK v0.34.0, commit
`4a80dbdb` (full source revision and SHA-256 hashes in
`specs/typescript-parity.json`). Install the complete release with:

```sh
go get github.com/cdot65/prisma-airs-go@v0.9.0
```

v0.9.0 also adds [directional security profiles](directional-security-profiles.md)
from the separately recorded observed contract. Frozen method/spec coverage
denominators remain unchanged.

## Product coverage

| Product | Go additions |
| --- | --- |
| AI Runtime Security | Token-scoped list routes; DLP patterns/profiles/dictionaries; application/session dashboard; OAuth cache facade; all-page helpers |
| AI Red Teaming | All-page scans/targets/adapters/custom attacks; scan metadata with documented 422 fallback |
| AI Gateway | Workspace/IAM provisioning; organization/plugins/audit/log exports; catalogs; telemetry; inference, SSE, binary, multipart and realtime adapter; public model pricing |
| AI Supply Chain Security | Existing Model Security and all 21 skill-scanning (AgentGuard preview) operations remain; all-page Model Security helpers added |

The pinned method map covers **451 TypeScript public class methods**, including
the four AgentGuard read methods. Go uses contexts and idiomatic names; overloads
can map to a shared method or separate streaming function. Symbol coverage alone
does not prove service behavior. Gateway also ports custom-host settings, dotted
values and operation-scoped secret redaction. Dotted builders accept native values and
limit aggregate array allocation to 10,000 elements. `aisec.Paginate` and
`aisec.CollectAll` accept native cursor callbacks; service `ListAll` helpers
default to 10,000 records, with explicit zero `Max` permitting unlimited records
within the safety page cap.

## Contract evidence and limits

Current vendor OpenAPI contracts and their coverage denominators remain unchanged.
`specs/contracts/typescript-parity.json` holds recovered TypeScript shapes, outside
that denominator. The workspace routes were removed from vendor publication;
IAM creation/binding comes from the TypeScript SDK's retained SCM captures.
IAM DELETE was initially inferred; disposable dedicated-scope deletion was subsequently verified on 2026-10-03. This does not establish cleanup of shared scopes or access policies. Provisioning does not grant roles.

Offline verification includes 49 retained TypeScript runtime wire cases, 63
synthetic management route/plane cases, a retained public pricing catalog,
a synthetic dashboard body, and focused transport, paging, query,
authentication and nullable-update tests. Synthetic fixtures are generated from
pinned contracts; they are not live captures. The retained JavaScript fixture's
rounded int64-minimum seed is replaced with zero only in synthetic test execution
to fit Go int64. Original fixture bytes remain hash-pinned. Feedback wire tests substitute a valid
UUID for the shared fixture placeholder, matching TypeScript's UUID refinement.

No newly added route was exercised against a live tenant in the original parity pass. Subsequent v0.8.1 workspace/IAM verification is recorded in the live-verification record.
Existing live evidence is described separately in [live verification](live-verification.md).
Realtime is tested through an injected socket; actual WebSocket upgrades and
provider readiness depend on the caller's adapter and deployment. A normal socket
close drains queued events; a transport failure becomes sticky and discards
queued events, matching the TypeScript client.

## Refresh and verify

With a clean TypeScript checkout and its locked dependencies installed:

```sh
../prisma-airs-sdk/node_modules/.bin/tsx scripts/export_typescript_parity.mts ../prisma-airs-sdk
../prisma-airs-sdk/node_modules/.bin/tsx scripts/audit_typescript_methods.mts ../prisma-airs-sdk
python3 scripts/schema_models.py parity
python3 scripts/parity_fixtures.py
python3 scripts/check_typescript_parity.py
python3 scripts/schema_models.py modelsecurity redteam gateway agentguard parity --check
GOTOOLCHAIN=go1.24.6 make check
```

CI checks the method map, contract/embedded-copy agreement, retained fixture
hashes, synthetic fixture regeneration, generated models and integration-test
compilation. The audit maps public class methods; documentation and transport
tests cover Go-specific constructors, adapters and helper functions.
