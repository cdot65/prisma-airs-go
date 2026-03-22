# Release Notes

## v0.3.1

- **fix**: customer apps `List` endpoint changed from `/v1/mgmt/customerapp/tsg/{id}` to `/v1/mgmt/customerapps` per OpenAPI spec — resolves timeout
- **fix**: add missing `AgentApp`, `AiSecProfileName`, `ApiKeysDPInfo` fields to `CustomerApp` struct
- **breaking**: remove `Create` method from `CustomerAppsClient` (not in OpenAPI spec)
- **breaking**: remove redundant `CustomerAppWithKeyInfo` type (fields merged into `CustomerApp`)
- **docs**: add `CustomerApp`, `APIKeyDPInfo` type definitions to API reference
- **docs**: fix README service domain count

## v0.3.0

- **docs**: comprehensive runtime scanning examples — SyncScan, AsyncScan, QueryByScanIDs, QueryByReportIDs, tool event scanning, code scanning
- **docs**: full custom topics CRUD examples with profile topic-guardrails integration
- **docs**: end-to-end red team scanning workflow — target create, launch scan, reports, attacks, remediation, custom attacks
- **docs**: replace stub `examples/basic-scan/main.go` with working 5-step example
- **docs**: add Examples section to README with links to all example pages
- **docs**: fix stale User-Agent version string in scan-api.md
- **chore**: bump SDK version to 0.3.0

## v0.2.1

- **fix**: `ForceDelete` no longer errors when the API returns non-JSON on success — `DoMgmtRequest` tolerates non-JSON 2xx responses
- **docs**: add `docs/examples/profile-crud.md` with full end-to-end CRUD walkthrough and real API responses
- **docs**: add 7 missing Red Team methods to `docs/services/red-team-api.md`
- **docs**: document ForceDelete non-JSON response behavior

## v0.2.0

- **feat**: `Profiles.GetByID` — client-side filter over List (no dedicated API endpoint)
- **feat**: `Profiles.GetByName` — returns highest revision when multiple revisions share the same name
- **feat**: `ProfileAction` and `ToxicContentAction` typed enums for security profile actions
- **docs**: full documentation alignment with current codebase

## v0.1.1

- **Red Team targets**: align all target models with OpenAPI spec (`TargetCreateRequest`, `TargetUpdateRequest`, `TargetContextUpdate`, `TargetProfileResponse`, `TargetListItem`)
- **Management enums**: add `ProfileAction` (`allow`, `block`, `alert`, disabled) and `ToxicContentAction` (compound severity-threshold values) typed enums for all security profile action fields
- **Release CI**: add Go module proxy publish step to release workflow
- Remove `omitempty` from spec-required response fields across all packages

## v0.1.0 — Initial Release

- Project scaffolding and Go module setup
- GitHub Actions CI/CD (lint, test matrix, docs deploy, release validation)
- MkDocs Material documentation site
- Core package: constants, configuration, errors, utils
- HTTP client with exponential backoff retry and full jitter
- **Scan API**: Scanner with SyncScan, AsyncScan, QueryByScanIDs, QueryByReportIDs
- **OAuth2 Client**: token caching, proactive refresh, 401/403 auto-retry, concurrent deduplication
- **Management API**: 8 sub-clients (profiles, topics, API keys, customer apps, DLP profiles, deployment profiles, scan logs, OAuth management)
- **Model Security API**: 3 sub-clients (scans, security groups, security rules) + PyPI auth
- **Red Team API**: 5 sub-clients (scans, reports, custom attack reports, targets, custom attacks) + 7 convenience methods
- Full feature parity with TypeScript SDK v0.6.7
