# Release Notes

## v0.6.1

- Fix customer-app updates to carry the deployment authentication code required by the live API. Add optional `UpdateAppRequest.AuthCode`, with paginated unambiguous recovery when omitted and typed missing/ambiguity errors.

## v0.6.0

- **feat(runtime)**: current query/update fields, explicit clears, precise delete-response handling, and live-verified topic force-delete and API key regeneration routes. Existing list aliases remain available.
- **feat(modelsecurity)**: model/version/file inventory, custom-rule lifecycle, rule/group history, and additive complete schema methods with omitted/null/value intent.
- **feat(redteam)**: target adapters, an independent Network Broker client, current report/metadata/lifecycle helpers, and complete opt-in models while retaining existing methods and field types. Deprecated prompt-set `Properties` maps remain source and wire compatible for the existing Terraform provider.
- **feat(gateway)**: SCM OAuth management clients for twelve CRUD/lifecycle families, 88 selected source operations, and explicit service/user API key aliases. Configuration replacement, binding ownership, one-time credentials, and deployment archival are documented. Workspaces must already exist.
- **fix**: endpoint-specific response interpretation rejects malformed or incompatible JSON with typed status/cause errors while preserving allowed text/empty deletes, including misleading JSON headers and JSON-string success messages. This includes the separately committed v0.5.2 hotfix.
- **test**: pinned source hashes, complete public HTTP contracts, generated-schema checks, independent feature scores of at least 9/10 on both axes, targeted disposable live CRUD checks, Go 1.22+ race verification, and existing Terraform consumer validation.
- **release**: checksummed source and Linux/macOS/Windows amd64/arm64 example binaries; see [release artifacts](../developer/releases.md).

The live Red Team scan-metadata route currently returns HTTP 422 despite the
pinned source declaring no parameters. The SDK retains its documented route and
strict live assertion. Some execution, permanent Broker creation, and lifecycle
helpers have mock contract verification only. See [live verification](../developer/live-verification.md)
for exact coverage; this release does not assert that every live integration passes.


## v0.5.2

- **fix**: OAuth operations requiring JSON now return `*AISecSDKError` for malformed JSON, incompatible field types, empty bodies, and JSON `null`, instead of silently returning zero-value or partial results. Decoding errors retain the HTTP status and wrapped JSON cause; unknown fields remain accepted.
- **refactor**: JSON requests and CSV uploads share one response interpretation implementation. Plain-text and empty success are explicitly preserved for profile force deletion, topic deletion/force deletion, and CSV upload; documented no-content Red Team and Model Security deletes remain successful.
- **fix(runtime)**: profile force deletion and topic delete responses decode both JSON strings and `{message: ...}` objects without changing public response types. Text success exceptions work even with misleading JSON Content-Type headers; HTML responses are rejected.
- **test**: topic deletion and profile force deletion failures during integration cleanup now fail the test. Successful delete responses log their Content-Type and a bounded body prefix for future live verification.

## v0.5.1

- **verified**: the changed Red Team report, goal, stream, custom-attack-report, score-trend and dashboard endpoints were exercised against a live tenant with the new read-only `TestIntegration_Reports_ReadEndpoints`; all returned data (the multi-turn detail endpoint answered at the spec path, but no multi-turn attack existed to fetch)
- **fix(redteam)**: `AttackListItem` now models the real list row — the identifier is `UUID` (the old `ID`/`Details` fields were never populated by the API and are kept only as deprecated fields). Pass `UUID` to `GetAttackDetail`
- **test**: unit tests are hermetic — `PANW_*` variables are cleared in each package's `TestMain` (build tag `!integration`), so they pass with live credentials exported; `TestIntegration_Profiles_CRUD` now deletes every revision it creates (it previously leaked revision 2); `TestIntegration_PyPIAuth` no longer logs the access token embedded in the PyPI URL

- **fix**: a persistent 401/403 no longer retries forever. The OAuth token refresh is granted once per request; a second 401/403 is returned as an error. Previously the refresh retry never consumed budget, so a genuine authorization failure produced an unbounded request loop (tens of thousands of requests per second against both the API and the token endpoint) until the context was cancelled
- **fix(redteam)**: data-plane report, custom-attack-report, score-trend, quota and sentiment methods now use the verbs and paths in the OpenAPI spec (verified by `spec_conformance_test.go`, which pins all 75 Red Team operations). Changed: `ListAttacks` → `/v1/report/static/{job}/list-attacks`, `GetAttackDetail` → `…/static/{job}/attack/{id}`, `GetMultiTurnAttackDetail` → `…/static/{job}/attack-multi-turn/{id}`, `GetStaticReport`/`GetDynamicReport` → `…/{job}/report`, `ListGoals` → `…/dynamic/{job}/list-goals`, `ListGoalStreams` → `…/goal/{goal}/list-streams`, `GetStreamDetail` → `…/dynamic/stream/{id}`, all `CustomAttackReports` methods → `/v1/custom-attacks/report/…` and `/v1/custom-attacks/job/…`, `GetScoreTrend` now sends `target_id` as a query parameter, `UpdateSentiment` is a **POST**. `GetQuota` deliberately stays a **GET**: the spec says POST, but a live tenant returns 403 for POST and serves GET (verified 2026-10-01)
- **feat(redteam)**: `Reports.GeneratePartialReport`; `GetScoreTrend` accepts optional `ScoreTrendOpts` (date range); `GoalListOpts` gains `Skip`, `Limit`, `Search`
- **feat**: `AISecSDKError.StatusCode`, sentinel errors (`ErrNotFound`, `ErrUnauthorized`, `ErrForbidden`, `ErrBadRequest`, `ErrConflict`, `ErrRateLimited`) matched by `errors.Is`, and `aisec.IsNotFound`. Error message text is unchanged
- **fix**: `PANW_MGMT_ENDPOINT`, `PANW_MODEL_SEC_{DATA,MGMT}_ENDPOINT` and `PANW_RED_TEAM_{DATA,MGMT}_ENDPOINT` are now honored (they were documented but never read). Resolution is option → environment → default
- **feat**: injectable HTTP client — `HTTPClient` on `runtime.Opts`, `modelsecurity.Opts`, `redteam.Opts` and `aisec.WithHTTPClient` for the scan API. Token requests now use the same client and the caller's context, and cannot hang indefinitely
- **feat**: 429 responses are retried, honoring `Retry-After` (capped at 30 s); backoff sleeps stop when the context is cancelled
- **fix**: `Profiles.GetByID`, `Profiles.GetByName` and `DlpProfiles.Get` page through the whole list instead of looking only at the first 1000 items; their "not found" errors match `ErrNotFound`
- **fix**: caller-supplied identifiers are escaped as single path segments (a `/`, `?` or `#` in an ID can no longer alter the request path)
- **fix**: concurrent callers waiting on a failed token fetch receive the real error instead of a generic one; if the fetching caller's context ended, waiters fetch for themselves
- **fix**: `UploadPromptsCsv`, `DownloadReport`, `DownloadTemplate` return `*AISecSDKError` for local failures and share the single OAuth request pipeline (`internal.DoMgmtRaw`)
- **fix**: `integration_test.go` (build tag `integration`) compiled against a removed field; it builds again
- **chore**: release workflow now fails when the release tag does not match `aisec.Version`; removed an accidentally tracked empty hook log

## v0.5.0

- **feat**: add `EulaClient` sub-client with `GetContent`, `GetStatus`, `Accept` methods
- **feat**: add `InstancesClient` sub-client with 7 methods — `Create`, `Get`, `Update`, `Delete`, `CreateDevice`, `UpdateDevice`, `DeleteDevice`
- **feat**: add `ValidateAuth` method on `TargetsClient` for auth configuration validation
- **feat**: add `GetTargetMetadata`, `GetTargetTemplates`, `GetRegistryCredentials` convenience methods
- **feat**: add `UploadPromptsCsv` and `DownloadTemplate` methods on `CustomAttacksClient`
- **feat**: add typed auth config structs — `HeadersAuthConfig`, `BasicAuthAuthConfig`, `OAuth2AuthConfig` with `AuthConfigType` enum
- **feat**: add `WEBSOCKET` to `TargetConnectionType` and `ResponseMode` enums
- **fix**: `UpdateProfile` path corrected from `/context` to `/profile`
- **fix**: `GetPropertyValuesMultiple` changed from POST with body to GET with query param
- **fix**: `CreatePropertyValue` path removed erroneous `/create` suffix
- **fix**: `DashboardOverviewResponse` typed with `TotalTargets` + `TargetsByType` (was `map[string]any`)
- **fix**: `CustomPromptSetCreateRequest`/`UpdateRequest` `Properties` field renamed to `PropertyNames []string`
- **fix**: `CustomPromptSetVersionInfo` fully typed (was `map[string]any`)
- **fix**: `TargetProbeRequest` metadata fields typed as `*TargetMetadata`, `*TargetBackground`, `*TargetAdditionalContext`
- **fix**: `TargetResponse` now includes `NetworkBrokerChannelUUID`, `AuthConfigType`, `AuthConfig` fields
- **refactor**: split `models.go` into 7 domain files (`models_enums.go`, `models_target.go`, `models_scan.go`, `models_custom_attack.go`, `models_dashboard.go`, `models_eula.go`, `models_instance.go`)
- **chore**: update red team mgmt-plane spec to latest OpenAPI JSON
- **docs**: update red team API docs with all new endpoints and sub-clients

## v0.4.1

- **fix**: remove `omitempty` from 33 plain `bool` JSON struct tags — `false` was silently dropped during marshaling, causing Terraform state drift

## v0.4.0

- **breaking**: consolidate `aisec/management` and `aisec/scan` into unified `aisec/runtime` package — all import paths change
- **feat**: add `DefaultURLCategory`, `UrlDetectedAction`, `MaliciousCodeProtection` fields to `AppProtectionConfig`
- **feat**: add `DatabaseSecurity` field to `DataProtectionConfig` with `DatabaseSecurityConfig` type
- **refactor**: package structure now mirrors functional domains: `runtime`, `modelsecurity`, `redteam`
- **docs**: rename `management-api.md` to `runtime-api.md`, update all documentation

### Migration

```diff
- import "github.com/cdot65/prisma-airs-go/aisec/management"
- import "github.com/cdot65/prisma-airs-go/aisec/scan"
+ import "github.com/cdot65/prisma-airs-go/aisec/runtime"

- client, err := management.NewClient(management.Opts{...})
+ client, err := runtime.NewClient(runtime.Opts{...})

- scanner := scan.NewScanner(cfg)
+ scanner := runtime.NewScanner(cfg)
```

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
- **Runtime enums**: add `ProfileAction` (`allow`, `block`, `alert`, disabled) and `ToxicContentAction` (compound severity-threshold values) typed enums for all security profile action fields
- **Release CI**: add Go module proxy publish step to release workflow
- Remove `omitempty` from spec-required response fields across all packages

## v0.1.0 — Initial Release

- Project scaffolding and Go module setup
- GitHub Actions CI/CD (lint, test matrix, docs deploy, release validation)
- MkDocs Material documentation site
- Core package: constants, configuration, errors, utils
- HTTP client with exponential backoff retry and full jitter
- **Runtime API**: Scanner with SyncScan, AsyncScan, QueryByScanIDs, QueryByReportIDs
- **OAuth2 Client**: token caching, proactive refresh, 401/403 auto-retry, concurrent deduplication
- **Runtime API**: 8 sub-clients (profiles, topics, API keys, customer apps, DLP profiles, deployment profiles, scan logs, OAuth management)
- **Model Security API**: 3 sub-clients (scans, security groups, security rules) + PyPI auth
- **Red Team API**: 5 sub-clients (scans, reports, custom attack reports, targets, custom attacks) + 7 convenience methods
- Full feature parity with TypeScript SDK v0.6.7
