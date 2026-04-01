# Release Notes

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
