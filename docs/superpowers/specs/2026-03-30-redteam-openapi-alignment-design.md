# Red Team SDK — OpenAPI Spec Alignment Design

**Date:** 2026-03-30
**Issue:** cdot65/prisma-airs-go#90
**Spec source:** `mp_ws_openapi.json` (mgmt-plane OpenAPI 3.1.0)

## Summary

Align the Go SDK's `aisec/redteam` package with the updated mgmt-plane OpenAPI spec. 16 PRs covering bug fixes, schema alignment, new endpoints, and cleanup.

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Scope | All three tiers (bugs, schema, new endpoints) | Full spec parity |
| File organization | Split `models.go` by domain, keep single `client.go` | Navigate models without changing client surface |
| Auth config typing | Typed structs; connection params stay `map[string]any` | Auth config is new surface — get it right. Connection params refactor is breaking with marginal benefit |
| Redact variants | Single `TargetResponse` type with doc comments | Server-side display concern, not structural |
| CSV upload | Inline multipart handling in client method | `DownloadReport` precedent; YAGNI on reusable helper |
| Sequencing | Vertical slices (one PR per sub-task) | Each PR reviewable/shippable independently |

## Phase 1: Bug Fixes

### PR 1 — Fix UpdateProfile path

- **File:** `client.go:559`
- **Change:** `"/context"` → `"/profile"`
- **Test:** assert request hits `/v1/target/{id}/profile`

### PR 2 — Fix GetPropertyValuesMultiple: POST → GET

- **File:** `client.go:741-745`
- **Change:** `http.MethodPost` → `http.MethodGet`, remove JSON body, pass `property_names` as comma-joined query param
- **Signature unchanged:** `GetPropertyValuesMultiple(ctx, []string) (*PropertyValuesMultipleResponse, error)`
- **Test:** assert GET method + query param format

### PR 3 — Fix CreatePropertyValue path

- **File:** `client.go:754`
- **Change:** `"/property-values/create"` → `"/property-values"`
- **Test:** assert correct path

### PR 4 — Type DashboardOverviewResponse

- **File:** `models.go:957-960`
- **Change:** replace `Overview map[string]any` with:
  ```go
  type DashboardOverviewResponse struct {
      TotalTargets  int           `json:"total_targets"`
      TargetsByType []CountByName `json:"targets_by_type,omitempty"`
  }
  ```
- **Breaking:** callers accessing `.Overview` must migrate
- `CountByName` already exists in models.go

### PR 5 — Fix CustomPromptSetCreateRequest/UpdateRequest fields

- **File:** `models.go:703-714`
- **Change:** on both `CustomPromptSetCreateRequest` and `CustomPromptSetUpdateRequest`:
  - `Properties map[string]any` → `PropertyNames []string`
  - JSON tag: `"properties"` → `"property_names"`
- **Breaking:** callers passing `.Properties` must migrate

## Phase 2: Schema/Model Alignment

### PR 6 — Add WebSocket enum values

- Add `TargetConnectionTypeWebSocket = "WEBSOCKET"` to `TargetConnectionType` enum
- Add `ResponseModeWebSocket = "WEBSOCKET"` to `ResponseMode` enum
- No new structs (connection params stay `map[string]any`)

### PR 7 — Add typed auth config

New enums:
```go
type AuthConfigType string // HEADERS, BASIC_AUTH, OAUTH2
type BasicAuthLocation string // HEADER, PAYLOAD
```

Note: named `AuthConfigType` to avoid collision with the existing `AuthType` enum (which holds `OAUTH`/`ACCESS_TOKEN` for Databricks).

New structs:
```go
type HeadersAuthConfig struct {
    AuthHeader map[string]string `json:"auth_header"`
}

type BasicAuthAuthConfig struct {
    BasicAuthLocation BasicAuthLocation `json:"basic_auth_location,omitempty"`
    BasicAuthHeader   map[string]string `json:"basic_auth_header,omitempty"`
}

type OAuth2AuthConfig struct {
    OAuth2TokenURL         string            `json:"oauth2_token_url"`
    OAuth2ExpiryMinutes    int               `json:"oauth2_expiry_minutes,omitempty"`
    OAuth2Headers          map[string]string `json:"oauth2_headers,omitempty"`
    OAuth2BodyParams       map[string]string `json:"oauth2_body_params,omitempty"`
    OAuth2TokenResponseKey string            `json:"oauth2_token_response_key,omitempty"`
    OAuth2InjectHeader     map[string]string `json:"oauth2_inject_header"`
}
```

Add to `TargetCreateRequest`, `TargetUpdateRequest`, and `TargetResponse`:
```go
AuthConfigType AuthConfigType `json:"auth_type,omitempty"`
AuthConfig     any            `json:"auth_config,omitempty"`
```

`AuthConfig` is `any` because Go lacks discriminated unions — callers pass one of the three typed structs. JSON marshals correctly.

Tests: round-trip marshal/unmarshal for each auth config variant.

### PR 8 — Fill missing fields on TargetResponse

Audit against spec's `TargetSchema` superset. Add missing fields:
- `NetworkBrokerChannelUUID string` (`json:"network_broker_channel_uuid,omitempty"`)
- `AuthConfigType` + `AuthConfig` (from PR 7)
- Verify `AdditionalCtx` JSON tag is `"additional_context"` (match spec)
- Add doc comment: `// Note: GET /v1/target/{id} returns redacted secrets (auth keys, connection passwords masked by the server).`

## Phase 3: New Endpoints

### PR 9 — Target Auth Validation

New structs:
```go
type TargetAuthValidationRequest struct {
    AuthType                 AuthConfigType `json:"auth_type"`
    AuthConfig               any            `json:"auth_config"`
    TargetID                 string         `json:"target_id,omitempty"`
    NetworkBrokerChannelUUID string         `json:"network_broker_channel_uuid,omitempty"`
}

type TargetAuthValidationResponse struct {
    Validated    bool   `json:"validated"`
    TokenPreview string `json:"token_preview,omitempty"`
    ExpiresIn    *int   `json:"expires_in,omitempty"`
}
```

New method on `TargetsClient`:
- `ValidateAuth(ctx, TargetAuthValidationRequest) (*TargetAuthValidationResponse, error)` — `POST /v1/target/validate-auth`

New constant: `RedTeamTargetValidateAuthPath = "/v1/target/validate-auth"`

### PR 10 — Templates

Opaque return types (spec schemas are `object` with `additionalProperties`):
```go
type TargetTemplateCollection map[string]any
```

Two new methods on top-level `Client` (mgmt plane):
- `GetTargetMetadata(ctx) (map[string]any, error)` — `GET /v1/template/target-metadata`
- `GetTargetTemplates(ctx) (*TargetTemplateCollection, error)` — `GET /v1/template/target-templates`

New constant: `RedTeamTemplatePath = "/v1/template"`

### PR 11 — EULA

New sub-client `EulaClient` wired as `Client.Eula`:
```go
type EulaContentResponse struct {
    Content string `json:"content"`
}

type EulaResponse struct {
    UUID             string `json:"uuid,omitempty"`
    IsAccepted       bool   `json:"is_accepted"`
    AcceptedAt       string `json:"accepted_at,omitempty"`
    AcceptedByUserID string `json:"accepted_by_user_id,omitempty"`
}

type EulaAcceptRequest struct {
    EulaContent string `json:"eula_content"`
    AcceptedAt  string `json:"accepted_at,omitempty"`
}
```

Methods:
- `GetContent(ctx) (*EulaContentResponse, error)` — `GET /v1/eula/content`
- `GetStatus(ctx) (*EulaResponse, error)` — `GET /v1/eula/status`
- `Accept(ctx, EulaAcceptRequest) (*EulaResponse, error)` — `POST /v1/eula/accept`

New constant: `RedTeamEulaPath = "/v1/eula"`

### PR 12 — Instances/Licensing

New sub-client `InstancesClient` wired as `Client.Instances`. 7 methods:
- `Create(ctx, InstanceRequest) (*InstanceResponse, error)` — `POST /v1/instances`
- `Get(ctx, tenantID) (*InstanceGetResponse, error)` — `GET /v1/instances/{tenant_id}`
- `Update(ctx, tenantID, InstanceRequest) (*InstanceResponse, error)` — `PUT /v1/instances/{tenant_id}`
- `Delete(ctx, tenantID) (*InstanceResponse, error)` — `DELETE /v1/instances/{tenant_id}`
- `CreateDevice(ctx, tenantID, DeviceRequest) (*DeviceResponse, error)` — `POST /v1/instances/{tenant_id}/devices`
- `UpdateDevice(ctx, tenantID, DeviceRequest) (*DeviceResponse, error)` — `PATCH /v1/instances/{tenant_id}/devices`
- `DeleteDevice(ctx, tenantID, serialNumbers string) (*DeviceResponse, error)` — `DELETE /v1/instances/{tenant_id}/devices?serial_numbers=...`

New model structs (~12):
```go
type InstanceRequest struct {
    TsgID              string                    `json:"tsg_id"`
    TenantID           string                    `json:"tenant_id"`
    AppID              string                    `json:"app_id"`
    Region             string                    `json:"region"`
    SupportAccountID   string                    `json:"support_account_id,omitempty"`
    SupportAccountName string                    `json:"support_account_name,omitempty"`
    CreatedBy          string                    `json:"created_by,omitempty"`
    Internal           *bool                     `json:"internal,omitempty"`
    TenantInstanceName string                    `json:"tenant_instance_name,omitempty"`
    Extra              *InstanceExtraDetails     `json:"extra,omitempty"`
    IAMControlled      *bool                     `json:"iam_controlled,omitempty"`
    PlatformRegion     string                    `json:"platform_region,omitempty"`
    CspTenantID        string                    `json:"csp_tenant_id,omitempty"`
    TsgInstances       []map[string]any          `json:"tsg_instances,omitempty"`
}

type InstanceResponse struct {
    TsgID    string `json:"tsg_id"`
    TenantID string `json:"tenant_id,omitempty"`
    AppID    string `json:"app_id,omitempty"`
    IsSuccess *bool `json:"is_success,omitempty"`
}

type InstanceGetResponse struct {
    TsgID              string                `json:"tsg_id"`
    TenantID           string                `json:"tenant_id"`
    AppID              string                `json:"app_id"`
    Region             string                `json:"region"`
    SupportAccountID   string                `json:"support_account_id,omitempty"`
    SupportAccountName string                `json:"support_account_name,omitempty"`
    CreatedBy          string                `json:"created_by,omitempty"`
    Internal           *bool                 `json:"internal,omitempty"`
    TenantInstanceName string                `json:"tenant_instance_name,omitempty"`
    DeploymentProfiles []InstanceDPMetadata  `json:"deployment_profiles,omitempty"`
}

type InstanceExtraDetails struct {
    DeploymentProfiles []DeploymentProfileRequest `json:"deployment_profiles,omitempty"`
    AirsSharedByTsg    map[string]any             `json:"airs_shared_by_tsg,omitempty"`
    AirsUnsharedDps    []string                   `json:"airs_unshared_dps,omitempty"`
}

type InstanceDPMetadata struct {
    AuthCode     string `json:"auth_code"`
    DpID         string `json:"dp_id,omitempty"`
    DpName       string `json:"dp_name,omitempty"`
    CreatedBy    string `json:"created_by,omitempty"`
    UpdatedBy    string `json:"updated_by,omitempty"`
    LicExpTs     string `json:"lic_exp_ts,omitempty"`
    DeviceSerial string `json:"device_serial,omitempty"`
    Status       string `json:"status,omitempty"`
    DeviceStatus string `json:"device_status,omitempty"`
    ActivatedTs  string `json:"activated_ts,omitempty"`
}

type DeploymentProfileRequest struct {
    DAuthCode            string                        `json:"dAuthCode,omitempty"`
    DeploymentProfileID  string                        `json:"deploymentProfileId,omitempty"`
    LicenseExpiration    string                        `json:"license_expiration,omitempty"`
    ProfileName          string                        `json:"profileName,omitempty"`
    SubType              string                        `json:"subType,omitempty"`
    Subscriptions        []any                         `json:"subscriptions,omitempty"`
    Type                 string                        `json:"type,omitempty"`
    AveTextRecord        *int                          `json:"aveTextRecord,omitempty"`
    Attributes           []DeploymentProfileAttribute  `json:"attributes,omitempty"`
}

type DeploymentProfileAttribute struct {
    Quantity      string `json:"quantity,omitempty"`
    UnitOfMeasure string `json:"unit_of_measure,omitempty"`
}

type DeviceRequest struct {
    Instance  DeviceInstance `json:"instance"`
    CreatedBy string         `json:"created_by,omitempty"`
    Devices   []Device       `json:"devices,omitempty"`
}

type DeviceInstance struct {
    AppID    string `json:"app_id"`
    Region   string `json:"region"`
    TenantID string `json:"tenant_id"`
    TsgID    string `json:"tsg_id"`
}

type Device struct {
    SerialNumber     string          `json:"serial_number"`
    Model            string          `json:"model,omitempty"`
    SKU              string          `json:"sku,omitempty"`
    DeviceType       string          `json:"device_type,omitempty"`
    DeviceName       string          `json:"device_name,omitempty"`
    TsgID            string          `json:"tsg_id,omitempty"`
    SupportAccountID string          `json:"support_account_id,omitempty"`
    AssetType        string          `json:"asset_type,omitempty"`
    Licenses         []DeviceLicense `json:"licenses,omitempty"`
}

type DeviceLicense struct {
    AuthorizationCode          string `json:"authorizationCode,omitempty"`
    ExpirationDate             string `json:"expirationDate,omitempty"`
    LicensePanDbIdentification string `json:"licensePanDbIdentification,omitempty"`
    PartNumber                 string `json:"partNumber,omitempty"`
    SerialNumber               string `json:"serialNumber,omitempty"`
    SubtypeName                string `json:"subtypeName,omitempty"`
    RegistrationDate           string `json:"registrationDate,omitempty"`
}

type DeviceResponse struct {
    Devices []DeviceStatus `json:"devices,omitempty"`
    Status  string         `json:"status,omitempty"`
}

type DeviceStatus struct {
    Status       string `json:"status"`
    Error        string `json:"error,omitempty"`
    SerialNumber string `json:"serial_number,omitempty"`
}
```

New constant: `RedTeamInstancesPath = "/v1/instances"`

### PR 13 — Registry Credentials

```go
type RegistryCredentials struct {
    Token  string `json:"token"`
    Expiry string `json:"expiry"`
}
```

New method on top-level `Client`:
- `GetRegistryCredentials(ctx) (*RegistryCredentials, error)` — `POST /v1/registry-credentials`

New constant: `RedTeamRegistryCredentialsPath = "/v1/registry-credentials"`

### PR 14 — CSV Upload/Download

Two new methods on `CustomAttacksClient`:

**UploadPromptsCsv:**
- Signature: `UploadPromptsCsv(ctx context.Context, promptSetUUID string, file io.Reader, filename string) (*BaseResponse, error)`
- `POST /v1/custom-attack/upload-custom-prompts-csv?prompt_set_uuid=...`
- Build `multipart/form-data` body inline (manual `mime/multipart` writer, like `DownloadReport` does manual HTTP)
- Set `Content-Type: multipart/form-data; boundary=...`

**DownloadTemplate:**
- Signature: `DownloadTemplate(ctx context.Context, promptSetUUID string) ([]byte, error)`
- `GET /v1/custom-attack/download-template/{id}`
- Raw byte response, manual HTTP (same pattern as `DownloadReport`)

New constants:
- `RedTeamUploadPromptsCsvPath = "/v1/custom-attack/upload-custom-prompts-csv"`
- `RedTeamDownloadTemplatePath = "/v1/custom-attack/download-template"`

## Phase 4: Cleanup

### PR 15 — Split models.go into domain files

Pure refactor. Move structs into:
- `models_enums.go` — all enum types and const blocks
- `models_target.go` — target request/response/metadata/auth config/background/context structs
- `models_scan.go` — job/scan/report/attack/goal/stream/remediation/policy structs
- `models_custom_attack.go` — prompt set/prompt/property structs
- `models_dashboard.go` — dashboard/statistics/quota/error-log/sentiment structs
- `models_eula.go` — EULA structs
- `models_instance.go` — instance/device/licensing structs

Delete original `models.go`. All types stay in package `redteam`. No behavioral changes.

### PR 16 — Update specs/redteam-mgmt.yaml

Replace `specs/redteam-mgmt.yaml` with the updated spec from `mp_ws_openapi.json`. Keep as JSON or convert to YAML — match existing convention (current file is YAML).

## PR Dependency Order

```
PR 1-5 (bug fixes) — independent, can merge in any order
    ↓
PR 6 (WebSocket enums) — independent
PR 7 (auth config types) — independent
PR 8 (TargetResponse fields) — depends on PR 7
    ↓
PR 9 (auth validation) — depends on PR 7
PR 10 (templates) — independent
PR 11 (EULA) — independent
PR 12 (instances) — independent
PR 13 (registry creds) — independent
PR 14 (CSV) — independent
    ↓
PR 15 (split models) — depends on all above
PR 16 (update spec) — depends on all above
```

## Resolved Questions

- **TargetProbeRequest typed fields:** Yes — align `TargetMetadata`, `TargetBackground`, `AdditionalContext` to use typed structs instead of `map[string]any`. Include in PR 8 (fill missing fields).
- **GetPromptSetVersionInfo version param:** Yes — add optional `version` query param. Include as a minor addition in one of the Phase 1-2 PRs or as part of PR 15 cleanup.
- **BaseResponse.Status field:** Yes — add `Status int` field to `BaseResponse`. Include in PR 4 (typing DashboardOverviewResponse) since it touches the same area of models.go.
