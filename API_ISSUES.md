# API Issues Discovered During E2E Testing

Issues found while running integration tests against the live AIRS API (2026-03-21).
These are API-side behaviors, not SDK bugs.

## Management API

### 1. Single-resource GET endpoints timeout (30s+)
- `GET /v1/mgmt/profile?profile_name=<name>` — times out at 30s
- `GET /v1/mgmt/dlpprofiles/<id>` — times out at 30s
- `GET /v1/mgmt/oauth/client_credential/accesstoken` — times out at 30s
- List endpoints for the same resources work fine within 2-5s
- **Impact:** Cannot use GetByName, DlpProfiles.Get, or OAuth.GetToken reliably

### 2. Topic Update (`PUT /v1/mgmt/topic/<id>`) times out
- Even with 2-minute timeout, the update never returns
- Topic was successfully created and listed
- **Impact:** Topics cannot be updated via API

### 3. Topic Delete returns unparseable JSON
- `DELETE /v1/mgmt/topic/<id>` returns a response body that fails JSON parsing
- SDK error: `failed to parse response JSON`
- The delete may succeed server-side despite the parse error
- **Impact:** Cleanup of test topics may leave orphaned resources

### 4. ScanLogs endpoint unresponsive
- `POST /v1/mgmt/scanlogs` consistently times out (>2min)
- Previously documented, still unresolved
- **Impact:** ScanLogs.List unusable

## Red Team API

### 5. Target Update requires undocumented fields
- `PUT /v1/targets/<uuid>` requires `api_endpoint_type` and `response_mode` in the request body
- Error: `"No configuration found for APPLICATION + CUSTOM + None + None"`
- These fields exist in `TargetCreateRequest` but not in `TargetUpdateRequest`
- **Impact:** SDK `TargetUpdateRequest` struct needs `APIEndpointType` and `ResponseMode` fields

### 6. Target List filters out DRAFT targets
- Newly created targets with DRAFT/unvalidated status don't appear in `GET /v1/targets` list
- Must use direct `GET /v1/targets/<uuid>` to retrieve them
- **Impact:** Users may not see newly created targets in list results

### 7. Target Create has undocumented validation rules
- `request_json` must contain `{INPUT}` placeholder
- `response_json` must contain `{RESPONSE}` placeholder
- `response_key` must be set
- None of these are documented in the OpenAPI spec
- **Impact:** Users get opaque validation errors without guidance

## Model Security API

No issues found — all CRUD operations work correctly.

## Scan API

No issues found — sync scan, async scan, query by scan/report IDs all work correctly.
