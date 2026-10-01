# API Issues Discovered During E2E Testing

## Live recheck — 2026-10-01

The October alignment rechecked temporary topic/profile CRUD and API-key
creation, regeneration, and deletion. Topics/profile/API-key deletes return JSON
strings under application/json. Ordinary profile/API-key deletion now uses the
same string-or-object adapter while still requiring JSON; force/profile/topic
text exceptions remain explicit. The topic force route is
`/v1/mgmt/topic/{id}/force`; `/topic/force/{id}` returned 403. Key regeneration
uses `/v1/mgmt/apikey/regenerate/{id}` and returns a replacement key ID. Existing
TSG-qualified and new unqualified profile/topic/key listing routes both returned
200. See `docs/developer/live-verification.md` for evidence; the historical entries
below retain their original dates and have not all been rechecked.

Issues found while running integration tests against the live AIRS API (2026-03-21).
These are API-side behaviors, not SDK bugs.

> **Status note (2026-10-01):** this file records the 2026-03-21 run and has not been re-verified since. Some items predate SDK fixes (for example `OAuth.GetToken` is now a POST per the spec, and `CustomerApps.List` moved to `/v1/mgmt/customerapps`). Re-test before relying on a specific timeout claim.

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
- **SDK compatibility update (v0.5.2, 2026-10-01):** topic deletion accepts JSON strings, message objects, empty bodies, and plain text, including text mislabeled as JSON. Malformed structured bodies still fail. These cases are covered by mock tests; the original live body and Content-Type were not recorded, so their format remains unknown. Integration delete responses now log a bounded body prefix and Content-Type for the next authorized live run.

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

## October 2026: Red Team scan metadata route returns validation error

Pinned data-plane specification documents `GET /v1/scan/scan-metadata` with no
parameters and a free-form JSON object response. On 2026-10-01 the selected
production tenant returned HTTP 422 (`code: validation_error`,
`message: Request validation failed`) with no parameter details. The alternative
`/v1/scan-metadata` and trailing-slash route returned 403, and
`/v1/scan/metadata` returned 422. A generic job route shadowing the static route
is a possibility, not a confirmed cause. Keep the documented path, expose the
typed error, and retain a strict live assertion until the service is corrected.
No successful live metadata response has been recorded.
