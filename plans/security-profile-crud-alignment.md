# Security Profile CRUD — Gap Analysis & Implementation Plan

## Current State

### SDK Methods (ProfilesClient)

| Operation | Method | API Endpoint | Status |
|-----------|--------|-------------|--------|
| Create | `Create(ctx, req)` | `POST /v1/mgmt/profile` | Implemented |
| List | `List(ctx, opts)` | `GET /v1/mgmt/profiles/tsg/{tsg_id}` | Implemented |
| Get by ID | — | — | **MISSING** |
| Get by Name | `GetByName(ctx, name)` | client-side filter over List | Workaround |
| Update | `Update(ctx, id, req)` | `PUT /v1/mgmt/profile/uuid/{profile_id}` | Implemented |
| Delete | `Delete(ctx, id)` | `DELETE /v1/mgmt/profile/{profile_id}` | Implemented |
| Force Delete | `ForceDelete(ctx, id, updatedBy)` | `DELETE /v1/mgmt/profile/{profile_id}/force` | Implemented |

### Gap: No Get-by-ID

**Root cause: The OpenAPI spec (`specs/runtime-mgmt.yaml`) does not define a dedicated GET endpoint for a single profile by ID.**

The spec defines these profile endpoints:
- `POST /v1/mgmt/profile` — Create
- `GET /v1/mgmt/profiles` — List all (paginated, with `offset`, `limit`, `latest` params)
- `PUT /v1/mgmt/profile/uuid/{profile_id}` — Update by UUID
- `DELETE /v1/mgmt/profile/{profile_id}` — Delete by ID
- `DELETE /v1/mgmt/profile/{profile_id}/force` — Force delete

There is no `GET /v1/mgmt/profile/{profile_id}` or `GET /v1/mgmt/profile/uuid/{profile_id}`.

The current `GetByName` method works around this by calling `List(limit=1000)` and filtering client-side. This is the same pattern used in the TypeScript SDK.

### Additional Gaps Found

Beyond the missing Get-by-ID, the audit revealed several model and API gaps that should be addressed together.

---

## Issue 1: Add `GetByID` Method (Client-Side Filter)

**Problem:** No way to retrieve a single profile by UUID without listing all profiles.

**Why no server-side endpoint:** The API simply doesn't expose one. The `PUT` path uses `/uuid/{profile_id}` but there's no corresponding `GET`. This is an API-level limitation, not an SDK gap.

**Implementation:**

```go
func (c *ProfilesClient) GetByID(ctx context.Context, profileID string) (*SecurityProfile, error) {
    resp, err := c.List(ctx, ListOpts{Limit: 1000})
    if err != nil {
        return nil, err
    }
    for _, p := range resp.Items {
        if p.ProfileID == profileID {
            return &p, nil
        }
    }
    return nil, aisec.NewAISecSDKError("profile not found: "+profileID, aisec.ClientSideError)
}
```

**Trade-offs:**
- Same approach as `GetByName` — fetches all profiles and filters
- For tenants with many profiles, this is inefficient (O(n) API call)
- No server-side alternative available
- Could add a `latest` query param optimization to reduce payload

**Tests:**
- Unit test: mock server returns list, verify correct profile extracted
- Unit test: profile not found returns appropriate error
- Integration test: create profile, get by ID, verify fields match

---

## Issue 2: `List` Endpoint Path Mismatch

**Problem:** SDK uses `GET /v1/mgmt/profiles/tsg/{tsg_id}` but spec defines `GET /v1/mgmt/profiles`.

**Analysis:** The spec endpoint at line 318 is `GET /v1/mgmt/profiles` with query params `offset`, `limit`, `latest`. No TSG path segment. The TSG is derived from the auth token, not the URL path.

**Current code (`client.go:97`):**
```go
Path: aisec.MgmtProfilesTsgPath + "/" + c.tsgID  // → /v1/mgmt/profiles/tsg/{tsg_id}
```

**Spec says:**
```
GET /v1/mgmt/profiles?offset=0&limit=10&latest=true
```

**Action:** Verify which endpoint the API actually accepts (the TSG path may be an undocumented variant). If the spec endpoint works:
- Change `List` to use `/v1/mgmt/profiles` with query params
- Remove or deprecate `MgmtProfilesTsgPath` constant
- Add `Latest` field to `ListOpts` or create `ProfileListOpts` with `Latest bool`

**Risk:** Medium — the TSG-in-path variant may be the only one that works in practice. Needs live API testing to confirm.

---

## Issue 3: `List` Missing `latest` Query Parameter

**Problem:** The spec defines a `latest` boolean query param on `GET /v1/mgmt/profiles` that returns only the latest revision of each profile. The SDK's `ListOpts` only has `Limit` and `Offset`.

**Implementation:**

Option A — add `Latest` to existing `ListOpts` (affects all sub-clients):
```go
type ListOpts struct {
    Limit  int
    Offset int
    Latest bool
}
```

Option B — create a profile-specific opts type:
```go
type ProfileListOpts struct {
    Limit  int
    Offset int
    Latest bool
}
```

**Recommendation:** Option B. The `latest` param is profile-specific (no other entity has revisions). Creating a dedicated type prevents leaking profile semantics into the generic opts.

**Tests:**
- Unit test: verify `latest=true` appears in query params
- Integration test: compare results with and without `latest`

---

## Issue 4: `SecurityProfile` Missing `omitempty` on Required Fields

**Problem:** The spec marks `profile_name`, `revision`, and `policy` as required on `AIProfileObject`. The SDK has `omitempty` on all fields.

**Current:**
```go
type SecurityProfile struct {
    ProfileID      string         `json:"profile_id,omitempty"`
    ProfileName    string         `json:"profile_name,omitempty"`     // spec: required
    Revision       int32          `json:"revision,omitempty"`         // spec: required
    Active         bool           `json:"active,omitempty"`
    Policy         *ProfilePolicy `json:"policy,omitempty"`           // spec: required
    CreatedBy      string         `json:"created_by,omitempty"`
    UpdatedBy      string         `json:"updated_by,omitempty"`
    LastModifiedTs string         `json:"last_modified_ts,omitempty"`
}
```

**Fix:** Remove `omitempty` from `ProfileName`, `Revision`, and `Policy` to match spec required semantics, consistent with the pattern applied to `TargetResponse` in the redteam package.

---

## Issue 5: `DLPDataProfileConfig.Rule1/Rule2` Should Be Typed

**Problem:** `Rule1` and `Rule2` are `map[string]any` but the spec defines them as objects with a single `action` string field.

**Spec:**
```yaml
rule1:
  type: object
  properties:
    action:
      type: string
rule2:
  type: object
  properties:
    action:
      type: string
```

**Fix:**
```go
type DLPRuleConfig struct {
    Action string `json:"action,omitempty"`
}

type DLPDataProfileConfig struct {
    Name         string         `json:"name"`            // spec: required
    UUID         string         `json:"uuid"`            // spec: required
    ID           string         `json:"id,omitempty"`
    Version      string         `json:"version,omitempty"`
    Rule1        *DLPRuleConfig `json:"rule1,omitempty"`
    Rule2        *DLPRuleConfig `json:"rule2,omitempty"`
    LogSeverity  string         `json:"log-severity,omitempty"`
    NonFileBased string         `json:"non-file-based,omitempty"`
    FileBased    string         `json:"file-based,omitempty"`
}
```

Also removes `omitempty` from `Name` and `UUID` (spec required).

---

## Issue 6: `CreateProfileRequest` and `UpdateProfileRequest` Are Under-Specified

**Problem:** Both request types are thin wrappers but don't reflect the full spec request body. The API expects a full `AIProfileObject` for both create and update.

**Current:**
```go
type CreateProfileRequest struct {
    ProfileName string         `json:"profile_name"`
    Policy      *ProfilePolicy `json:"policy,omitempty"`
}

type UpdateProfileRequest struct {
    ProfileName string         `json:"profile_name,omitempty"`
    Policy      *ProfilePolicy `json:"policy,omitempty"`
}
```

**Spec (both create and update accept `AIProfileObject`):**
```yaml
requestBody:
  schema:
    $ref: "#/components/schemas/AIProfileObject"
```

The `AIProfileObject` includes `profile_id`, `profile_name`, `revision`, `active`, `policy`, `created_by`, `updated_by`, `last_modified_ts`. For create, most are server-set. For update (PUT, full replacement), all mutable fields should be settable.

**Fix — `UpdateProfileRequest` should include all mutable fields:**
```go
type UpdateProfileRequest struct {
    ProfileName string         `json:"profile_name"`
    Policy      *ProfilePolicy `json:"policy"`
    Active      *bool          `json:"active,omitempty"`
}
```

`CreateProfileRequest` is likely fine as-is (server ignores extra fields on create), but `Policy` should not be `omitempty` since the spec marks it required.

---

## Issue 7: `DeleteProfileResponse` Doesn't Handle 409 Conflict

**Problem:** The spec defines a 409 response for `DELETE /v1/mgmt/profile/{profile_id}` with a `DeleteAIProfileResponse` schema that differs from the 200 response. The SDK doesn't distinguish these.

**Spec (409):**
```yaml
"409":
  description: conflict occurred
  content:
    application/json:
      schema:
        $ref: "#/components/schemas/DeleteAIProfileResponse"
```

**Check what `DeleteAIProfileResponse` looks like:**

This is at line 1559 in the spec. Need to verify the schema.

**Action:** Read the `DeleteAIProfileResponse` schema and determine if it carries useful information (e.g., conflicting deployments that prevent deletion). If so, the SDK should surface this in the error type so callers can act on it (e.g., use ForceDelete instead).

---

## Implementation Order

Dependencies flow top-to-bottom:

```
1. Issue 4: SecurityProfile omitempty fix          (model change, no API change)
2. Issue 5: DLPDataProfileConfig Rule1/Rule2 types (model change, no API change)
3. Issue 6: Update request types                   (model change, no API change)
4. Issue 2: List endpoint path verification        (requires live API testing)
5. Issue 3: ProfileListOpts with Latest            (depends on Issue 2 resolution)
6. Issue 1: GetByID method                         (new method, can use Latest optimization)
7. Issue 7: 409 conflict handling                  (error handling enhancement)
```

### Suggested GitHub Issues

| # | Title | Type | Depends On |
|---|-------|------|-----------|
| 1 | `fix(management): remove omitempty from SecurityProfile required fields` | fix | — |
| 2 | `fix(management): type DLPDataProfileConfig Rule1/Rule2 as DLPRuleConfig` | fix | — |
| 3 | `fix(management): expand UpdateProfileRequest to include all mutable fields` | fix | — |
| 4 | `fix(management): verify List endpoint path against live API` | fix | — |
| 5 | `feat(management): add ProfileListOpts with Latest bool` | feat | #4 |
| 6 | `feat(management): add GetByID for security profiles` | feat | #5 |
| 7 | `feat(management): surface 409 conflict details on profile delete` | feat | — |

---

## Testing Strategy

### Unit Tests (per issue)

1. **omitempty fix:** JSON marshal `SecurityProfile` with zero-value `Revision` and nil `Policy` — verify fields still appear in output
2. **DLPRuleConfig:** JSON round-trip with `Rule1: {Action: "alert"}`, verify no data loss vs `map[string]any`
3. **UpdateProfileRequest:** marshal with all fields, verify complete JSON body
4. **List path:** mock server expects `/v1/mgmt/profiles` vs `/v1/mgmt/profiles/tsg/X` — determine which works
5. **ProfileListOpts:** verify `latest=true` query param appears when set
6. **GetByID:** mock list response with 3 profiles, verify correct one returned; verify not-found error
7. **409 handling:** mock server returns 409 with conflict body, verify error surfaces details

### Integration Tests

- Full CRUD cycle: Create → GetByID → Update → GetByName (verify update) → Delete
- `List(ProfileListOpts{Latest: true})` returns fewer results than `List(ProfileListOpts{Latest: false})`
- ForceDelete after 409 on regular Delete

---

## Open Questions

- Does the API actually accept `GET /v1/mgmt/profiles` (spec) or only `GET /v1/mgmt/profiles/tsg/{tsg_id}` (current SDK)? Need live testing.
- What fields does `DeleteAIProfileResponse` (409 schema) carry? Need to read full schema at spec line 1559.
- Should `GetByID` support a `Latest` param to avoid fetching all revisions?
- Is there an undocumented `GET /v1/mgmt/profile/{id}` or `GET /v1/mgmt/profile/uuid/{id}` endpoint that works but isn't in the spec?
