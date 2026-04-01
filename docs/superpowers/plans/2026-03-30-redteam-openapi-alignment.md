# Red Team SDK — OpenAPI Spec Alignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Align the `aisec/redteam` package with the updated mgmt-plane OpenAPI spec — fix 5 bugs, add 3 schema alignments, implement 6 new endpoint groups, and clean up file structure.

**Architecture:** Vertical slices — each task is one self-contained PR. Bug fixes first, then schema alignment, then new endpoints, then cleanup. Each task modifies models, client methods, constants, and tests together.

**Tech Stack:** Go 1.22+, stdlib only, `httptest` for mocking, `golangci-lint` for linting.

**Design spec:** `docs/superpowers/specs/2026-03-30-redteam-openapi-alignment-design.md`
**Tracking issue:** cdot65/prisma-airs-go#90

---

## File Map

| File | Responsibility |
|------|---------------|
| `aisec/constants.go` | API path constants — add new RedTeam mgmt-plane paths |
| `aisec/redteam/models.go` | All model structs and enums (split into domain files in Task 15) |
| `aisec/redteam/client.go` | All client methods and sub-clients |
| `aisec/redteam/client_test.go` | All client method tests using `httptest` |
| `aisec/redteam/models_test.go` | Enum value tests and JSON round-trip tests |

After Task 15, `models.go` splits into:
- `models_enums.go`, `models_target.go`, `models_scan.go`, `models_custom_attack.go`, `models_dashboard.go`, `models_eula.go`, `models_instance.go`

---

## Phase 1: Bug Fixes

### Task 1: Fix UpdateProfile path (`/context` → `/profile`)

**Files:**
- Modify: `aisec/redteam/client.go:557-564`
- Modify: `aisec/redteam/client_test.go` (add path assertion to existing test)

- [ ] **Step 1: Update the test to assert correct path**

In `client_test.go`, replace the existing `TestTargets_GetProfile` test and add a new `TestTargets_UpdateProfile` test that asserts the path:

```go
func TestTargets_UpdateProfile(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("method = %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/v1/target/tgt-1/profile") {
			t.Errorf("path = %s, want suffix /v1/target/tgt-1/profile", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(TargetResponse{UUID: "tgt-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Targets.UpdateProfile(context.Background(), "tgt-1", TargetContextUpdate{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.UUID != "tgt-1" {
		t.Errorf("UUID = %q", resp.UUID)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v ./aisec/redteam/ -run TestTargets_UpdateProfile`
Expected: FAIL — path will be `/v1/target/tgt-1/context`, not `/v1/target/tgt-1/profile`

- [ ] **Step 3: Fix the path in client.go**

In `aisec/redteam/client.go:559`, change:
```go
Method: http.MethodPut, Path: aisec.RedTeamTargetPath + "/" + uuid + "/context", Body: req,
```
to:
```go
Method: http.MethodPut, Path: aisec.RedTeamTargetPath + "/" + uuid + "/profile", Body: req,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -v ./aisec/redteam/ -run TestTargets_UpdateProfile`
Expected: PASS

- [ ] **Step 5: Run full test suite**

Run: `make check`
Expected: All checks pass

- [ ] **Step 6: Commit**

```bash
git add aisec/redteam/client.go aisec/redteam/client_test.go
git commit -m "fix(redteam): UpdateProfile path /context -> /profile"
```

---

### Task 2: Fix GetPropertyValuesMultiple (POST → GET with query param)

**Files:**
- Modify: `aisec/redteam/client.go:741-749`
- Modify: `aisec/redteam/client_test.go`

- [ ] **Step 1: Write the failing test**

Add to `client_test.go`:

```go
func TestCustomAttacks_GetPropertyValuesMultiple(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method = %s, want GET", r.Method)
		}
		got := r.URL.Query().Get("property_names")
		if got != "category,severity" {
			t.Errorf("property_names = %q, want %q", got, "category,severity")
		}
		_ = json.NewEncoder(w).Encode(PropertyValuesMultipleResponse{
			Data: map[string][]string{"category": {"security"}},
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttacks.GetPropertyValuesMultiple(context.Background(), []string{"category", "severity"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Data["category"]) != 1 {
		t.Errorf("category values = %d", len(resp.Data["category"]))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v ./aisec/redteam/ -run TestCustomAttacks_GetPropertyValuesMultiple`
Expected: FAIL — method is POST, no query param

- [ ] **Step 3: Fix the method in client.go**

Add `"strings"` to the imports in `client.go` (if not already present). Then replace the `GetPropertyValuesMultiple` method body at `client.go:741-749`:

```go
func (c *CustomAttacksClient) GetPropertyValuesMultiple(ctx context.Context, propertyNames []string) (*PropertyValuesMultipleResponse, error) {
	resp, err := internal.DoMgmtRequest[PropertyValuesMultipleResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamCustomAttackPath + "/property-values",
		Params: map[string]string{"property_names": strings.Join(propertyNames, ",")},
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -v ./aisec/redteam/ -run TestCustomAttacks_GetPropertyValuesMultiple`
Expected: PASS

- [ ] **Step 5: Run full test suite**

Run: `make check`
Expected: All checks pass

- [ ] **Step 6: Commit**

```bash
git add aisec/redteam/client.go aisec/redteam/client_test.go
git commit -m "fix(redteam): GetPropertyValuesMultiple POST -> GET with query param"
```

---

### Task 3: Fix CreatePropertyValue path (remove `/create` suffix)

**Files:**
- Modify: `aisec/redteam/client.go:752-758`
- Modify: `aisec/redteam/client_test.go`

- [ ] **Step 1: Write the failing test**

Add to `client_test.go`:

```go
func TestCustomAttacks_CreatePropertyValue(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/v1/custom-attack/property-values") {
			t.Errorf("path = %s, want suffix /v1/custom-attack/property-values", r.URL.Path)
		}
		// Must NOT have /create suffix
		if strings.HasSuffix(r.URL.Path, "/create") {
			t.Errorf("path should not end with /create: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(BaseResponse{Message: "created"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttacks.CreatePropertyValue(context.Background(), PropertyValueCreateRequest{
		PropertyName: "category", Value: "security",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Message != "created" {
		t.Errorf("Message = %q", resp.Message)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v ./aisec/redteam/ -run TestCustomAttacks_CreatePropertyValue`
Expected: FAIL — path ends with `/create`

- [ ] **Step 3: Fix the path in client.go**

In `aisec/redteam/client.go:754`, change:
```go
Method: http.MethodPost, Path: aisec.RedTeamCustomAttackPath + "/property-values/create", Body: req,
```
to:
```go
Method: http.MethodPost, Path: aisec.RedTeamCustomAttackPath + "/property-values", Body: req,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -v ./aisec/redteam/ -run TestCustomAttacks_CreatePropertyValue`
Expected: PASS

- [ ] **Step 5: Run full test suite**

Run: `make check`
Expected: All checks pass

- [ ] **Step 6: Commit**

```bash
git add aisec/redteam/client.go aisec/redteam/client_test.go
git commit -m "fix(redteam): CreatePropertyValue remove /create path suffix"
```

---

### Task 4: Type DashboardOverviewResponse + add BaseResponse.Status

**Files:**
- Modify: `aisec/redteam/models.go:695-698` (BaseResponse)
- Modify: `aisec/redteam/models.go:957-960` (DashboardOverviewResponse)
- Modify: `aisec/redteam/client_test.go:568-583` (TestGetDashboardOverview)
- Modify: `aisec/redteam/models_test.go` (add JSON round-trip test)

- [ ] **Step 1: Write the failing model test**

Add to `models_test.go`:

```go
func TestDashboardOverviewResponse_JSON(t *testing.T) {
	raw := `{"total_targets":5,"targets_by_type":[{"name":"APPLICATION","count":3},{"name":"MODEL","count":2}]}`
	var resp DashboardOverviewResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.TotalTargets != 5 {
		t.Errorf("TotalTargets = %d, want 5", resp.TotalTargets)
	}
	if len(resp.TargetsByType) != 2 {
		t.Errorf("TargetsByType len = %d, want 2", len(resp.TargetsByType))
	}
	if resp.TargetsByType[0].Name != "APPLICATION" {
		t.Errorf("TargetsByType[0].Name = %q", resp.TargetsByType[0].Name)
	}
}

func TestBaseResponse_JSON(t *testing.T) {
	raw := `{"message":"ok","status":200}`
	var resp BaseResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Message != "ok" {
		t.Errorf("Message = %q", resp.Message)
	}
	if resp.Status != 200 {
		t.Errorf("Status = %d, want 200", resp.Status)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v ./aisec/redteam/ -run "TestDashboardOverviewResponse_JSON|TestBaseResponse_JSON"`
Expected: FAIL — `TotalTargets` field doesn't exist; `Status` field doesn't exist

- [ ] **Step 3: Update the model structs**

In `aisec/redteam/models.go`, replace the `BaseResponse` struct (lines 695-698):
```go
// BaseResponse is a generic base response.
type BaseResponse struct {
	Message string `json:"message,omitempty"`
	Status  int    `json:"status,omitempty"`
}
```

Replace the `DashboardOverviewResponse` struct (lines 957-960):
```go
// DashboardOverviewResponse is the dashboard overview.
type DashboardOverviewResponse struct {
	TotalTargets  int           `json:"total_targets"`
	TargetsByType []CountByName `json:"targets_by_type,omitempty"`
}
```

- [ ] **Step 4: Run model tests to verify they pass**

Run: `go test -v ./aisec/redteam/ -run "TestDashboardOverviewResponse_JSON|TestBaseResponse_JSON"`
Expected: PASS

- [ ] **Step 5: Update the client test for GetDashboardOverview**

In `client_test.go`, replace `TestGetDashboardOverview` (lines 568-583):

```go
func TestGetDashboardOverview(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(DashboardOverviewResponse{
			TotalTargets:  5,
			TargetsByType: []CountByName{{Name: "APPLICATION", Count: 3}},
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.GetDashboardOverview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.TotalTargets != 5 {
		t.Errorf("TotalTargets = %d", resp.TotalTargets)
	}
}
```

- [ ] **Step 6: Run full test suite**

Run: `make check`
Expected: All checks pass

- [ ] **Step 7: Commit**

```bash
git add aisec/redteam/models.go aisec/redteam/models_test.go aisec/redteam/client_test.go
git commit -m "fix(redteam): type DashboardOverviewResponse, add BaseResponse.Status"
```

---

### Task 5: Fix CustomPromptSetCreateRequest/UpdateRequest fields

**Files:**
- Modify: `aisec/redteam/models.go:702-714`
- Modify: `aisec/redteam/models_test.go`
- Modify: `aisec/redteam/client_test.go`

- [ ] **Step 1: Write the failing model test**

Add to `models_test.go`:

```go
func TestCustomPromptSetCreateRequest_JSON(t *testing.T) {
	req := CustomPromptSetCreateRequest{
		Name:          "test-set",
		PropertyNames: []string{"category", "severity"},
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, ok := m["property_names"]; !ok {
		t.Error("expected property_names key in JSON, got properties or missing")
	}
	if _, ok := m["properties"]; ok {
		t.Error("should not have properties key in JSON")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v ./aisec/redteam/ -run TestCustomPromptSetCreateRequest_JSON`
Expected: FAIL — `PropertyNames` field doesn't exist

- [ ] **Step 3: Update the model structs**

In `aisec/redteam/models.go`, replace `CustomPromptSetCreateRequest` (lines 702-707):
```go
// CustomPromptSetCreateRequest is the request to create a prompt set.
type CustomPromptSetCreateRequest struct {
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	PropertyNames []string `json:"property_names,omitempty"`
}
```

Replace `CustomPromptSetUpdateRequest` (lines 709-714):
```go
// CustomPromptSetUpdateRequest is the request to update a prompt set.
type CustomPromptSetUpdateRequest struct {
	Name          string   `json:"name,omitempty"`
	Description   string   `json:"description,omitempty"`
	Archive       *bool    `json:"archive,omitempty"`
	PropertyNames []string `json:"property_names,omitempty"`
}
```

Note: `Archive` added to `CustomPromptSetUpdateRequest` per spec — the spec allows setting archive via the update endpoint too.

Also replace `CustomPromptSetVersionInfo` (lines 763-766) — it's severely undertyped:
```go
// CustomPromptSetVersionInfo is the version info for a prompt set.
type CustomPromptSetVersionInfo struct {
	UUID              string             `json:"uuid,omitempty"`
	Version           string             `json:"version,omitempty"`
	Status            string             `json:"status,omitempty"`
	Stats             *PromptSetStats    `json:"stats,omitempty"`
	SnapshotCreatedAt string             `json:"snapshot_created_at,omitempty"`
	IsLatest          bool               `json:"is_latest"`
}

// PromptSetStats contains statistics for a prompt set.
type PromptSetStats struct {
	TotalPrompts      int `json:"total_prompts"`
	ActivePrompts     int `json:"active_prompts"`
	FailedPrompts     int `json:"failed_prompts,omitempty"`
	ValidationPrompts int `json:"validation_prompts,omitempty"`
	InactivePrompts   int `json:"inactive_prompts"`
}
```

Also update `GetPromptSetVersionInfo` in `client.go:636-644` to accept an optional version param:
```go
func (c *CustomAttacksClient) GetPromptSetVersionInfo(ctx context.Context, uuid string, version string) (*CustomPromptSetVersionInfo, error) {
	var params map[string]string
	if version != "" {
		params = map[string]string{"version": version}
	}
	resp, err := internal.DoMgmtRequest[CustomPromptSetVersionInfo](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamCustomPromptSetPath + "/" + uuid + "/version-info",
		Params: params,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}
```

Also type `CustomPromptSetResponse.Stats` — replace `Stats map[string]any` with `Stats *PromptSetStats` in the struct (line 730).

- [ ] **Step 4: Run model test to verify it passes**

Run: `go test -v ./aisec/redteam/ -run TestCustomPromptSetCreateRequest_JSON`
Expected: PASS

- [ ] **Step 5: Update client test for CreatePromptSet**

In `client_test.go`, update `TestCustomAttacks_CreatePromptSet` (line 462) to use the new field name:

```go
ps, err := client.CustomAttacks.CreatePromptSet(context.Background(), CustomPromptSetCreateRequest{Name: "test-set"})
```

This line is already correct (only uses `Name`), so no change needed. But verify it compiles.

- [ ] **Step 6: Run full test suite**

Run: `make check`
Expected: All checks pass

- [ ] **Step 7: Commit**

```bash
git add aisec/redteam/models.go aisec/redteam/models_test.go aisec/redteam/client_test.go
git commit -m "fix(redteam): CustomPromptSet request Properties -> PropertyNames"
```

---

## Phase 2: Schema/Model Alignment

### Task 6: Add WebSocket enum values

**Files:**
- Modify: `aisec/redteam/models.go:52-60` (TargetConnectionType enum)
- Modify: `aisec/redteam/models.go:91-97` (ResponseMode enum)
- Modify: `aisec/redteam/models_test.go`

- [ ] **Step 1: Write the failing test**

Add to `models_test.go`:

```go
func TestWebSocketEnumValues(t *testing.T) {
	if string(TargetConnectionTypeWebSocket) != "WEBSOCKET" {
		t.Errorf("TargetConnectionTypeWebSocket = %q", TargetConnectionTypeWebSocket)
	}
	if string(ResponseModeWebSocket) != "WEBSOCKET" {
		t.Errorf("ResponseModeWebSocket = %q", ResponseModeWebSocket)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v ./aisec/redteam/ -run TestWebSocketEnumValues`
Expected: FAIL — undefined constants

- [ ] **Step 3: Add enum values**

In `aisec/redteam/models.go`, add to the `TargetConnectionType` const block (after line 59):
```go
TargetConnectionTypeWebSocket TargetConnectionType = "WEBSOCKET"
```

Add to the `ResponseMode` const block (after line 96):
```go
ResponseModeWebSocket ResponseMode = "WEBSOCKET"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -v ./aisec/redteam/ -run TestWebSocketEnumValues`
Expected: PASS

- [ ] **Step 5: Run full test suite**

Run: `make check`
Expected: All checks pass

- [ ] **Step 6: Commit**

```bash
git add aisec/redteam/models.go aisec/redteam/models_test.go
git commit -m "feat(redteam): add WEBSOCKET to TargetConnectionType and ResponseMode"
```

---

### Task 7: Add typed auth config structs

**Files:**
- Modify: `aisec/redteam/models.go` (add enums + structs after existing AuthType block)
- Modify: `aisec/redteam/models.go` (add fields to TargetCreateRequest, TargetUpdateRequest, TargetResponse)
- Modify: `aisec/redteam/models_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `models_test.go`:

```go
func TestAuthConfigType_Values(t *testing.T) {
	vals := []AuthConfigType{AuthConfigTypeHeaders, AuthConfigTypeBasicAuth, AuthConfigTypeOAuth2}
	expected := []string{"HEADERS", "BASIC_AUTH", "OAUTH2"}
	for i, v := range vals {
		if string(v) != expected[i] {
			t.Errorf("AuthConfigType[%d] = %q, want %q", i, v, expected[i])
		}
	}
}

func TestBasicAuthLocation_Values(t *testing.T) {
	vals := []BasicAuthLocation{BasicAuthLocationHeader, BasicAuthLocationPayload}
	expected := []string{"HEADER", "PAYLOAD"}
	for i, v := range vals {
		if string(v) != expected[i] {
			t.Errorf("BasicAuthLocation[%d] = %q, want %q", i, v, expected[i])
		}
	}
}

func TestHeadersAuthConfig_JSON(t *testing.T) {
	cfg := HeadersAuthConfig{AuthHeader: map[string]string{"Authorization": "Bearer tok"}}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var out HeadersAuthConfig
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.AuthHeader["Authorization"] != "Bearer tok" {
		t.Errorf("AuthHeader = %v", out.AuthHeader)
	}
}

func TestOAuth2AuthConfig_JSON(t *testing.T) {
	cfg := OAuth2AuthConfig{
		OAuth2TokenURL:      "https://auth.example.com/token",
		OAuth2ExpiryMinutes: 30,
		OAuth2InjectHeader:  map[string]string{"Authorization": "Bearer {TOKEN}"},
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var out OAuth2AuthConfig
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.OAuth2TokenURL != "https://auth.example.com/token" {
		t.Errorf("OAuth2TokenURL = %q", out.OAuth2TokenURL)
	}
	if out.OAuth2ExpiryMinutes != 30 {
		t.Errorf("OAuth2ExpiryMinutes = %d", out.OAuth2ExpiryMinutes)
	}
}

func TestTargetCreateRequest_AuthConfig_JSON(t *testing.T) {
	req := TargetCreateRequest{
		Name:           "test",
		AuthConfigType: AuthConfigTypeHeaders,
		AuthConfig:     HeadersAuthConfig{AuthHeader: map[string]string{"X-Key": "val"}},
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if m["auth_type"] != "HEADERS" {
		t.Errorf("auth_type = %v", m["auth_type"])
	}
	if m["auth_config"] == nil {
		t.Error("auth_config is nil")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v ./aisec/redteam/ -run "TestAuthConfigType|TestBasicAuthLocation|TestHeadersAuthConfig|TestOAuth2AuthConfig|TestTargetCreateRequest_AuthConfig"`
Expected: FAIL — types don't exist

- [ ] **Step 3: Add the enum types and struct definitions**

In `aisec/redteam/models.go`, add after the existing `AuthType` const block (after line 143):

```go
// AuthConfigType represents the auth config type for target endpoints.
// Named AuthConfigType to avoid collision with AuthType (Databricks OAUTH/ACCESS_TOKEN).
type AuthConfigType string

const (
	AuthConfigTypeHeaders   AuthConfigType = "HEADERS"
	AuthConfigTypeBasicAuth AuthConfigType = "BASIC_AUTH"
	AuthConfigTypeOAuth2    AuthConfigType = "OAUTH2"
)

// BasicAuthLocation represents where basic auth credentials are sent.
type BasicAuthLocation string

const (
	BasicAuthLocationHeader  BasicAuthLocation = "HEADER"
	BasicAuthLocationPayload BasicAuthLocation = "PAYLOAD"
)

// HeadersAuthConfig is auth config using custom headers.
type HeadersAuthConfig struct {
	AuthHeader map[string]string `json:"auth_header"`
}

// BasicAuthAuthConfig is auth config using basic authentication.
type BasicAuthAuthConfig struct {
	BasicAuthLocation BasicAuthLocation `json:"basic_auth_location,omitempty"`
	BasicAuthHeader   map[string]string `json:"basic_auth_header,omitempty"`
}

// OAuth2AuthConfig is auth config using OAuth2 client credentials.
type OAuth2AuthConfig struct {
	OAuth2TokenURL         string            `json:"oauth2_token_url"`
	OAuth2ExpiryMinutes    int               `json:"oauth2_expiry_minutes,omitempty"`
	OAuth2Headers          map[string]string `json:"oauth2_headers,omitempty"`
	OAuth2BodyParams       map[string]string `json:"oauth2_body_params,omitempty"`
	OAuth2TokenResponseKey string            `json:"oauth2_token_response_key,omitempty"`
	OAuth2InjectHeader     map[string]string `json:"oauth2_inject_header"`
}
```

- [ ] **Step 4: Add auth fields to TargetCreateRequest, TargetUpdateRequest, TargetResponse**

In `aisec/redteam/models.go`, add two fields to `TargetCreateRequest` (after the `AdditionalContext` field, before the closing brace):
```go
	AuthConfigType AuthConfigType `json:"auth_type,omitempty"`
	AuthConfig     any            `json:"auth_config,omitempty"`
```

Add the same two fields to `TargetUpdateRequest` (same position).

Add the same two fields to `TargetResponse` (after `AdditionalCtx`, before closing brace):
```go
	AuthConfigType           AuthConfigType          `json:"auth_type,omitempty"`
	AuthConfig               any                     `json:"auth_config,omitempty"`
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test -v ./aisec/redteam/ -run "TestAuthConfigType|TestBasicAuthLocation|TestHeadersAuthConfig|TestOAuth2AuthConfig|TestTargetCreateRequest_AuthConfig"`
Expected: PASS

- [ ] **Step 6: Run full test suite**

Run: `make check`
Expected: All checks pass

- [ ] **Step 7: Commit**

```bash
git add aisec/redteam/models.go aisec/redteam/models_test.go
git commit -m "feat(redteam): add typed auth config (Headers/BasicAuth/OAuth2)"
```

---

### Task 8: Fill missing fields on TargetResponse + type TargetProbeRequest

**Files:**
- Modify: `aisec/redteam/models.go` (TargetResponse, TargetProbeRequest)
- Modify: `aisec/redteam/models_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `models_test.go`:

```go
func TestTargetResponse_NetworkBrokerField(t *testing.T) {
	raw := `{"uuid":"t-1","tsg_id":"123","name":"test","status":"ACTIVE","active":true,"validated":true,"created_at":"2026-01-01","updated_at":"2026-01-01","network_broker_channel_uuid":"nb-1"}`
	var resp TargetResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.NetworkBrokerChannelUUID != "nb-1" {
		t.Errorf("NetworkBrokerChannelUUID = %q", resp.NetworkBrokerChannelUUID)
	}
}

func TestTargetProbeRequest_TypedFields(t *testing.T) {
	req := TargetProbeRequest{
		Name: "probe",
		TargetMeta: &TargetMetadata{
			MultiTurn:    true,
			ProbeMessage: "hello",
		},
		TargetBackground: &TargetBackground{
			Industry: "finance",
		},
		AdditionalContext: &TargetAdditionalContext{
			BaseModel: "gpt-4",
		},
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	tm, ok := m["target_metadata"].(map[string]any)
	if !ok {
		t.Fatal("target_metadata not a map")
	}
	if tm["multi_turn"] != true {
		t.Errorf("multi_turn = %v", tm["multi_turn"])
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v ./aisec/redteam/ -run "TestTargetResponse_NetworkBrokerField|TestTargetProbeRequest_TypedFields"`
Expected: FAIL — `NetworkBrokerChannelUUID` missing from `TargetResponse`; `TargetProbeRequest.TargetMeta` doesn't exist (it uses `map[string]any`)

- [ ] **Step 3: Add missing field to TargetResponse**

In `aisec/redteam/models.go`, add to the `TargetResponse` struct (after `AdditionalCtx`):
```go
	NetworkBrokerChannelUUID string                  `json:"network_broker_channel_uuid,omitempty"`
```

Also add the doc comment about redaction:
```go
// TargetResponse represents a target.
// Note: GET /v1/target/{id} returns redacted secrets (auth keys, connection passwords masked by the server).
```

- [ ] **Step 4: Convert TargetProbeRequest to use typed fields**

In `aisec/redteam/models.go`, replace `TargetProbeRequest` (lines 664-681):
```go
// TargetProbeRequest is the request to probe a target.
type TargetProbeRequest struct {
	Name                     string                   `json:"name"`
	Description              string                   `json:"description,omitempty"`
	TargetType               TargetType               `json:"target_type,omitempty"`
	ConnectionType           TargetConnectionType     `json:"connection_type,omitempty"`
	APIEndpointType          APIEndpointType          `json:"api_endpoint_type,omitempty"`
	ResponseMode             ResponseMode             `json:"response_mode,omitempty"`
	SessionSupported         *bool                    `json:"session_supported,omitempty"`
	ConnectionParams         map[string]any           `json:"connection_params,omitempty"`
	NetworkBrokerChannelUUID string                   `json:"network_broker_channel_uuid,omitempty"`
	ExtraInfo                map[string]any           `json:"extra_info,omitempty"`
	TargetMeta               *TargetMetadata          `json:"target_metadata,omitempty"`
	TargetBackground         *TargetBackground        `json:"target_background,omitempty"`
	AdditionalContext        *TargetAdditionalContext  `json:"additional_context,omitempty"`
	AuthConfigType           AuthConfigType           `json:"auth_type,omitempty"`
	AuthConfig               any                      `json:"auth_config,omitempty"`
	UUID                     string                   `json:"uuid,omitempty"`
	ProbeFields              []string                 `json:"probe_fields,omitempty"`
}
```

Note: `SessionSupported` changed from `*bool` with `json:"session_supported"` to `json:"session_supported,omitempty"` to avoid sending `false` when unset. The three map fields (`TargetMetadata`, `TargetBackground`, `AdditionalContext`) changed from `map[string]any` to typed pointers.

- [ ] **Step 5: Update the existing probe test**

In `client_test.go`, the `TestTargets_Probe_AllFields` test (line 374) accesses `req.TargetMetadata`, `req.TargetBackground`, `req.AdditionalContext` as maps. Since the server-side test decodes into `TargetProbeRequest`, the typed fields will now unmarshal correctly. But the test constructs a request with `ConnectionParams: map[string]any{...}` which is still valid. Review the test — the field names in the struct literal need to match the new names:

The existing test at line 409-420 uses `ConnectionParams` (still `map[string]any`, unchanged) and doesn't set `TargetMetadata`/`TargetBackground`/`AdditionalContext`, so it compiles as-is. No change needed.

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test -v ./aisec/redteam/ -run "TestTargetResponse_NetworkBrokerField|TestTargetProbeRequest_TypedFields|TestTargets_Probe"`
Expected: PASS

- [ ] **Step 7: Run full test suite**

Run: `make check`
Expected: All checks pass

- [ ] **Step 8: Commit**

```bash
git add aisec/redteam/models.go aisec/redteam/models_test.go aisec/redteam/client_test.go
git commit -m "feat(redteam): fill missing TargetResponse fields, type TargetProbeRequest"
```

---

## Phase 3: New Endpoints

### Task 9: Add Target Auth Validation endpoint

**Files:**
- Modify: `aisec/constants.go:173-186` (add new path constant)
- Modify: `aisec/redteam/models.go` (add request/response structs)
- Modify: `aisec/redteam/client.go` (add method to TargetsClient)
- Modify: `aisec/redteam/client_test.go`

- [ ] **Step 1: Write the failing test**

Add to `client_test.go`:

```go
func TestTargets_ValidateAuth(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/v1/target/validate-auth") {
			t.Errorf("path = %s", r.URL.Path)
		}
		var req TargetAuthValidationRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.AuthType != AuthConfigTypeHeaders {
			t.Errorf("AuthType = %q", req.AuthType)
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(TargetAuthValidationResponse{Validated: true})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Targets.ValidateAuth(context.Background(), TargetAuthValidationRequest{
		AuthType:   AuthConfigTypeHeaders,
		AuthConfig: HeadersAuthConfig{AuthHeader: map[string]string{"X-Key": "val"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Validated {
		t.Error("expected Validated=true")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v ./aisec/redteam/ -run TestTargets_ValidateAuth`
Expected: FAIL — `TargetAuthValidationRequest`, `TargetAuthValidationResponse`, `ValidateAuth` don't exist

- [ ] **Step 3: Add model structs**

Add to `aisec/redteam/models.go` (after the `TargetProfileResponse` struct):

```go
// TargetAuthValidationRequest is the request to validate target auth config.
type TargetAuthValidationRequest struct {
	AuthType                 AuthConfigType `json:"auth_type"`
	AuthConfig               any            `json:"auth_config"`
	TargetID                 string         `json:"target_id,omitempty"`
	NetworkBrokerChannelUUID string         `json:"network_broker_channel_uuid,omitempty"`
}

// TargetAuthValidationResponse is the response from auth validation.
type TargetAuthValidationResponse struct {
	Validated    bool   `json:"validated"`
	TokenPreview string `json:"token_preview,omitempty"`
	ExpiresIn    *int   `json:"expires_in,omitempty"`
}
```

- [ ] **Step 4: Add path constant**

In `aisec/constants.go`, add to the Red Team management plane const block (after line 177):
```go
	RedTeamTargetValidateAuthPath = "/v1/target/validate-auth"
```

- [ ] **Step 5: Add client method**

In `aisec/redteam/client.go`, add after the `UpdateProfile` method (after line 564):

```go
// ValidateAuth validates target authentication configuration.
func (c *TargetsClient) ValidateAuth(ctx context.Context, req TargetAuthValidationRequest) (*TargetAuthValidationResponse, error) {
	resp, err := internal.DoMgmtRequest[TargetAuthValidationResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.RedTeamTargetValidateAuthPath, Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `go test -v ./aisec/redteam/ -run TestTargets_ValidateAuth`
Expected: PASS

- [ ] **Step 7: Run full test suite**

Run: `make check`
Expected: All checks pass

- [ ] **Step 8: Commit**

```bash
git add aisec/constants.go aisec/redteam/models.go aisec/redteam/client.go aisec/redteam/client_test.go
git commit -m "feat(redteam): add Target ValidateAuth endpoint"
```

---

### Task 10: Add Templates endpoints

**Files:**
- Modify: `aisec/constants.go`
- Modify: `aisec/redteam/client.go`
- Modify: `aisec/redteam/client_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `client_test.go`:

```go
func TestGetTargetMetadata(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/template/target-metadata") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"industries": []string{"finance", "healthcare"}})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.GetTargetMetadata(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Error("response is nil")
	}
}

func TestGetTargetTemplates(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/template/target-templates") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"OPENAI": map[string]any{"name": "OpenAI"}})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.GetTargetTemplates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Error("response is nil")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v ./aisec/redteam/ -run "TestGetTargetMetadata|TestGetTargetTemplates"`
Expected: FAIL — methods don't exist

- [ ] **Step 3: Add path constant**

In `aisec/constants.go`, add to the Red Team management plane const block:
```go
	RedTeamTemplatePath = "/v1/template"
```

- [ ] **Step 4: Add client methods**

In `aisec/redteam/client.go`, add after `GetDashboardOverview` (after line 157):

```go
// GetTargetMetadata gets scan metadata for target configuration from the mgmt plane.
func (c *Client) GetTargetMetadata(ctx context.Context) (map[string]any, error) {
	resp, err := internal.DoMgmtRequest[map[string]any](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamTemplatePath + "/target-metadata",
	})
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// GetTargetTemplates gets target templates from the mgmt plane.
func (c *Client) GetTargetTemplates(ctx context.Context) (map[string]any, error) {
	resp, err := internal.DoMgmtRequest[map[string]any](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamTemplatePath + "/target-templates",
	})
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test -v ./aisec/redteam/ -run "TestGetTargetMetadata|TestGetTargetTemplates"`
Expected: PASS

- [ ] **Step 6: Run full test suite**

Run: `make check`
Expected: All checks pass

- [ ] **Step 7: Commit**

```bash
git add aisec/constants.go aisec/redteam/client.go aisec/redteam/client_test.go
git commit -m "feat(redteam): add Templates endpoints (metadata + templates)"
```

---

### Task 11: Add EULA endpoints

**Files:**
- Modify: `aisec/constants.go`
- Modify: `aisec/redteam/models.go` (add EULA structs)
- Modify: `aisec/redteam/client.go` (add EulaClient sub-client, wire into Client)
- Modify: `aisec/redteam/client_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `client_test.go`:

```go
func TestEula_GetContent(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/eula/content") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(EulaContentResponse{Content: "EULA text here"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Eula.GetContent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Content != "EULA text here" {
		t.Errorf("Content = %q", resp.Content)
	}
}

func TestEula_GetStatus(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/eula/status") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(EulaResponse{IsAccepted: true})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Eula.GetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsAccepted {
		t.Error("expected IsAccepted=true")
	}
}

func TestEula_Accept(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/v1/eula/accept") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(EulaResponse{IsAccepted: true, AcceptedAt: "2026-03-30T00:00:00Z"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Eula.Accept(context.Background(), EulaAcceptRequest{EulaContent: "EULA text"})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsAccepted {
		t.Error("expected IsAccepted=true")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v ./aisec/redteam/ -run "TestEula_"`
Expected: FAIL — types and methods don't exist

- [ ] **Step 3: Add EULA model structs**

Add to `aisec/redteam/models.go` (after `BaseResponse`):

```go
// --- EULA types ---

// EulaContentResponse is the EULA content response.
type EulaContentResponse struct {
	Content string `json:"content"`
}

// EulaResponse is the EULA status response.
type EulaResponse struct {
	UUID             string `json:"uuid,omitempty"`
	IsAccepted       bool   `json:"is_accepted"`
	AcceptedAt       string `json:"accepted_at,omitempty"`
	AcceptedByUserID string `json:"accepted_by_user_id,omitempty"`
}

// EulaAcceptRequest is the request to accept the EULA.
type EulaAcceptRequest struct {
	EulaContent string `json:"eula_content"`
	AcceptedAt  string `json:"accepted_at,omitempty"`
}
```

- [ ] **Step 4: Add path constant**

In `aisec/constants.go`, add to the Red Team management plane const block:
```go
	RedTeamEulaPath = "/v1/eula"
```

- [ ] **Step 5: Add EulaClient sub-client and wire into Client**

In `aisec/redteam/client.go`, add the `Eula` field to the `Client` struct:
```go
type Client struct {
	Scans               *ScansClient
	Reports             *ReportsClient
	CustomAttackReports *CustomAttackReportsClient
	Targets             *TargetsClient
	CustomAttacks       *CustomAttacksClient
	Eula                *EulaClient

	dataCfg *internal.OAuthServiceConfig
	mgmtCfg *internal.OAuthServiceConfig
}
```

In `NewClient`, add initialization (after line 75):
```go
c.Eula = &EulaClient{mgmtCfg: mgmtCfg}
```

Add the sub-client and its methods (at end of file or after the CustomAttacks section):
```go
// --- EULA Client (mgmt plane) ---

// EulaClient provides EULA operations.
type EulaClient struct {
	mgmtCfg *internal.OAuthServiceConfig
}

// GetContent gets the EULA content.
func (c *EulaClient) GetContent(ctx context.Context) (*EulaContentResponse, error) {
	resp, err := internal.DoMgmtRequest[EulaContentResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamEulaPath + "/content",
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetStatus gets the EULA acceptance status.
func (c *EulaClient) GetStatus(ctx context.Context) (*EulaResponse, error) {
	resp, err := internal.DoMgmtRequest[EulaResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamEulaPath + "/status",
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Accept accepts the EULA.
func (c *EulaClient) Accept(ctx context.Context, req EulaAcceptRequest) (*EulaResponse, error) {
	resp, err := internal.DoMgmtRequest[EulaResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.RedTeamEulaPath + "/accept", Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}
```

- [ ] **Step 6: Update TestSubClients_AllPresent**

In `client_test.go`, add to `TestSubClients_AllPresent` (after line 615):
```go
	if client.Eula == nil {
		t.Error("Eula is nil")
	}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test -v ./aisec/redteam/ -run "TestEula_|TestSubClients"`
Expected: PASS

- [ ] **Step 8: Run full test suite**

Run: `make check`
Expected: All checks pass

- [ ] **Step 9: Commit**

```bash
git add aisec/constants.go aisec/redteam/models.go aisec/redteam/client.go aisec/redteam/client_test.go
git commit -m "feat(redteam): add EULA endpoints (content, status, accept)"
```

---

### Task 12: Add Instances/Licensing endpoints

**Files:**
- Modify: `aisec/constants.go`
- Modify: `aisec/redteam/models.go` (add ~14 structs)
- Modify: `aisec/redteam/client.go` (add InstancesClient sub-client)
- Modify: `aisec/redteam/client_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `client_test.go`:

```go
func TestInstances_Create(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/v1/instances") {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(InstanceResponse{TsgID: "tsg-1", IsSuccess: boolPtr(true)})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Instances.Create(context.Background(), InstanceRequest{
		TsgID: "tsg-1", TenantID: "t-1", AppID: "app-1", Region: "us-east-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.TsgID != "tsg-1" {
		t.Errorf("TsgID = %q", resp.TsgID)
	}
}

func TestInstances_Get(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/instances/t-1") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(InstanceGetResponse{
			TsgID: "tsg-1", TenantID: "t-1", AppID: "app-1", Region: "us-east-1",
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Instances.Get(context.Background(), "t-1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.TenantID != "t-1" {
		t.Errorf("TenantID = %q", resp.TenantID)
	}
}

func TestInstances_Delete(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(InstanceResponse{TsgID: "tsg-1", IsSuccess: boolPtr(true)})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Instances.Delete(context.Background(), "t-1")
	if err != nil {
		t.Fatal(err)
	}
	if *resp.IsSuccess != true {
		t.Error("expected IsSuccess=true")
	}
}

func TestInstances_CreateDevice(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/v1/instances/t-1/devices") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(DeviceResponse{Status: "created"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Instances.CreateDevice(context.Background(), "t-1", DeviceRequest{
		Instance: DeviceInstance{AppID: "app-1", Region: "us-east-1", TenantID: "t-1", TsgID: "tsg-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != "created" {
		t.Errorf("Status = %q", resp.Status)
	}
}

func TestInstances_DeleteDevice(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("method = %s", r.Method)
		}
		sn := r.URL.Query().Get("serial_numbers")
		if sn != "SN-001,SN-002" {
			t.Errorf("serial_numbers = %q", sn)
		}
		_ = json.NewEncoder(w).Encode(DeviceResponse{Status: "deleted"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Instances.DeleteDevice(context.Background(), "t-1", "SN-001,SN-002")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != "deleted" {
		t.Errorf("Status = %q", resp.Status)
	}
}
```

Also add the `boolPtr` helper near the top of `client_test.go` (after `newTestClient`):
```go
func boolPtr(b bool) *bool { return &b }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v ./aisec/redteam/ -run "TestInstances_"`
Expected: FAIL — types and methods don't exist

- [ ] **Step 3: Add all Instance/Device model structs**

Add to `aisec/redteam/models.go` (after EULA types):

```go
// --- Instance/Licensing types ---

// InstanceRequest is the request to create or update an instance.
type InstanceRequest struct {
	TsgID              string                `json:"tsg_id"`
	TenantID           string                `json:"tenant_id"`
	AppID              string                `json:"app_id"`
	Region             string                `json:"region"`
	SupportAccountID   string                `json:"support_account_id,omitempty"`
	SupportAccountName string                `json:"support_account_name,omitempty"`
	CreatedBy          string                `json:"created_by,omitempty"`
	Internal           *bool                 `json:"internal,omitempty"`
	TenantInstanceName string                `json:"tenant_instance_name,omitempty"`
	Extra              *InstanceExtraDetails `json:"extra,omitempty"`
	IAMControlled      *bool                 `json:"iam_controlled,omitempty"`
	PlatformRegion     string                `json:"platform_region,omitempty"`
	CspTenantID        string                `json:"csp_tenant_id,omitempty"`
	TsgInstances       []map[string]any      `json:"tsg_instances,omitempty"`
}

// InstanceResponse is the response from instance create/update/delete.
type InstanceResponse struct {
	TsgID     string `json:"tsg_id"`
	TenantID  string `json:"tenant_id,omitempty"`
	AppID     string `json:"app_id,omitempty"`
	IsSuccess *bool  `json:"is_success,omitempty"`
}

// InstanceGetResponse is the response from instance get.
type InstanceGetResponse struct {
	TsgID              string               `json:"tsg_id"`
	TenantID           string               `json:"tenant_id"`
	AppID              string               `json:"app_id"`
	Region             string               `json:"region"`
	SupportAccountID   string               `json:"support_account_id,omitempty"`
	SupportAccountName string               `json:"support_account_name,omitempty"`
	CreatedBy          string               `json:"created_by,omitempty"`
	Internal           *bool                `json:"internal,omitempty"`
	TenantInstanceName string               `json:"tenant_instance_name,omitempty"`
	DeploymentProfiles []InstanceDPMetadata `json:"deployment_profiles,omitempty"`
}

// InstanceExtraDetails contains extra details for an instance request.
type InstanceExtraDetails struct {
	DeploymentProfiles []DeploymentProfileRequest `json:"deployment_profiles,omitempty"`
	AirsSharedByTsg    map[string]any             `json:"airs_shared_by_tsg,omitempty"`
	AirsUnsharedDps    []string                   `json:"airs_unshared_dps,omitempty"`
}

// InstanceDPMetadata is metadata for a deployment profile.
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

// DeploymentProfileRequest is a deployment profile in an instance request.
type DeploymentProfileRequest struct {
	DAuthCode           string                       `json:"dAuthCode,omitempty"`
	DeploymentProfileID string                       `json:"deploymentProfileId,omitempty"`
	LicenseExpiration   string                       `json:"license_expiration,omitempty"`
	ProfileName         string                       `json:"profileName,omitempty"`
	SubType             string                       `json:"subType,omitempty"`
	Subscriptions       []any                        `json:"subscriptions,omitempty"`
	Type                string                       `json:"type,omitempty"`
	AveTextRecord       *int                         `json:"aveTextRecord,omitempty"`
	Attributes          []DeploymentProfileAttribute `json:"attributes,omitempty"`
}

// DeploymentProfileAttribute is an attribute of a deployment profile.
type DeploymentProfileAttribute struct {
	Quantity      string `json:"quantity,omitempty"`
	UnitOfMeasure string `json:"unit_of_measure,omitempty"`
}

// DeviceRequest is the request to create/update devices.
type DeviceRequest struct {
	Instance  DeviceInstance `json:"instance"`
	CreatedBy string         `json:"created_by,omitempty"`
	Devices   []Device       `json:"devices,omitempty"`
}

// DeviceInstance identifies the instance for device operations.
type DeviceInstance struct {
	AppID    string `json:"app_id"`
	Region   string `json:"region"`
	TenantID string `json:"tenant_id"`
	TsgID    string `json:"tsg_id"`
}

// Device represents a device.
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

// DeviceLicense represents a license on a device.
type DeviceLicense struct {
	AuthorizationCode          string `json:"authorizationCode,omitempty"`
	ExpirationDate             string `json:"expirationDate,omitempty"`
	LicensePanDbIdentification string `json:"licensePanDbIdentification,omitempty"`
	PartNumber                 string `json:"partNumber,omitempty"`
	SerialNumber               string `json:"serialNumber,omitempty"`
	SubtypeName                string `json:"subtypeName,omitempty"`
	RegistrationDate           string `json:"registrationDate,omitempty"`
}

// DeviceResponse is the response from device operations.
type DeviceResponse struct {
	Devices []DeviceStatus `json:"devices,omitempty"`
	Status  string         `json:"status,omitempty"`
}

// DeviceStatus is the status of a device operation.
type DeviceStatus struct {
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
}
```

- [ ] **Step 4: Add path constant**

In `aisec/constants.go`, add:
```go
	RedTeamInstancesPath = "/v1/instances"
```

- [ ] **Step 5: Add InstancesClient sub-client and wire into Client**

Add `Instances *InstancesClient` to the `Client` struct. In `NewClient`, add:
```go
c.Instances = &InstancesClient{mgmtCfg: mgmtCfg}
```

Add the sub-client (at end of `client.go`):

```go
// --- Instances Client (mgmt plane) ---

// InstancesClient provides instance and device management operations.
type InstancesClient struct {
	mgmtCfg *internal.OAuthServiceConfig
}

// Create creates a new instance.
func (c *InstancesClient) Create(ctx context.Context, req InstanceRequest) (*InstanceResponse, error) {
	resp, err := internal.DoMgmtRequest[InstanceResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.RedTeamInstancesPath, Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Get gets an instance by tenant ID.
func (c *InstancesClient) Get(ctx context.Context, tenantID string) (*InstanceGetResponse, error) {
	resp, err := internal.DoMgmtRequest[InstanceGetResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamInstancesPath + "/" + tenantID,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Update updates an instance.
func (c *InstancesClient) Update(ctx context.Context, tenantID string, req InstanceRequest) (*InstanceResponse, error) {
	resp, err := internal.DoMgmtRequest[InstanceResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodPut, Path: aisec.RedTeamInstancesPath + "/" + tenantID, Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Delete deletes an instance.
func (c *InstancesClient) Delete(ctx context.Context, tenantID string) (*InstanceResponse, error) {
	resp, err := internal.DoMgmtRequest[InstanceResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodDelete, Path: aisec.RedTeamInstancesPath + "/" + tenantID,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// CreateDevice creates devices for an instance.
func (c *InstancesClient) CreateDevice(ctx context.Context, tenantID string, req DeviceRequest) (*DeviceResponse, error) {
	resp, err := internal.DoMgmtRequest[DeviceResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.RedTeamInstancesPath + "/" + tenantID + "/devices", Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// UpdateDevice updates devices for an instance.
func (c *InstancesClient) UpdateDevice(ctx context.Context, tenantID string, req DeviceRequest) (*DeviceResponse, error) {
	resp, err := internal.DoMgmtRequest[DeviceResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodPatch, Path: aisec.RedTeamInstancesPath + "/" + tenantID + "/devices", Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// DeleteDevice deletes devices from an instance.
func (c *InstancesClient) DeleteDevice(ctx context.Context, tenantID string, serialNumbers string) (*DeviceResponse, error) {
	resp, err := internal.DoMgmtRequest[DeviceResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodDelete, Path: aisec.RedTeamInstancesPath + "/" + tenantID + "/devices",
		Params: map[string]string{"serial_numbers": serialNumbers},
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}
```

- [ ] **Step 6: Update TestSubClients_AllPresent**

Add to the test:
```go
	if client.Instances == nil {
		t.Error("Instances is nil")
	}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test -v ./aisec/redteam/ -run "TestInstances_|TestSubClients"`
Expected: PASS

- [ ] **Step 8: Run full test suite**

Run: `make check`
Expected: All checks pass

- [ ] **Step 9: Commit**

```bash
git add aisec/constants.go aisec/redteam/models.go aisec/redteam/client.go aisec/redteam/client_test.go
git commit -m "feat(redteam): add Instances/Licensing endpoints (7 methods)"
```

---

### Task 13: Add Registry Credentials endpoint

**Files:**
- Modify: `aisec/constants.go`
- Modify: `aisec/redteam/models.go`
- Modify: `aisec/redteam/client.go`
- Modify: `aisec/redteam/client_test.go`

- [ ] **Step 1: Write the failing test**

Add to `client_test.go`:

```go
func TestGetRegistryCredentials(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/v1/registry-credentials") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(RegistryCredentials{Token: "tok-123", Expiry: "2026-04-01T00:00:00Z"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.GetRegistryCredentials(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Token != "tok-123" {
		t.Errorf("Token = %q", resp.Token)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v ./aisec/redteam/ -run TestGetRegistryCredentials`
Expected: FAIL — type and method don't exist

- [ ] **Step 3: Add model struct**

Add to `aisec/redteam/models.go`:

```go
// RegistryCredentials is the response from the registry credentials endpoint.
type RegistryCredentials struct {
	Token  string `json:"token"`
	Expiry string `json:"expiry"`
}
```

- [ ] **Step 4: Add path constant**

In `aisec/constants.go`, add:
```go
	RedTeamRegistryCredentialsPath = "/v1/registry-credentials"
```

- [ ] **Step 5: Add client method**

In `aisec/redteam/client.go`, add after `GetTargetTemplates`:

```go
// GetRegistryCredentials gets or creates registry credentials from the mgmt plane.
func (c *Client) GetRegistryCredentials(ctx context.Context) (*RegistryCredentials, error) {
	resp, err := internal.DoMgmtRequest[RegistryCredentials](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.RedTeamRegistryCredentialsPath,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `go test -v ./aisec/redteam/ -run TestGetRegistryCredentials`
Expected: PASS

- [ ] **Step 7: Run full test suite**

Run: `make check`
Expected: All checks pass

- [ ] **Step 8: Commit**

```bash
git add aisec/constants.go aisec/redteam/models.go aisec/redteam/client.go aisec/redteam/client_test.go
git commit -m "feat(redteam): add GetRegistryCredentials endpoint"
```

---

### Task 14: Add CSV Upload/Download for custom prompts

**Files:**
- Modify: `aisec/constants.go`
- Modify: `aisec/redteam/client.go` (add 2 methods with manual HTTP)
- Modify: `aisec/redteam/client_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `client_test.go`:

```go
func TestCustomAttacks_UploadPromptsCsv(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/v1/custom-attack/upload-custom-prompts-csv") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.URL.Query().Get("prompt_set_uuid") != "ps-1" {
			t.Errorf("prompt_set_uuid = %q", r.URL.Query().Get("prompt_set_uuid"))
		}
		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "multipart/form-data") {
			t.Errorf("Content-Type = %q, want multipart/form-data", ct)
		}
		_ = json.NewEncoder(w).Encode(BaseResponse{Message: "uploaded", Status: 201})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	csvData := strings.NewReader("prompt,goal\nhello,test\n")
	resp, err := client.CustomAttacks.UploadPromptsCsv(context.Background(), "ps-1", csvData, "prompts.csv")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Message != "uploaded" {
		t.Errorf("Message = %q", resp.Message)
	}
}

func TestCustomAttacks_DownloadTemplate(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/v1/custom-attack/download-template/ps-1") {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte("prompt,goal\n"))
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	data, err := client.CustomAttacks.DownloadTemplate(context.Background(), "ps-1")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "prompt,goal\n" {
		t.Errorf("data = %q", string(data))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v ./aisec/redteam/ -run "TestCustomAttacks_UploadPromptsCsv|TestCustomAttacks_DownloadTemplate"`
Expected: FAIL — methods don't exist

- [ ] **Step 3: Add path constants**

In `aisec/constants.go`, add:
```go
	RedTeamUploadPromptsCsvPath = "/v1/custom-attack/upload-custom-prompts-csv"
	RedTeamDownloadTemplatePath = "/v1/custom-attack/download-template"
```

- [ ] **Step 4: Add UploadPromptsCsv method**

In `aisec/redteam/client.go`, add `"mime/multipart"` to the imports. Then add after the `CreatePropertyValue` method:

```go
// UploadPromptsCsv uploads a CSV file of prompts to a prompt set.
func (c *CustomAttacksClient) UploadPromptsCsv(ctx context.Context, promptSetUUID string, file io.Reader, filename string) (*BaseResponse, error) {
	svcCfg := c.mgmtCfg

	u, err := url.Parse(svcCfg.BaseURL + aisec.RedTeamUploadPromptsCsvPath)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	q := u.Query()
	q.Set("prompt_set_uuid", promptSetUUID)
	u.RawQuery = q.Encode()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %w", err)
	}
	if _, err := io.Copy(part, file); err != nil {
		return nil, fmt.Errorf("failed to copy file data: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close multipart writer: %w", err)
	}

	resp, err := internal.ExecuteWithRetry(internal.RetryOptions{
		MaxRetries: svcCfg.NumRetries,
		Execute: func(attempt int) (*http.Response, error) {
			token, tokenErr := svcCfg.OAuth.GetToken()
			if tokenErr != nil {
				return nil, tokenErr
			}
			req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body.Bytes()))
			if reqErr != nil {
				return nil, reqErr
			}
			req.Header.Set("Content-Type", writer.FormDataContentType())
			req.Header.Set("User-Agent", aisec.UserAgent)
			req.Header.Set(aisec.HeaderAuthToken, aisec.Bearer+token)
			return http.DefaultClient.Do(req)
		},
		OnRetryableFailure: func(resp *http.Response, attempt int) (bool, error) {
			if resp.StatusCode == 401 || resp.StatusCode == 403 {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				svcCfg.OAuth.ClearToken()
				return true, nil
			}
			return false, nil
		},
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	var result BaseResponse
	if len(respBody) > 0 {
		_ = json.Unmarshal(respBody, &result)
	}
	return &result, nil
}
```

- [ ] **Step 5: Add DownloadTemplate method**

Add after `UploadPromptsCsv`:

```go
// DownloadTemplate downloads the CSV template for a prompt set.
func (c *CustomAttacksClient) DownloadTemplate(ctx context.Context, promptSetUUID string) ([]byte, error) {
	svcCfg := c.mgmtCfg
	path := aisec.RedTeamDownloadTemplatePath + "/" + promptSetUUID

	u, err := url.Parse(svcCfg.BaseURL + path)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %s%s: %w", svcCfg.BaseURL, path, err)
	}

	resp, err := internal.ExecuteWithRetry(internal.RetryOptions{
		MaxRetries: svcCfg.NumRetries,
		Execute: func(attempt int) (*http.Response, error) {
			token, tokenErr := svcCfg.OAuth.GetToken()
			if tokenErr != nil {
				return nil, tokenErr
			}
			req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
			if reqErr != nil {
				return nil, reqErr
			}
			req.Header.Set("User-Agent", aisec.UserAgent)
			req.Header.Set(aisec.HeaderAuthToken, aisec.Bearer+token)
			return http.DefaultClient.Do(req)
		},
		OnRetryableFailure: func(resp *http.Response, attempt int) (bool, error) {
			if resp.StatusCode == 401 || resp.StatusCode == 403 {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				svcCfg.OAuth.ClearToken()
				return true, nil
			}
			return false, nil
		},
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read template body: %w", err)
	}
	return buf.Bytes(), nil
}
```

- [ ] **Step 6: Add necessary imports**

Ensure `client.go` imports include `"encoding/json"`, `"mime/multipart"`, and `"io"` (some may already be present).

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test -v ./aisec/redteam/ -run "TestCustomAttacks_UploadPromptsCsv|TestCustomAttacks_DownloadTemplate"`
Expected: PASS

- [ ] **Step 8: Run full test suite**

Run: `make check`
Expected: All checks pass

- [ ] **Step 9: Commit**

```bash
git add aisec/constants.go aisec/redteam/client.go aisec/redteam/client_test.go
git commit -m "feat(redteam): add CSV upload/download for custom prompts"
```

---

## Phase 4: Cleanup

### Task 15: Split models.go into domain files

**Files:**
- Delete: `aisec/redteam/models.go`
- Create: `aisec/redteam/models_enums.go`
- Create: `aisec/redteam/models_target.go`
- Create: `aisec/redteam/models_scan.go`
- Create: `aisec/redteam/models_custom_attack.go`
- Create: `aisec/redteam/models_dashboard.go`
- Create: `aisec/redteam/models_eula.go`
- Create: `aisec/redteam/models_instance.go`

This is a pure refactor. All types stay in package `redteam`. No behavioral changes.

- [ ] **Step 1: Create models_enums.go**

Move all `type X string` enum definitions and their `const` blocks from `models.go` into `models_enums.go`. This includes: `JobType`, `JobStatus`, `TargetType`, `TargetStatus`, `TargetConnectionType`, `APIEndpointType`, `RedTeamCategory`, `RiskRating`, `ResponseMode`, `GoalType`, `FileFormat`, `AttackStatus`, `AttackType`, `AuthType`, `AuthConfigType`, `BasicAuthLocation`, `BrandSubCategory`, `ComplianceSubCategory`, `SafetySubCategory`, `SecuritySubCategory`, `ErrorSource`, `ErrorTypeEnum`, `ProfilingStatus`, `StreamType`, `PolicyType`, `GuardrailAction`, `DateRangeFilter`, `CountedQuotaEnum`.

File starts with `package redteam`.

- [ ] **Step 2: Create models_target.go**

Move target-related structs: `TargetCreateRequest`, `TargetUpdateRequest`, `TargetContextUpdate`, `TargetResponse`, `TargetListItem`, `TargetList`, `TargetProbeRequest`, `TargetProfileResponse`, `TargetAuthValidationRequest`, `TargetAuthValidationResponse`, `TargetMetadata`, `TargetBackground`, `TargetAdditionalContext`, `OtherDetails`, `HeadersAuthConfig`, `BasicAuthAuthConfig`, `OAuth2AuthConfig`.

- [ ] **Step 3: Create models_scan.go**

Move scan/report structs: `RedTeamPagination`, `TargetJobRequest`, `JobCreateRequest`, `JobTargetResponse`, `JobResponse`, `JobListResponse`, `JobAbortResponse`, `CategoryModel`, `SubCategory`, `SeverityReport`, `CategoryReport`, `StaticJobReport`, `DynamicJobReport`, `ReportDownloadResponse`, `AttackListItem`, `AttackListResponse`, `AttackDetailResponse`, `AttackMultiTurnDetailResponse`, `RemediationResponse`, `RuntimePolicyConfigResponse`, `GoalListResponse`, `Goal`, `StreamListResponse`, `StreamDetailResponse`.

- [ ] **Step 4: Create models_custom_attack.go**

Move custom attack structs: `CustomPromptSetCreateRequest`, `CustomPromptSetUpdateRequest`, `CustomPromptSetArchiveRequest`, `CustomPromptSetResponse`, `CustomPromptSetList`, `CustomPromptSetListActive`, `CustomPromptSetReference`, `CustomPromptSetVersionInfo`, `CustomPromptCreateRequest`, `CustomPromptUpdateRequest`, `CustomPromptResponse`, `CustomPromptList`, `PropertyNamesListResponse`, `PropertyNameCreateRequest`, `PropertyValueCreateRequest`, `PropertyValuesResponse`, `PropertyValuesMultipleResponse`, `PropertyAssignment`, `PropertyStatistic`, `CustomAttackReportResponse`, `PromptSetsReportResponse`, `PromptDetailResponse`, `CustomAttacksListResponse`, `CustomAttackOutput`.

- [ ] **Step 5: Create models_dashboard.go**

Move dashboard/stats structs: `CountByName`, `RiskLevel`, `ScanStatisticsResponse`, `ScoreTrendSeries`, `ScoreTrendResponse`, `QuotaDetails`, `QuotaSummary`, `ErrorLog`, `ErrorLogListResponse`, `SentimentRequest`, `SentimentResponse`, `DashboardOverviewResponse`, `BaseResponse`, `RegistryCredentials`.

Also move all `ListOpts` types: `ListOpts`, `ScanListOpts`, `AttackListOpts`, `GoalListOpts`, `TargetListOpts`, `PromptSetListOpts`, `PromptListOpts`, `PromptsBySetListOpts`, `CustomAttacksReportListOpts`.

- [ ] **Step 6: Create models_eula.go**

Move EULA structs: `EulaContentResponse`, `EulaResponse`, `EulaAcceptRequest`.

- [ ] **Step 7: Create models_instance.go**

Move instance/device structs: `InstanceRequest`, `InstanceResponse`, `InstanceGetResponse`, `InstanceExtraDetails`, `InstanceDPMetadata`, `DeploymentProfileRequest`, `DeploymentProfileAttribute`, `DeviceRequest`, `DeviceInstance`, `Device`, `DeviceLicense`, `DeviceResponse`, `DeviceStatus`.

- [ ] **Step 8: Delete models.go**

Remove the original `aisec/redteam/models.go`.

- [ ] **Step 9: Run full test suite**

Run: `make check`
Expected: All checks pass — pure refactor, no behavioral changes

- [ ] **Step 10: Commit**

```bash
git add aisec/redteam/models_enums.go aisec/redteam/models_target.go aisec/redteam/models_scan.go aisec/redteam/models_custom_attack.go aisec/redteam/models_dashboard.go aisec/redteam/models_eula.go aisec/redteam/models_instance.go
git rm aisec/redteam/models.go
git commit -m "refactor(redteam): split models.go into domain files"
```

---

### Task 16: Update specs/redteam-mgmt.yaml

**Files:**
- Modify: `specs/redteam-mgmt.yaml`

- [ ] **Step 1: Replace spec file with updated content**

Copy `~/Downloads/mp_ws_openapi.json` to `specs/redteam-mgmt.json` and remove the old YAML file. Or convert to YAML if preferred — but since the source is JSON, keeping it as JSON avoids conversion errors.

```bash
cp ~/Downloads/mp_ws_openapi.json specs/redteam-mgmt.json
git rm specs/redteam-mgmt.yaml
```

- [ ] **Step 2: Verify the file is valid JSON**

Run: `python3 -c "import json; json.load(open('specs/redteam-mgmt.json'))"`
Expected: No output (success)

- [ ] **Step 3: Commit**

```bash
git add specs/redteam-mgmt.json
git commit -m "chore: update redteam mgmt-plane spec to latest OpenAPI"
```
