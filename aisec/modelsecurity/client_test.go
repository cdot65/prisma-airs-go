package modelsecurity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func intPtr(n int) *int { return &n }

// newTestServers creates mock token + API servers for model security tests.
func newTestServers(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *httptest.Server) {
	t.Helper()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	}))

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			t.Errorf("missing Bearer auth: %q", auth)
			w.WriteHeader(401)
			return
		}
		handler(w, r)
	}))

	return tokenServer, apiServer
}

func newTestClient(t *testing.T, tokenURL, dataURL, mgmtURL string) *Client {
	t.Helper()
	client, err := NewClient(Opts{
		ClientID:      "test-id",
		ClientSecret:  "test-secret",
		TsgID:         "123",
		DataEndpoint:  dataURL,
		MgmtEndpoint:  mgmtURL,
		TokenEndpoint: tokenURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestScans_Create(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/v1/scans") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(ScanBaseResponse{UUID: "scan-1", ModelURI: "hf://test/model"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	scan, err := client.Scans.Create(context.Background(), ScanCreateRequest{
		ModelURI:          "hf://test/model",
		SecurityGroupUUID: "550e8400-e29b-41d4-a716-446655440000",
		ScanOrigin:        ScanOriginModelSecuritySDK,
	})
	if err != nil {
		t.Fatal(err)
	}
	if scan.UUID != "scan-1" {
		t.Errorf("UUID = %q", scan.UUID)
	}
}

func TestScans_List(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(ScanList{
			Items:    []ScanBaseResponse{{UUID: "scan-1"}},
			Metadata: PaginationMeta{TotalItems: intPtr(1)},
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Scans.List(context.Background(), ScanListOpts{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 1 {
		t.Errorf("items = %d", len(resp.Items))
	}
}

func TestScans_Get(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ScanBaseResponse{UUID: "scan-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	scan, err := client.Scans.Get(context.Background(), "550e8400-e29b-41d4-a716-446655440000")
	if err != nil {
		t.Fatal(err)
	}
	if scan.UUID != "scan-1" {
		t.Errorf("UUID = %q", scan.UUID)
	}
}

func TestScans_GetInvalidUUID(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	_, err := client.Scans.Get(context.Background(), "not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid UUID")
	}
}

func TestScans_GetEvaluations(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/evaluations") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(RuleEvaluationList{
			Items:    []RuleEvaluationResponse{{UUID: "eval-1"}},
			Metadata: PaginationMeta{TotalItems: intPtr(1)},
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Scans.GetEvaluations(context.Background(), "550e8400-e29b-41d4-a716-446655440000", EvaluationListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 1 {
		t.Errorf("items = %d", len(resp.Items))
	}
}

func TestScans_GetFiles(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(FileList{
			Items:    []FileResponse{{UUID: "file-1"}},
			Metadata: PaginationMeta{TotalItems: intPtr(1)},
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Scans.GetFiles(context.Background(), "550e8400-e29b-41d4-a716-446655440000", FileListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 1 {
		t.Errorf("items = %d", len(resp.Items))
	}
}

func TestScans_GetViolations(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ViolationList{
			Items:    []ViolationResponse{{UUID: "viol-1"}},
			Metadata: PaginationMeta{TotalItems: intPtr(1)},
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Scans.GetViolations(context.Background(), "550e8400-e29b-41d4-a716-446655440000", ViolationListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 1 {
		t.Errorf("items = %d", len(resp.Items))
	}
}

func TestScans_AddLabels(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(LabelsResponse{Labels: []Label{{Key: "env", Value: "prod"}}})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Scans.AddLabels(context.Background(), "550e8400-e29b-41d4-a716-446655440000", LabelsCreateRequest{
		Labels: []Label{{Key: "env", Value: "prod"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Labels) != 1 || resp.Labels[0].Key != "env" || resp.Labels[0].Value != "prod" {
		t.Errorf("labels = %v", resp.Labels)
	}
}

func TestScans_SetLabels(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(LabelsResponse{Labels: []Label{{Key: "env", Value: "staging"}}})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Scans.SetLabels(context.Background(), "550e8400-e29b-41d4-a716-446655440000", LabelsCreateRequest{
		Labels: []Label{{Key: "env", Value: "staging"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Labels) != 1 || resp.Labels[0].Value != "staging" {
		t.Errorf("labels = %v", resp.Labels)
	}
}

func TestScans_GetLabelKeys(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(LabelKeyList{
			Items:    []string{"env", "team"},
			Metadata: PaginationMeta{TotalItems: intPtr(2)},
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Scans.GetLabelKeys(context.Background(), LabelListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 2 {
		t.Errorf("items = %d", len(resp.Items))
	}
}

func TestScans_GetLabelValues(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(LabelValueList{
			Items:    []string{"prod", "staging"},
			Metadata: PaginationMeta{TotalItems: intPtr(2)},
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Scans.GetLabelValues(context.Background(), "env", LabelListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 2 {
		t.Errorf("items = %d", len(resp.Items))
	}
}

func TestScans_GetEvaluation(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(RuleEvaluationResponse{UUID: "eval-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	eval, err := client.Scans.GetEvaluation(context.Background(), "550e8400-e29b-41d4-a716-446655440000")
	if err != nil {
		t.Fatal(err)
	}
	if eval.UUID != "eval-1" {
		t.Errorf("UUID = %q", eval.UUID)
	}
}

func TestScans_GetViolation(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ViolationResponse{UUID: "viol-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	v, err := client.Scans.GetViolation(context.Background(), "550e8400-e29b-41d4-a716-446655440000")
	if err != nil {
		t.Fatal(err)
	}
	if v.UUID != "viol-1" {
		t.Errorf("UUID = %q", v.UUID)
	}
}

// --- Security Groups ---

func TestSecurityGroups_Create(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(ModelSecurityGroupResponse{UUID: "sg-1", Name: "test-group"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	sg, err := client.SecurityGroups.Create(context.Background(), ModelSecurityGroupCreateRequest{Name: "test-group", SourceType: SourceTypeLocal})
	if err != nil {
		t.Fatal(err)
	}
	if sg.UUID != "sg-1" {
		t.Errorf("UUID = %q", sg.UUID)
	}
}

func TestSecurityGroups_List(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ListModelSecurityGroupsResponse{
			Items:    []ModelSecurityGroupResponse{{UUID: "sg-1"}},
			Metadata: PaginationMeta{TotalItems: intPtr(1)},
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.SecurityGroups.List(context.Background(), GroupListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 1 {
		t.Errorf("items = %d", len(resp.Items))
	}
}

func TestSecurityGroups_Get(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ModelSecurityGroupResponse{UUID: "sg-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	sg, err := client.SecurityGroups.Get(context.Background(), "550e8400-e29b-41d4-a716-446655440000")
	if err != nil {
		t.Fatal(err)
	}
	if sg.UUID != "sg-1" {
		t.Errorf("UUID = %q", sg.UUID)
	}
}

func TestSecurityGroups_Update(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(ModelSecurityGroupResponse{UUID: "sg-1", Name: "updated"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	sg, err := client.SecurityGroups.Update(context.Background(), "550e8400-e29b-41d4-a716-446655440000", ModelSecurityGroupUpdateRequest{Name: "updated"})
	if err != nil {
		t.Fatal(err)
	}
	if sg.Name != "updated" {
		t.Errorf("Name = %q", sg.Name)
	}
}

func TestSecurityGroups_Delete(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("method = %s", r.Method)
		}
		w.WriteHeader(204)
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	err := client.SecurityGroups.Delete(context.Background(), "550e8400-e29b-41d4-a716-446655440000")
	if err != nil {
		t.Fatal(err)
	}
}

func TestSecurityGroups_ListRuleInstances(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ListModelSecurityRuleInstancesResponse{
			Items:    []ModelSecurityRuleInstanceResponse{{UUID: "ri-1"}},
			Metadata: PaginationMeta{TotalItems: intPtr(1)},
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.SecurityGroups.ListRuleInstances(context.Background(), "550e8400-e29b-41d4-a716-446655440000", RuleInstanceListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 1 {
		t.Errorf("items = %d", len(resp.Items))
	}
}

func TestSecurityGroups_GetRuleInstance(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ModelSecurityRuleInstanceResponse{UUID: "ri-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	ri, err := client.SecurityGroups.GetRuleInstance(context.Background(), "550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-446655440001")
	if err != nil {
		t.Fatal(err)
	}
	if ri.UUID != "ri-1" {
		t.Errorf("UUID = %q", ri.UUID)
	}
}

func TestSecurityGroups_UpdateRuleInstance(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(ModelSecurityRuleInstanceResponse{UUID: "ri-1", State: RuleStateBlocking})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	ri, err := client.SecurityGroups.UpdateRuleInstance(context.Background(), "550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-446655440001", ModelSecurityRuleInstanceUpdateRequest{
		SecurityGroupUUID: "550e8400-e29b-41d4-a716-446655440000",
		State:             RuleStateBlocking,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ri.State != RuleStateBlocking {
		t.Errorf("State = %q", ri.State)
	}
}

// --- Security Rules (read-only) ---

func TestSecurityRules_List(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ListModelSecurityRulesResponse{
			Items:    []ModelSecurityRuleResponse{{UUID: "rule-1"}},
			Metadata: PaginationMeta{TotalItems: intPtr(1)},
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.SecurityRules.List(context.Background(), RuleListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 1 {
		t.Errorf("items = %d", len(resp.Items))
	}
}

func TestSecurityRules_Get(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ModelSecurityRuleResponse{UUID: "rule-1", Name: "test-rule"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	rule, err := client.SecurityRules.Get(context.Background(), "550e8400-e29b-41d4-a716-446655440000")
	if err != nil {
		t.Fatal(err)
	}
	if rule.UUID != "rule-1" {
		t.Errorf("UUID = %q", rule.UUID)
	}
}

// --- PyPI Auth ---

func TestGetPyPIAuth(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/v1/pypi/authenticate") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(PyPIAuthResponse{URL: "https://pypi.example.com", ExpiresAt: "2026-12-31"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	auth, err := client.GetPyPIAuth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if auth.URL != "https://pypi.example.com" {
		t.Errorf("URL = %q", auth.URL)
	}
}

// --- Client validation ---

func TestNewClient_MissingCredentials(t *testing.T) {
	_, err := NewClient(Opts{})
	if err == nil {
		t.Fatal("expected error for missing credentials")
	}
}

func TestSubClients_AllPresent(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "t", "expires_in": 3600})
	}))
	defer tokenSrv.Close()

	client := newTestClient(t, tokenSrv.URL, "https://data.example.com", "https://mgmt.example.com")
	if client.Scans == nil {
		t.Error("Scans is nil")
	}
	if client.SecurityGroups == nil {
		t.Error("SecurityGroups is nil")
	}
	if client.SecurityRules == nil {
		t.Error("SecurityRules is nil")
	}
}

// --- Dual endpoint routing ---

func TestDualEndpointRouting(t *testing.T) {
	var dataCalled, mgmtCalled bool

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "t", "expires_in": 3600})
	}))
	defer tokenSrv.Close()

	dataSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dataCalled = true
		_ = json.NewEncoder(w).Encode(ScanList{Items: []ScanBaseResponse{}, Metadata: PaginationMeta{}})
	}))
	defer dataSrv.Close()

	mgmtSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mgmtCalled = true
		_ = json.NewEncoder(w).Encode(ListModelSecurityGroupsResponse{Items: []ModelSecurityGroupResponse{}, Metadata: PaginationMeta{}})
	}))
	defer mgmtSrv.Close()

	client := newTestClient(t, tokenSrv.URL, dataSrv.URL, mgmtSrv.URL)

	_, _ = client.Scans.List(context.Background(), ScanListOpts{})
	if !dataCalled {
		t.Error("Scans.List should hit data endpoint")
	}

	_, _ = client.SecurityGroups.List(context.Background(), GroupListOpts{})
	if !mgmtCalled {
		t.Error("SecurityGroups.List should hit mgmt endpoint")
	}
}

func TestScans_DeleteLabels(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("method = %s", r.Method)
		}
		keys := r.URL.Query()["keys"]
		if len(keys) != 2 || keys[0] != "env" || keys[1] != "team" {
			t.Errorf("keys = %v", keys)
		}
		w.WriteHeader(204)
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	err := client.Scans.DeleteLabels(context.Background(), "550e8400-e29b-41d4-a716-446655440000", []string{"env", "team"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestScans_DeleteLabels_InvalidUUID(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach server")
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	err := client.Scans.DeleteLabels(context.Background(), "invalid", []string{"env"})
	if err == nil {
		t.Fatal("expected error for invalid UUID")
	}
}

// --- JSON serialization tests ---

func TestScanList_JSONTags(t *testing.T) {
	list := ScanList{
		Items:    []ScanBaseResponse{{UUID: "s1"}},
		Metadata: PaginationMeta{TotalItems: intPtr(1)},
	}
	data, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, `"scans"`) {
		t.Errorf("expected 'scans' key, got %s", s)
	}
	if !strings.Contains(s, `"pagination"`) {
		t.Errorf("expected 'pagination' key, got %s", s)
	}
	if !strings.Contains(s, `"total_items"`) {
		t.Errorf("expected 'total_items' key, got %s", s)
	}
}

func TestListResponses_JSONTags(t *testing.T) {
	tests := []struct {
		name    string
		val     any
		wantKey string
	}{
		{"RuleEvaluationList", RuleEvaluationList{Items: []RuleEvaluationResponse{{UUID: "e1"}}}, `"evaluations"`},
		{"FileList", FileList{Items: []FileResponse{{UUID: "f1"}}}, `"files"`},
		{"ViolationList", ViolationList{Items: []ViolationResponse{{UUID: "v1"}}}, `"violations"`},
		{"LabelKeyList", LabelKeyList{Items: []string{"k1"}}, `"keys"`},
		{"LabelValueList", LabelValueList{Items: []string{"v1"}}, `"values"`},
		{"SecurityGroups", ListModelSecurityGroupsResponse{Items: []ModelSecurityGroupResponse{{UUID: "sg1"}}}, `"security_groups"`},
		{"RuleInstances", ListModelSecurityRuleInstancesResponse{Items: []ModelSecurityRuleInstanceResponse{{UUID: "ri1"}}}, `"rule_instances"`},
		{"Rules", ListModelSecurityRulesResponse{Items: []ModelSecurityRuleResponse{{UUID: "r1"}}}, `"rules"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.val)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), tt.wantKey) {
				t.Errorf("expected %s key, got %s", tt.wantKey, string(data))
			}
		})
	}
}

func TestErrorCode_Constants(t *testing.T) {
	codes := []ErrorCode{
		ErrorCodeUnknownError, ErrorCodeScanError, ErrorCodeInvalidResponse,
		ErrorCodeAccessDenied, ErrorCodeMissingCredentials, ErrorCodeNoSuchKey,
		ErrorCodeNoSuchBucket, ErrorCodeInvalidBucketName, ErrorCodeInternalError,
		ErrorCodeServiceUnavailable, ErrorCodeInvalidObjectState,
		ErrorCodeUnknownRemoteServiceError, ErrorCodeUnsupportedRemoteStorage,
		ErrorCodeMissingArtifacts, ErrorCodeWorkerError, ErrorCodePolicyEvalError,
	}
	if len(codes) != 16 {
		t.Errorf("expected 16 error codes, got %d", len(codes))
	}
	if string(ErrorCodeScanError) != "SCAN_ERROR" {
		t.Errorf("ErrorCodeScanError = %q", ErrorCodeScanError)
	}
}

func TestThreatCategory_Constants(t *testing.T) {
	cats := []ThreatCategory{
		ThreatCategoryPAITARV100, ThreatCategoryPAITGGUF100, ThreatCategoryPAITGGUF101,
		ThreatCategoryPAITKERAS100, ThreatCategoryPAITKERAS101, ThreatCategoryPAITKERAS102,
		ThreatCategoryPAITJOBLIB100, ThreatCategoryPAITJOBLIB101,
		ThreatCategoryPAITPKL100, ThreatCategoryPAITPKL101,
		ThreatCategoryPAITPYTCH100, ThreatCategoryPAITPYTCH101,
		ThreatCategoryPAITEXDIR100, ThreatCategoryPAITEXDIR101,
		ThreatCategoryPAITONNX200, ThreatCategoryPAITTF200,
		ThreatCategoryPAITLMAFL300, ThreatCategoryPAITLITERT300,
		ThreatCategoryPAITLITERT301, ThreatCategoryPAITLITERT302,
		ThreatCategoryPAITKERAS300, ThreatCategoryPAITKERAS301,
		ThreatCategoryPAITTCHST300, ThreatCategoryPAITTCHST301,
		ThreatCategoryPAITTF300, ThreatCategoryPAITTF301, ThreatCategoryPAITTF302,
		ThreatCategoryPAITTMT300, ThreatCategoryPAITTMT301,
		ThreatCategoryUnapprovedFormats,
	}
	if len(cats) != 30 {
		t.Errorf("expected 30 threat categories, got %d", len(cats))
	}
	if string(ThreatCategoryPAITARV100) != "PAIT-ARV-100" {
		t.Errorf("ThreatCategoryPAITARV100 = %q", ThreatCategoryPAITARV100)
	}
}

func TestLabelsResponse_EmptyJSON(t *testing.T) {
	raw := `{}`
	var resp LabelsResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Labels != nil {
		t.Errorf("expected nil labels, got %v", resp.Labels)
	}

	// Round-trip with labels
	raw2 := `{"labels":[{"key":"env","value":"prod"}]}`
	var resp2 LabelsResponse
	if err := json.Unmarshal([]byte(raw2), &resp2); err != nil {
		t.Fatal(err)
	}
	if len(resp2.Labels) != 1 || resp2.Labels[0].Key != "env" {
		t.Errorf("labels = %v", resp2.Labels)
	}

	// Marshal empty omits labels
	data, err := json.Marshal(LabelsResponse{})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "{}" {
		t.Errorf("empty marshal = %s", string(data))
	}
}

func TestScanListOpts_NoSortBy(t *testing.T) {
	opts := ScanListOpts{Limit: 10, SortOrder: "desc"}
	params := buildScanListParams(opts)
	if _, ok := params["sort_by"]; ok {
		t.Error("sort_by should not be in params")
	}
	if params["sort_order"] != "desc" {
		t.Errorf("sort_order = %q", params["sort_order"])
	}
}

func TestBuildGroupListParams_SourceTypesAndEnabledRules(t *testing.T) {
	params := buildGroupListParams(GroupListOpts{
		SourceTypes:  []string{"LOCAL", "S3"},
		EnabledRules: []string{"rule-1", "rule-2"},
	})
	if params["source_types"] != "LOCAL,S3" {
		t.Errorf("source_types = %q", params["source_types"])
	}
	if params["enabled_rules"] != "rule-1,rule-2" {
		t.Errorf("enabled_rules = %q", params["enabled_rules"])
	}
}
