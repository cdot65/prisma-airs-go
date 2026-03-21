package modelsecurity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
		_ = json.NewEncoder(w).Encode(ScanBaseResponse{UUID: "scan-1", Name: "test-scan"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	scan, err := client.Scans.Create(context.Background(), ScanCreateRequest{
		Name:       "test-scan",
		SourceType: SourceTypeLocal,
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
			Metadata: PaginationMeta{Total: 1},
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
			Metadata: PaginationMeta{Total: 1},
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
			Metadata: PaginationMeta{Total: 1},
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
			Metadata: PaginationMeta{Total: 1},
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
		_ = json.NewEncoder(w).Encode(LabelsResponse{Labels: map[string]string{"env": "prod"}})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Scans.AddLabels(context.Background(), "550e8400-e29b-41d4-a716-446655440000", LabelsCreateRequest{
		Labels: map[string]string{"env": "prod"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Labels["env"] != "prod" {
		t.Errorf("labels = %v", resp.Labels)
	}
}

func TestScans_SetLabels(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(LabelsResponse{Labels: map[string]string{"env": "staging"}})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Scans.SetLabels(context.Background(), "550e8400-e29b-41d4-a716-446655440000", LabelsCreateRequest{
		Labels: map[string]string{"env": "staging"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Labels["env"] != "staging" {
		t.Errorf("labels = %v", resp.Labels)
	}
}

func TestScans_GetLabelKeys(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(LabelKeyList{
			Items:    []string{"env", "team"},
			Metadata: PaginationMeta{Total: 2},
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
			Metadata: PaginationMeta{Total: 2},
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
	sg, err := client.SecurityGroups.Create(context.Background(), ModelSecurityGroupCreateRequest{Name: "test-group"})
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
			Metadata: PaginationMeta{Total: 1},
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
			Metadata: PaginationMeta{Total: 1},
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
	ri, err := client.SecurityGroups.UpdateRuleInstance(context.Background(), "550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-446655440001", ModelSecurityRuleInstanceUpdateRequest{State: RuleStateBlocking})
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
			Metadata: PaginationMeta{Total: 1},
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
