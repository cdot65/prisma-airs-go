package redteam

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServers(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *httptest.Server) {
	t.Helper()
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	}))
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			t.Errorf("missing Bearer auth: %q", auth)
			w.WriteHeader(401)
			return
		}
		handler(w, r)
	}))
	return tokenSrv, apiSrv
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

func boolPtr(b bool) *bool { return &b }

// --- Scans ---

func TestScans_Create(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		var req JobCreateRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Target.UUID != "t-1" {
			t.Errorf("target.uuid = %q", req.Target.UUID)
		}
		_ = json.NewEncoder(w).Encode(JobResponse{UUID: "job-1", Name: "test-scan"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	job, err := client.Scans.Create(context.Background(), JobCreateRequest{
		Name:    "test-scan",
		Target:  TargetJobRequest{UUID: "t-1"},
		JobType: JobTypeStatic,
	})
	if err != nil {
		t.Fatal(err)
	}
	if job.UUID != "job-1" {
		t.Errorf("UUID = %q", job.UUID)
	}
}

func TestScans_List(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(JobListResponse{
			Data:       []JobResponse{{UUID: "job-1"}},
			Pagination: RedTeamPagination{Total: 1},
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Scans.List(context.Background(), ScanListOpts{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Data) != 1 {
		t.Errorf("items = %d", len(resp.Data))
	}
}

func TestScans_Get(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(JobResponse{UUID: "job-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	job, err := client.Scans.Get(context.Background(), "job-1")
	if err != nil {
		t.Fatal(err)
	}
	if job.UUID != "job-1" {
		t.Errorf("UUID = %q", job.UUID)
	}
}

func TestScans_Abort(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(JobAbortResponse{Message: "aborted"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Scans.Abort(context.Background(), "job-1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Message != "aborted" {
		t.Errorf("Message = %q", resp.Message)
	}
}

func TestScans_GetCategories(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]CategoryModel{{ID: "cat-1", Name: "Security"}})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	cats, err := client.Scans.GetCategories(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cats) != 1 {
		t.Errorf("categories = %d", len(cats))
	}
}

// --- Reports ---

func TestReports_GetStaticReport(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(StaticJobReport{ReportSummary: "job-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	rpt, err := client.Reports.GetStaticReport(context.Background(), "job-1")
	if err != nil {
		t.Fatal(err)
	}
	if rpt.ReportSummary != "job-1" {
		t.Errorf("ReportSummary = %q", rpt.ReportSummary)
	}
}

func TestReports_GetDynamicReport(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(DynamicJobReport{ReportSummary: "job-1", TotalGoals: 5})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	rpt, err := client.Reports.GetDynamicReport(context.Background(), "job-1")
	if err != nil {
		t.Fatal(err)
	}
	if rpt.ReportSummary != "job-1" {
		t.Errorf("ReportSummary = %q", rpt.ReportSummary)
	}
}

func TestReports_ListAttacks(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(AttackListResponse{
			Data:       []AttackListItem{{ID: "atk-1"}},
			Pagination: RedTeamPagination{Total: 1},
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Reports.ListAttacks(context.Background(), "job-1", AttackListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Data) != 1 {
		t.Errorf("items = %d", len(resp.Data))
	}
}

func TestReports_ListGoals(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(GoalListResponse{
			Data:       []Goal{{UUID: "goal-1"}},
			Pagination: RedTeamPagination{Total: 1},
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Reports.ListGoals(context.Background(), "job-1", GoalListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Data) != 1 {
		t.Errorf("items = %d", len(resp.Data))
	}
}

// --- Custom Attack Reports ---

func TestCustomAttackReports_GetReport(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(CustomAttackReportResponse{JobID: "job-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	rpt, err := client.CustomAttackReports.GetReport(context.Background(), "job-1")
	if err != nil {
		t.Fatal(err)
	}
	if rpt.JobID != "job-1" {
		t.Errorf("JobID = %q", rpt.JobID)
	}
}

// --- Targets ---

func TestTargets_Create(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(TargetResponse{UUID: "tgt-1", Name: "test-target"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	tgt, err := client.Targets.Create(context.Background(), TargetCreateRequest{Name: "test-target"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if tgt.UUID != "tgt-1" {
		t.Errorf("UUID = %q", tgt.UUID)
	}
}

func TestTargets_List(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(TargetList{
			Data:       []TargetListItem{{UUID: "tgt-1"}},
			Pagination: RedTeamPagination{Total: 1},
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Targets.List(context.Background(), TargetListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Data) != 1 {
		t.Errorf("items = %d", len(resp.Data))
	}
}

func TestTargets_Get(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(TargetResponse{UUID: "tgt-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	tgt, err := client.Targets.Get(context.Background(), "tgt-1")
	if err != nil {
		t.Fatal(err)
	}
	if tgt.UUID != "tgt-1" {
		t.Errorf("UUID = %q", tgt.UUID)
	}
}

func TestTargets_Update(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(TargetResponse{UUID: "tgt-1", Name: "updated"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	tgt, err := client.Targets.Update(context.Background(), "tgt-1", TargetUpdateRequest{Name: "updated"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if tgt.Name != "updated" {
		t.Errorf("Name = %q", tgt.Name)
	}
}

func TestTargets_Delete(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(BaseResponse{Message: "deleted"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Targets.Delete(context.Background(), "tgt-1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Message != "deleted" {
		t.Errorf("Message = %q", resp.Message)
	}
}

func TestTargets_Probe(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		var req TargetProbeRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Name != "probe-target" {
			t.Errorf("Name = %q", req.Name)
		}
		_ = json.NewEncoder(w).Encode(TargetResponse{UUID: "tgt-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	tgt, err := client.Targets.Probe(context.Background(), TargetProbeRequest{Name: "probe-target"})
	if err != nil {
		t.Fatal(err)
	}
	if tgt.UUID != "tgt-1" {
		t.Errorf("UUID = %q", tgt.UUID)
	}
}

func TestTargets_Probe_AllFields(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		var req TargetProbeRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Name != "full-probe" {
			t.Errorf("Name = %q", req.Name)
		}
		if req.TargetType != TargetTypeApplication {
			t.Errorf("TargetType = %q", req.TargetType)
		}
		if req.ConnectionType != TargetConnectionTypeRest {
			t.Errorf("ConnectionType = %q", req.ConnectionType)
		}
		if req.APIEndpointType != APIEndpointTypePublic {
			t.Errorf("APIEndpointType = %q", req.APIEndpointType)
		}
		if req.ResponseMode != ResponseModeRest {
			t.Errorf("ResponseMode = %q", req.ResponseMode)
		}
		if req.SessionSupported == nil || *req.SessionSupported != true {
			t.Errorf("SessionSupported = %v", req.SessionSupported)
		}
		if req.UUID != "existing-uuid" {
			t.Errorf("UUID = %q", req.UUID)
		}
		if len(req.ProbeFields) != 1 || req.ProbeFields[0] != "field1" {
			t.Errorf("ProbeFields = %v", req.ProbeFields)
		}
		_ = json.NewEncoder(w).Encode(TargetResponse{UUID: "tgt-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	sessionSupported := true
	tgt, err := client.Targets.Probe(context.Background(), TargetProbeRequest{
		Name:             "full-probe",
		Description:      "A full probe",
		TargetType:       TargetTypeApplication,
		ConnectionType:   TargetConnectionTypeRest,
		APIEndpointType:  APIEndpointTypePublic,
		ResponseMode:     ResponseModeRest,
		SessionSupported: &sessionSupported,
		ConnectionParams: map[string]any{"url": "https://example.com"},
		UUID:             "existing-uuid",
		ProbeFields:      []string{"field1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tgt.UUID != "tgt-1" {
		t.Errorf("UUID = %q", tgt.UUID)
	}
}

func TestTargets_GetProfile(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(TargetProfileResponse{TargetID: "tgt-1", TargetVersion: 1, Status: "COMPLETED"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	prof, err := client.Targets.GetProfile(context.Background(), "tgt-1")
	if err != nil {
		t.Fatal(err)
	}
	if prof.TargetID != "tgt-1" {
		t.Errorf("TargetID = %q", prof.TargetID)
	}
}

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

// --- Custom Attacks ---

func TestCustomAttacks_CreatePromptSet(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/v1/custom-attack/custom-prompt-set") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(CustomPromptSetResponse{UUID: "ps-1", Name: "test-set"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	ps, err := client.CustomAttacks.CreatePromptSet(context.Background(), CustomPromptSetCreateRequest{Name: "test-set"})
	if err != nil {
		t.Fatal(err)
	}
	if ps.UUID != "ps-1" {
		t.Errorf("UUID = %q", ps.UUID)
	}
}

func TestCustomAttacks_ListPromptSets(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/custom-attack/list-custom-prompt-sets") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(CustomPromptSetList{
			Data:       []CustomPromptSetResponse{{UUID: "ps-1"}},
			Pagination: RedTeamPagination{Total: 1},
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttacks.ListPromptSets(context.Background(), PromptSetListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Data) != 1 {
		t.Errorf("items = %d", len(resp.Data))
	}
}

func TestCustomAttacks_GetPropertyNames(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(PropertyNamesListResponse{Data: []string{"category"}})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttacks.GetPropertyNames(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Data) != 1 {
		t.Errorf("items = %d", len(resp.Data))
	}
}

// --- Convenience methods ---

func TestGetScanStatistics(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ScanStatisticsResponse{TotalScans: 10, TargetsScanned: 5})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	stats, err := client.GetScanStatistics(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if stats.TotalScans != 10 {
		t.Errorf("TotalScans = %d", stats.TotalScans)
	}
}

func TestGetQuota(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(QuotaSummary{
			Static:  QuotaDetails{Allocated: 100, Consumed: 50},
			Dynamic: QuotaDetails{Allocated: 200},
			Custom:  QuotaDetails{Allocated: 50},
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	quota, err := client.GetQuota(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if quota.Static.Allocated != 100 {
		t.Errorf("Static.Allocated = %d", quota.Static.Allocated)
	}
}

func TestGetSentiment(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(SentimentResponse{JobID: "job-1", Sentiment: "positive"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.GetSentiment(context.Background(), "job-1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Sentiment != "positive" {
		t.Errorf("Sentiment = %q", resp.Sentiment)
	}
}

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
	if client.Reports == nil {
		t.Error("Reports is nil")
	}
	if client.CustomAttackReports == nil {
		t.Error("CustomAttackReports is nil")
	}
	if client.Targets == nil {
		t.Error("Targets is nil")
	}
	if client.CustomAttacks == nil {
		t.Error("CustomAttacks is nil")
	}
	if client.Eula == nil {
		t.Error("Eula is nil")
	}
	if client.Instances == nil {
		t.Error("Instances is nil")
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
		_ = json.NewEncoder(w).Encode(JobListResponse{Data: []JobResponse{}, Pagination: RedTeamPagination{}})
	}))
	defer dataSrv.Close()

	mgmtSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mgmtCalled = true
		_ = json.NewEncoder(w).Encode(TargetList{Data: []TargetListItem{}, Pagination: RedTeamPagination{}})
	}))
	defer mgmtSrv.Close()

	client := newTestClient(t, tokenSrv.URL, dataSrv.URL, mgmtSrv.URL)

	_, _ = client.Scans.List(context.Background(), ScanListOpts{})
	if !dataCalled {
		t.Error("Scans.List should hit data endpoint")
	}

	_, _ = client.Targets.List(context.Background(), TargetListOpts{})
	if !mgmtCalled {
		t.Error("Targets.List should hit mgmt endpoint")
	}
}

// --- Reports (additional methods) ---

func TestReports_GetAttackDetail(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(AttackDetailResponse{UUID: "a-1", Category: "injection"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Reports.GetAttackDetail(context.Background(), "job-1", "a-1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.UUID != "a-1" {
		t.Errorf("UUID = %q", resp.UUID)
	}
}

func TestReports_GetMultiTurnAttackDetail(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(AttackMultiTurnDetailResponse{UUID: "a-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Reports.GetMultiTurnAttackDetail(context.Background(), "job-1", "a-1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.UUID != "a-1" {
		t.Errorf("UUID = %q", resp.UUID)
	}
}

func TestReports_GetStaticRemediation(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(RemediationResponse{JobID: "job-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Reports.GetStaticRemediation(context.Background(), "job-1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.JobID != "job-1" {
		t.Errorf("JobID = %q", resp.JobID)
	}
}

func TestReports_GetStaticRuntimePolicy(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/runtime-policy-config") {
			t.Errorf("path should contain /runtime-policy-config, got %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(RuntimePolicyConfigResponse{JobID: "job-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Reports.GetStaticRuntimePolicy(context.Background(), "job-1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.JobID != "job-1" {
		t.Errorf("JobID = %q", resp.JobID)
	}
}

func TestReports_GetDynamicRemediation(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(RemediationResponse{JobID: "job-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Reports.GetDynamicRemediation(context.Background(), "job-1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.JobID != "job-1" {
		t.Errorf("JobID = %q", resp.JobID)
	}
}

func TestReports_GetDynamicRuntimePolicy(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/runtime-policy-config") {
			t.Errorf("path should contain /runtime-policy-config, got %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(RuntimePolicyConfigResponse{JobID: "job-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Reports.GetDynamicRuntimePolicy(context.Background(), "job-1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.JobID != "job-1" {
		t.Errorf("JobID = %q", resp.JobID)
	}
}

func TestReports_ListGoalStreams(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(StreamListResponse{
			Data:       []StreamDetailResponse{{UUID: "s-1"}},
			Pagination: RedTeamPagination{Total: 1},
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Reports.ListGoalStreams(context.Background(), "job-1", "goal-1", ListOpts{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Data) != 1 {
		t.Errorf("items = %d", len(resp.Data))
	}
}

func TestReports_GetStreamDetail(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(StreamDetailResponse{UUID: "s-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.Reports.GetStreamDetail(context.Background(), "s-1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.UUID != "s-1" {
		t.Errorf("UUID = %q", resp.UUID)
	}
}

func TestReports_DownloadReport(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method = %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/v1/report/job-1/download") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.URL.Query().Get("file_format") != "JSON" {
			t.Errorf("file_format = %s", r.URL.Query().Get("file_format"))
		}
		_, _ = w.Write([]byte("fake-json-content"))
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	data, err := client.Reports.DownloadReport(context.Background(), "job-1", FileFormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "fake-json-content" {
		t.Errorf("data = %q", string(data))
	}
}

// --- CustomAttackReports (additional methods) ---

func TestCustomAttackReports_GetPromptSets(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(PromptSetsReportResponse{Data: []map[string]any{{"id": "ps-1"}}})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttackReports.GetPromptSets(context.Background(), "job-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Data) != 1 {
		t.Errorf("items = %d", len(resp.Data))
	}
}

func TestCustomAttackReports_GetPromptsBySet(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]PromptDetailResponse{{ID: "pr-1"}})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttackReports.GetPromptsBySet(context.Background(), "job-1", "ps-1", PromptsBySetListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) != 1 {
		t.Errorf("items = %d", len(resp))
	}
}

func TestCustomAttackReports_GetPromptDetail(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(PromptDetailResponse{ID: "pr-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttackReports.GetPromptDetail(context.Background(), "job-1", "pr-1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.ID != "pr-1" {
		t.Errorf("ID = %q", resp.ID)
	}
}

func TestCustomAttackReports_ListCustomAttacks(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(CustomAttacksListResponse{
			Data:       []map[string]any{{"id": "ca-1"}},
			Pagination: RedTeamPagination{Total: 1},
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttackReports.ListCustomAttacks(context.Background(), "job-1", CustomAttacksReportListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Data) != 1 {
		t.Errorf("items = %d", len(resp.Data))
	}
}

func TestCustomAttackReports_GetAttackOutputs(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]CustomAttackOutput{{ID: "out-1"}})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttackReports.GetAttackOutputs(context.Background(), "job-1", "ca-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) != 1 {
		t.Errorf("items = %d", len(resp))
	}
}

func TestCustomAttackReports_GetPropertyStats(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]PropertyStatistic{{PropertyName: "type"}})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttackReports.GetPropertyStats(context.Background(), "job-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) != 1 {
		t.Errorf("items = %d", len(resp))
	}
}

// --- Convenience methods (additional) ---

func TestGetScoreTrend(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ScoreTrendResponse{Labels: []string{"2025-01"}})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.GetScoreTrend(context.Background(), "t-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Labels) != 1 {
		t.Errorf("Labels = %v", resp.Labels)
	}
}

func TestGetErrorLogs(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ErrorLogListResponse{
			Data:       []ErrorLog{{JobID: "e-1"}},
			Pagination: RedTeamPagination{Total: 1},
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.GetErrorLogs(context.Background(), "job-1", ListOpts{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Data) != 1 {
		t.Errorf("items = %d", len(resp.Data))
	}
}

func TestUpdateSentiment(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(SentimentResponse{JobID: "job-1", Sentiment: "positive"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.UpdateSentiment(context.Background(), SentimentRequest{JobID: "job-1", Sentiment: "positive"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Sentiment != "positive" {
		t.Errorf("Sentiment = %q", resp.Sentiment)
	}
}

// --- CustomAttacks client (additional coverage) ---

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

func TestCustomAttacks_GetPromptSet(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/custom-attack/custom-prompt-set/ps-1") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(CustomPromptSetResponse{UUID: "ps-1", Name: "test"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttacks.GetPromptSet(context.Background(), "ps-1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.UUID != "ps-1" {
		t.Errorf("UUID = %q", resp.UUID)
	}
}

func TestCustomAttacks_UpdatePromptSet(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("method = %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/v1/custom-attack/custom-prompt-set/ps-1") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(CustomPromptSetResponse{UUID: "ps-1", Name: "updated"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttacks.UpdatePromptSet(context.Background(), "ps-1", CustomPromptSetUpdateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.UUID != "ps-1" {
		t.Errorf("UUID = %q", resp.UUID)
	}
}

func TestCustomAttacks_ArchivePromptSet(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("method = %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/v1/custom-attack/custom-prompt-set/ps-1/archive") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(CustomPromptSetResponse{UUID: "ps-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttacks.ArchivePromptSet(context.Background(), "ps-1", CustomPromptSetArchiveRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.UUID != "ps-1" {
		t.Errorf("UUID = %q", resp.UUID)
	}
}

func TestCustomAttacks_GetPromptSetReference(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/custom-attack/custom-prompt-set/ps-1/reference") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(CustomPromptSetReference{UUID: "ps-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttacks.GetPromptSetReference(context.Background(), "ps-1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.UUID != "ps-1" {
		t.Errorf("UUID = %q", resp.UUID)
	}
}

func TestCustomAttacks_GetPromptSetVersionInfo(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/custom-attack/custom-prompt-set/ps-1/version-info") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(CustomPromptSetVersionInfo{UUID: "ps-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttacks.GetPromptSetVersionInfo(context.Background(), "ps-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if resp.UUID != "ps-1" {
		t.Errorf("UUID = %q", resp.UUID)
	}
}

func TestCustomAttacks_GetPromptSetVersionInfoWithVersion(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/custom-attack/custom-prompt-set/ps-1/version-info") {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.URL.Query().Get("version") != "2" {
			t.Errorf("version query param = %q", r.URL.Query().Get("version"))
		}
		_ = json.NewEncoder(w).Encode(CustomPromptSetVersionInfo{UUID: "ps-1", Version: "2"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttacks.GetPromptSetVersionInfo(context.Background(), "ps-1", "2")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Version != "2" {
		t.Errorf("Version = %q", resp.Version)
	}
}

func TestCustomAttacks_ListActivePromptSets(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/custom-attack/active-custom-prompt-sets") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(CustomPromptSetListActive{
			Data: []CustomPromptSetResponse{{UUID: "ps-1"}},
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttacks.ListActivePromptSets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Data) != 1 {
		t.Errorf("items = %d", len(resp.Data))
	}
}

func TestCustomAttacks_CreatePrompt(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/v1/custom-attack/custom-prompt-set/custom-prompt") {
			t.Errorf("path = %s", r.URL.Path)
		}
		var req CustomPromptCreateRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.PromptSetID != "ps-1" {
			t.Errorf("PromptSetID = %q", req.PromptSetID)
		}
		if req.Prompt != "test prompt" {
			t.Errorf("Prompt = %q", req.Prompt)
		}
		if req.Goal != "test goal" {
			t.Errorf("Goal = %q", req.Goal)
		}
		_ = json.NewEncoder(w).Encode(CustomPromptResponse{UUID: "p-1", Prompt: "test prompt", Goal: "test goal"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttacks.CreatePrompt(context.Background(), CustomPromptCreateRequest{
		PromptSetID: "ps-1",
		Prompt:      "test prompt",
		Goal:        "test goal",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.UUID != "p-1" {
		t.Errorf("UUID = %q", resp.UUID)
	}
}

func TestCustomAttacks_ListPrompts(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/v1/custom-attack/custom-prompt-set/ps-1/list-custom-prompts") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(CustomPromptList{
			Data:       []CustomPromptResponse{{UUID: "p-1"}},
			Pagination: RedTeamPagination{Total: 1},
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttacks.ListPrompts(context.Background(), "ps-1", PromptListOpts{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Data) != 1 {
		t.Errorf("items = %d", len(resp.Data))
	}
}

func TestCustomAttacks_GetPrompt(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/v1/custom-attack/custom-prompt-set/ps-1/custom-prompt/p-1") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(CustomPromptResponse{UUID: "p-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttacks.GetPrompt(context.Background(), "ps-1", "p-1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.UUID != "p-1" {
		t.Errorf("UUID = %q", resp.UUID)
	}
}

func TestCustomAttacks_UpdatePrompt(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("method = %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/v1/custom-attack/custom-prompt-set/ps-1/custom-prompt/p-1") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(CustomPromptResponse{UUID: "p-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttacks.UpdatePrompt(context.Background(), "ps-1", "p-1", CustomPromptUpdateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.UUID != "p-1" {
		t.Errorf("UUID = %q", resp.UUID)
	}
}

func TestCustomAttacks_DeletePrompt(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("method = %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/v1/custom-attack/custom-prompt-set/ps-1/custom-prompt/p-1") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(BaseResponse{Message: "deleted"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttacks.DeletePrompt(context.Background(), "ps-1", "p-1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Message != "deleted" {
		t.Errorf("Message = %q", resp.Message)
	}
}

func TestCustomAttacks_CreatePropertyName(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(BaseResponse{Message: "created"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttacks.CreatePropertyName(context.Background(), PropertyNameCreateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Message != "created" {
		t.Errorf("Message = %q", resp.Message)
	}
}

func TestCustomAttacks_GetPropertyValues(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(PropertyValuesResponse{Values: []string{"v1", "v2"}})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttacks.GetPropertyValues(context.Background(), "category")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Values) != 2 {
		t.Errorf("values = %d", len(resp.Values))
	}
}

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

func TestCustomAttacks_CreatePropertyValue(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/v1/custom-attack/property-values") {
			t.Errorf("path = %s, want suffix /v1/custom-attack/property-values", r.URL.Path)
		}
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

// --- JSON round-trip tests ---

func TestJobCreateRequest_JSON(t *testing.T) {
	req := JobCreateRequest{
		Name:    "test-job",
		Target:  TargetJobRequest{UUID: "t-1", Version: 2},
		JobType: JobTypeStatic,
		JobMetadata: map[string]any{
			"key": "value",
		},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, `"target":{`) {
		t.Errorf("missing target object: %s", s)
	}
	if !strings.Contains(s, `"job_metadata":{`) {
		t.Errorf("missing job_metadata: %s", s)
	}
	if strings.Contains(s, `"target_id"`) {
		t.Errorf("should not contain target_id: %s", s)
	}
	if strings.Contains(s, `"metadata"`) {
		t.Errorf("should not contain metadata: %s", s)
	}
}

func TestJobResponse_JSON(t *testing.T) {
	raw := `{
		"uuid": "job-1",
		"name": "test",
		"tsg_id": "tsg-123",
		"target": {"uuid": "t-1", "name": "tgt", "version": 3},
		"job_type": "STATIC",
		"status": "COMPLETED",
		"job_metadata": {"key": "val"},
		"version": 1,
		"target_type": "APPLICATION",
		"total": 100,
		"completed": 95,
		"score": 0.85,
		"asr": 0.15
	}`
	var resp JobResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.UUID != "job-1" {
		t.Errorf("UUID = %q", resp.UUID)
	}
	if resp.TsgID != "tsg-123" {
		t.Errorf("TsgID = %q", resp.TsgID)
	}
	if resp.Target.UUID != "t-1" {
		t.Errorf("Target.UUID = %q", resp.Target.UUID)
	}
	if resp.Total != 100 {
		t.Errorf("Total = %d", resp.Total)
	}
	if resp.Completed != 95 {
		t.Errorf("Completed = %d", resp.Completed)
	}
	if resp.Score != 0.85 {
		t.Errorf("Score = %f", resp.Score)
	}
	if resp.ASR != 0.15 {
		t.Errorf("ASR = %f", resp.ASR)
	}
}

func TestCustomPromptCreateRequest_JSON(t *testing.T) {
	req := CustomPromptCreateRequest{
		PromptSetID: "ps-1",
		Prompt:      "test prompt",
		Goal:        "test goal",
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, `"prompt_set_id":"ps-1"`) {
		t.Errorf("missing prompt_set_id: %s", s)
	}
	if !strings.Contains(s, `"prompt":"test prompt"`) {
		t.Errorf("missing prompt: %s", s)
	}
	if !strings.Contains(s, `"goal":"test goal"`) {
		t.Errorf("missing goal: %s", s)
	}
	if strings.Contains(s, `"content"`) {
		t.Errorf("should not contain content: %s", s)
	}
	if strings.Contains(s, `"prompt_set_uuid"`) {
		t.Errorf("should not contain prompt_set_uuid: %s", s)
	}
}

func TestCustomPromptResponse_JSON(t *testing.T) {
	raw := `{
		"uuid": "p-1",
		"prompt_set_id": "ps-1",
		"prompt": "test",
		"goal": "a goal",
		"user_defined_goal": true,
		"detector_category": "security",
		"severity": "HIGH",
		"active": true
	}`
	var resp CustomPromptResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.UUID != "p-1" {
		t.Errorf("UUID = %q", resp.UUID)
	}
	if resp.PromptSetID != "ps-1" {
		t.Errorf("PromptSetID = %q", resp.PromptSetID)
	}
	if resp.Prompt != "test" {
		t.Errorf("Prompt = %q", resp.Prompt)
	}
	if resp.Goal != "a goal" {
		t.Errorf("Goal = %q", resp.Goal)
	}
	if !resp.UserDefinedGoal {
		t.Error("UserDefinedGoal should be true")
	}
	if resp.DetectorCategory != "security" {
		t.Errorf("DetectorCategory = %q", resp.DetectorCategory)
	}
	if resp.Severity != "HIGH" {
		t.Errorf("Severity = %q", resp.Severity)
	}
}

func TestAPIEndpointType_Constants(t *testing.T) {
	vals := []APIEndpointType{
		APIEndpointTypePublic, APIEndpointTypePrivate, APIEndpointTypeNetworkBroker,
	}
	if len(vals) != 3 {
		t.Errorf("expected 3, got %d", len(vals))
	}
	if string(APIEndpointTypePublic) != "PUBLIC" {
		t.Errorf("APIEndpointTypePublic = %q", APIEndpointTypePublic)
	}
	if string(APIEndpointTypeNetworkBroker) != "NETWORK_BROKER" {
		t.Errorf("APIEndpointTypeNetworkBroker = %q", APIEndpointTypeNetworkBroker)
	}
}

func TestFileFormat_Constants(t *testing.T) {
	vals := []FileFormat{FileFormatCSV, FileFormatJSON, FileFormatAll}
	if len(vals) != 3 {
		t.Errorf("expected 3, got %d", len(vals))
	}
	if string(FileFormatAll) != "ALL" {
		t.Errorf("FileFormatAll = %q", FileFormatAll)
	}
}

func TestTargetCreateRequest_NewFields_JSON(t *testing.T) {
	req := TargetCreateRequest{
		Name:                     "test",
		APIEndpointType:          APIEndpointTypePrivate,
		NetworkBrokerChannelUUID: "ch-uuid",
		ResponseMode:             "REST",
		SessionSupported:         true,
		ExtraInfo:                map[string]any{"key": "val"},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var decoded TargetCreateRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.APIEndpointType != APIEndpointTypePrivate {
		t.Errorf("APIEndpointType = %q", decoded.APIEndpointType)
	}
	if decoded.NetworkBrokerChannelUUID != "ch-uuid" {
		t.Errorf("NetworkBrokerChannelUUID = %q", decoded.NetworkBrokerChannelUUID)
	}
	if decoded.ResponseMode != "REST" {
		t.Errorf("ResponseMode = %q", decoded.ResponseMode)
	}
	if !decoded.SessionSupported {
		t.Error("SessionSupported should be true")
	}
	if decoded.ExtraInfo["key"] != "val" {
		t.Errorf("ExtraInfo = %v", decoded.ExtraInfo)
	}
}

func TestTargetResponse_NewFields_JSON(t *testing.T) {
	raw := `{
		"uuid": "tgt-1",
		"active": true,
		"tsg_id": "tsg-123",
		"version": 2,
		"profiling_status": "DONE",
		"api_endpoint_type": "PRIVATE",
		"response_mode": "STREAMING",
		"session_supported": true,
		"validated": true,
		"secret_version": "v1",
		"created_by_user_id": "user-1",
		"updated_by_user_id": "user-2",
		"extra_info": {"k": "v"}
	}`
	var resp TargetResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Active {
		t.Error("Active should be true")
	}
	if resp.TsgID != "tsg-123" {
		t.Errorf("TsgID = %q", resp.TsgID)
	}
	if resp.Version != 2 {
		t.Errorf("Version = %d", resp.Version)
	}
	if resp.ProfilingStatus != "DONE" {
		t.Errorf("ProfilingStatus = %q", resp.ProfilingStatus)
	}
	if resp.APIEndpointType != APIEndpointTypePrivate {
		t.Errorf("APIEndpointType = %q", resp.APIEndpointType)
	}
	if resp.ResponseMode != "STREAMING" {
		t.Errorf("ResponseMode = %q", resp.ResponseMode)
	}
	if !resp.SessionSupported {
		t.Error("SessionSupported should be true")
	}
	if !resp.Validated {
		t.Error("Validated should be true")
	}
	if resp.SecretVersion != "v1" {
		t.Errorf("SecretVersion = %q", resp.SecretVersion)
	}
	if resp.CreatedByUserID != "user-1" {
		t.Errorf("CreatedByUserID = %q", resp.CreatedByUserID)
	}
	if resp.UpdatedByUserID != "user-2" {
		t.Errorf("UpdatedByUserID = %q", resp.UpdatedByUserID)
	}
}

func TestJobResponse_NewFields_JSON(t *testing.T) {
	raw := `{
		"uuid": "job-1",
		"target_id": "tgt-1",
		"extra_info": {"k": "v"},
		"invocation_id": "inv-1",
		"created_by_user_id": "user-1"
	}`
	var resp JobResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.TargetID != "tgt-1" {
		t.Errorf("TargetID = %q", resp.TargetID)
	}
	if resp.InvocationID != "inv-1" {
		t.Errorf("InvocationID = %q", resp.InvocationID)
	}
	if resp.CreatedByUserID != "user-1" {
		t.Errorf("CreatedByUserID = %q", resp.CreatedByUserID)
	}
	if resp.ExtraInfo["k"] != "v" {
		t.Errorf("ExtraInfo = %v", resp.ExtraInfo)
	}
}

func TestJobCreateRequest_NewFields_JSON(t *testing.T) {
	v := 3
	req := JobCreateRequest{
		Name:      "test",
		Target:    TargetJobRequest{UUID: "t-1"},
		JobType:   JobTypeStatic,
		Version:   &v,
		ExtraInfo: map[string]any{"k": "v"},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var decoded JobCreateRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Version == nil || *decoded.Version != 3 {
		t.Errorf("Version = %v", decoded.Version)
	}
	if decoded.ExtraInfo["k"] != "v" {
		t.Errorf("ExtraInfo = %v", decoded.ExtraInfo)
	}
}

// --- EULA ---

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

// --- Instances ---

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

// --- CSV Upload/Download ---

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
		_ = json.NewEncoder(w).Encode(BaseResponse{Message: "uploaded"})
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
