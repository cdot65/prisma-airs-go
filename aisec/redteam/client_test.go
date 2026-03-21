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

// --- Scans ---

func TestScans_Create(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(JobResponse{ID: "job-1", Name: "test-scan"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	job, err := client.Scans.Create(context.Background(), JobCreateRequest{TargetID: "t-1", JobType: JobTypeStatic})
	if err != nil {
		t.Fatal(err)
	}
	if job.ID != "job-1" {
		t.Errorf("ID = %q", job.ID)
	}
}

func TestScans_List(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(JobListResponse{
			Items:      []JobResponse{{ID: "job-1"}},
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
	if len(resp.Items) != 1 {
		t.Errorf("items = %d", len(resp.Items))
	}
}

func TestScans_Get(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(JobResponse{ID: "job-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	job, err := client.Scans.Get(context.Background(), "job-1")
	if err != nil {
		t.Fatal(err)
	}
	if job.ID != "job-1" {
		t.Errorf("ID = %q", job.ID)
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
		_ = json.NewEncoder(w).Encode(StaticJobReport{JobID: "job-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	rpt, err := client.Reports.GetStaticReport(context.Background(), "job-1")
	if err != nil {
		t.Fatal(err)
	}
	if rpt.JobID != "job-1" {
		t.Errorf("JobID = %q", rpt.JobID)
	}
}

func TestReports_GetDynamicReport(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(DynamicJobReport{JobID: "job-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	rpt, err := client.Reports.GetDynamicReport(context.Background(), "job-1")
	if err != nil {
		t.Fatal(err)
	}
	if rpt.JobID != "job-1" {
		t.Errorf("JobID = %q", rpt.JobID)
	}
}

func TestReports_ListAttacks(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(AttackListResponse{
			Items:      []AttackListItem{{ID: "atk-1"}},
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
	if len(resp.Items) != 1 {
		t.Errorf("items = %d", len(resp.Items))
	}
}

func TestReports_ListGoals(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(GoalListResponse{
			Items:      []Goal{{ID: "goal-1"}},
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
	if len(resp.Items) != 1 {
		t.Errorf("items = %d", len(resp.Items))
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
			Items:      []TargetResponse{{UUID: "tgt-1"}},
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
	if len(resp.Items) != 1 {
		t.Errorf("items = %d", len(resp.Items))
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
		_ = json.NewEncoder(w).Encode(TargetResponse{UUID: "tgt-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	tgt, err := client.Targets.Probe(context.Background(), TargetProbeRequest{UUID: "tgt-1"})
	if err != nil {
		t.Fatal(err)
	}
	if tgt.UUID != "tgt-1" {
		t.Errorf("UUID = %q", tgt.UUID)
	}
}

func TestTargets_GetProfile(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(TargetProfileResponse{UUID: "tgt-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	prof, err := client.Targets.GetProfile(context.Background(), "tgt-1")
	if err != nil {
		t.Fatal(err)
	}
	if prof.UUID != "tgt-1" {
		t.Errorf("UUID = %q", prof.UUID)
	}
}

// --- Custom Attacks ---

func TestCustomAttacks_CreatePromptSet(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
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
		_ = json.NewEncoder(w).Encode(CustomPromptSetList{
			Items:      []CustomPromptSetResponse{{UUID: "ps-1"}},
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
	if len(resp.Items) != 1 {
		t.Errorf("items = %d", len(resp.Items))
	}
}

func TestCustomAttacks_GetPropertyNames(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(PropertyNamesListResponse{Items: []map[string]any{{"name": "category"}}})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.CustomAttacks.GetPropertyNames(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 1 {
		t.Errorf("items = %d", len(resp.Items))
	}
}

// --- Convenience methods ---

func TestGetScanStatistics(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ScanStatisticsResponse{Stats: map[string]any{"total": 10}})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	stats, err := client.GetScanStatistics(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Stats["total"] == nil {
		t.Error("missing stats")
	}
}

func TestGetQuota(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(QuotaSummary{Details: map[string]any{"used": 5}})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	quota, err := client.GetQuota(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if quota.Details["used"] == nil {
		t.Error("missing quota details")
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
		_ = json.NewEncoder(w).Encode(DashboardOverviewResponse{Overview: map[string]any{"risk": "low"}})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)
	resp, err := client.GetDashboardOverview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Overview["risk"] == nil {
		t.Error("missing overview")
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
		_ = json.NewEncoder(w).Encode(JobListResponse{Items: []JobResponse{}, Pagination: RedTeamPagination{}})
	}))
	defer dataSrv.Close()

	mgmtSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mgmtCalled = true
		_ = json.NewEncoder(w).Encode(TargetList{Items: []TargetResponse{}, Pagination: RedTeamPagination{}})
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
