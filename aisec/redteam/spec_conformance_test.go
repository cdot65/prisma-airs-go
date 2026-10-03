package redteam

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// These tests pin the exact verb, path and plane of every Red Team method to
// the vendored OpenAPI specs (specs/redteam-service.yaml = data plane,
// specs/redteam-mgmt.json = management plane). The unit tests elsewhere mock
// whatever path the SDK sends, so without this a wrong path passes silently —
// which is how the data-plane report paths drifted from the spec.

type recordedRequest struct {
	Plane  string
	Method string
	Path   string // URL.EscapedPath()
	Query  string
}

type recorder struct {
	mu   sync.Mutex
	reqs []recordedRequest
}

func (r *recorder) add(rr recordedRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = append(r.reqs, rr)
}

func (r *recorder) last(t *testing.T) recordedRequest {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.reqs) == 0 {
		t.Fatal("no API request was recorded")
	}
	return r.reqs[len(r.reqs)-1]
}

func (r *recorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = nil
}

func newRecordingClient(t *testing.T) (*Client, *recorder) {
	t.Helper()
	rec := &recorder{}
	tok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "t", "expires_in": 3600, "token_type": "Bearer"})
	}))
	mk := func(plane string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			rec.add(recordedRequest{Plane: plane, Method: r.Method, Path: r.URL.EscapedPath(), Query: r.URL.RawQuery})
			_, _ = w.Write([]byte(`{}`))
		}))
	}
	data, mgmt := mk("data"), mk("mgmt")
	t.Cleanup(func() { tok.Close(); data.Close(); mgmt.Close() })
	return newTestClient(t, tok.URL, data.URL, mgmt.URL), rec
}

func TestSpecConformance_PlanesVerbsAndPaths(t *testing.T) {
	const j, a, g, s, p, u, tn = "J", "A", "G", "S", "P", "U", "T"
	ctx := context.Background()

	cases := []struct {
		name   string
		call   func(c *Client)
		plane  string
		method string
		path   string
	}{
		// ---- data plane: redteam-service.yaml ----
		{"GetScanMetadata", func(c *Client) { _, _ = c.GetScanMetadata(ctx) }, "data", "GET", "/v1/scan/scan-metadata"},
		{"GetScanStatistics", func(c *Client) { _, _ = c.GetScanStatistics(ctx, nil) }, "data", "GET", "/v1/dashboard/scan-statistics"},
		{"GetScoreTrend", func(c *Client) { _, _ = c.GetScoreTrend(ctx, u) }, "data", "GET", "/v1/dashboard/score-trend"},
		{"GetQuota", func(c *Client) { _, _ = c.GetQuota(ctx) }, "data", "GET", "/v1/metering/quota"}, // DELIBERATE spec deviation: spec says POST, live tenant returns 403 for POST and serves GET (verified 2026-10-01)
		{"GetErrorLogs", func(c *Client) { _, _ = c.GetErrorLogs(ctx, j, ListOpts{}) }, "data", "GET", "/v1/error-log/job/J"},
		{"UpdateSentiment", func(c *Client) { _, _ = c.UpdateSentiment(ctx, SentimentRequest{}) }, "data", "POST", "/v1/sentiment"},
		{"GetSentiment", func(c *Client) { _, _ = c.GetSentiment(ctx, j) }, "data", "GET", "/v1/sentiment/J"},
		{"Scans.Create", func(c *Client) { _, _ = c.Scans.Create(ctx, JobCreateRequest{}) }, "data", "POST", "/v1/scan"},
		{"Scans.List", func(c *Client) { _, _ = c.Scans.List(ctx, ScanListOpts{}) }, "data", "GET", "/v1/scan"},
		{"Scans.Get", func(c *Client) { _, _ = c.Scans.Get(ctx, j) }, "data", "GET", "/v1/scan/J"},
		{"Scans.Abort", func(c *Client) { _, _ = c.Scans.Abort(ctx, j) }, "data", "POST", "/v1/scan/J/abort"},
		{"Scans.GetCategories", func(c *Client) { _, _ = c.Scans.GetCategories(ctx) }, "data", "GET", "/v1/categories"},
		{"Reports.GetStaticReport", func(c *Client) { _, _ = c.Reports.GetStaticReport(ctx, j) }, "data", "GET", "/v1/report/static/J/report"},
		{"Reports.GetDynamicReport", func(c *Client) { _, _ = c.Reports.GetDynamicReport(ctx, j) }, "data", "GET", "/v1/report/dynamic/J/report"},
		{"Reports.ListAttacks", func(c *Client) { _, _ = c.Reports.ListAttacks(ctx, j, AttackListOpts{}) }, "data", "GET", "/v1/report/static/J/list-attacks"},
		{"Reports.GetAttackDetail", func(c *Client) { _, _ = c.Reports.GetAttackDetail(ctx, j, a) }, "data", "GET", "/v1/report/static/J/attack/A"},
		{"Reports.GetMultiTurnAttackDetail", func(c *Client) { _, _ = c.Reports.GetMultiTurnAttackDetail(ctx, j, a) }, "data", "GET", "/v1/report/static/J/attack-multi-turn/A"},
		{"Reports.GetStaticRemediation", func(c *Client) { _, _ = c.Reports.GetStaticRemediation(ctx, j) }, "data", "GET", "/v1/report/static/J/remediation"},
		{"Reports.GetStaticRuntimePolicy", func(c *Client) { _, _ = c.Reports.GetStaticRuntimePolicy(ctx, j) }, "data", "GET", "/v1/report/static/J/runtime-policy-config"},
		{"Reports.GetDynamicRemediation", func(c *Client) { _, _ = c.Reports.GetDynamicRemediation(ctx, j) }, "data", "GET", "/v1/report/dynamic/J/remediation"},
		{"Reports.GetDynamicRuntimePolicy", func(c *Client) { _, _ = c.Reports.GetDynamicRuntimePolicy(ctx, j) }, "data", "GET", "/v1/report/dynamic/J/runtime-policy-config"},
		{"Reports.ListGoals", func(c *Client) { _, _ = c.Reports.ListGoals(ctx, j, GoalListOpts{}) }, "data", "GET", "/v1/report/dynamic/J/list-goals"},
		{"Reports.ListGoalStreams", func(c *Client) { _, _ = c.Reports.ListGoalStreams(ctx, j, g, ListOpts{}) }, "data", "GET", "/v1/report/dynamic/J/goal/G/list-streams"},
		{"Reports.GetStreamDetail", func(c *Client) { _, _ = c.Reports.GetStreamDetail(ctx, s) }, "data", "GET", "/v1/report/dynamic/stream/S"},
		{"Reports.DownloadReport", func(c *Client) { _, _ = c.Reports.DownloadReport(ctx, j, FileFormatJSON) }, "data", "GET", "/v1/report/J/download"},
		{"Reports.GeneratePartialReport", func(c *Client) { _, _ = c.Reports.GeneratePartialReport(ctx, j) }, "data", "POST", "/v1/report/J/generate-partial-report"},
		{"CustomAttackReports.GetReport", func(c *Client) { _, _ = c.CustomAttackReports.GetReport(ctx, j) }, "data", "GET", "/v1/custom-attacks/report/J"},
		{"CustomAttackReports.GetPromptSets", func(c *Client) { _, _ = c.CustomAttackReports.GetPromptSets(ctx, j) }, "data", "GET", "/v1/custom-attacks/report/J/prompt-sets"},
		{"CustomAttackReports.GetPromptsBySet", func(c *Client) {
			_, _ = c.CustomAttackReports.GetPromptsBySet(ctx, j, s, PromptsBySetListOpts{})
		}, "data", "GET", "/v1/custom-attacks/report/J/prompt-set/S/prompts"},
		{"CustomAttackReports.GetPromptDetail", func(c *Client) { _, _ = c.CustomAttackReports.GetPromptDetail(ctx, j, p) }, "data", "GET", "/v1/custom-attacks/report/J/prompt/P"},
		{"CustomAttackReports.ListCustomAttacks", func(c *Client) {
			_, _ = c.CustomAttackReports.ListCustomAttacks(ctx, j, CustomAttacksReportListOpts{})
		}, "data", "GET", "/v1/custom-attacks/job/J/list-custom-attacks"},
		{"CustomAttackReports.GetAttackOutputs", func(c *Client) { _, _ = c.CustomAttackReports.GetAttackOutputs(ctx, j, a) }, "data", "GET", "/v1/custom-attacks/job/J/attack/A/list-outputs"},
		{"CustomAttackReports.GetPropertyStats", func(c *Client) { _, _ = c.CustomAttackReports.GetPropertyStats(ctx, j) }, "data", "GET", "/v1/custom-attacks/job/J/property-stats"},

		// ---- management plane: redteam-mgmt.json ----
		{"GetRegistryCredentials", func(c *Client) { _, _ = c.GetRegistryCredentials(ctx) }, "mgmt", "POST", "/v1/registry-credentials"},
		{"GetDashboardOverview", func(c *Client) { _, _ = c.GetDashboardOverview(ctx) }, "mgmt", "GET", "/v1/dashboard/overview"},
		{"GetTargetMetadata", func(c *Client) { _, _ = c.GetTargetMetadata(ctx) }, "mgmt", "GET", "/v1/template/target-metadata"},
		{"GetTargetTemplates", func(c *Client) { _, _ = c.GetTargetTemplates(ctx) }, "mgmt", "GET", "/v1/template/target-templates"},
		{"Targets.Create", func(c *Client) { _, _ = c.Targets.Create(ctx, TargetCreateRequest{}, false) }, "mgmt", "POST", "/v1/target"},
		{"Targets.List", func(c *Client) { _, _ = c.Targets.List(ctx, TargetListOpts{}) }, "mgmt", "GET", "/v1/target"},
		{"Targets.Get", func(c *Client) { _, _ = c.Targets.Get(ctx, u) }, "mgmt", "GET", "/v1/target/U"},
		{"Targets.Update", func(c *Client) { _, _ = c.Targets.Update(ctx, u, TargetUpdateRequest{}, false) }, "mgmt", "PUT", "/v1/target/U"},
		{"Targets.Delete", func(c *Client) { _, _ = c.Targets.Delete(ctx, u) }, "mgmt", "DELETE", "/v1/target/U"},
		{"Targets.Probe", func(c *Client) { _, _ = c.Targets.Probe(ctx, TargetProbeRequest{}) }, "mgmt", "POST", "/v1/target/probe"},
		{"Targets.GetProfile", func(c *Client) { _, _ = c.Targets.GetProfile(ctx, u) }, "mgmt", "GET", "/v1/target/U/profile"},
		{"Targets.UpdateProfile", func(c *Client) { _, _ = c.Targets.UpdateProfile(ctx, u, TargetContextUpdate{}) }, "mgmt", "PUT", "/v1/target/U/profile"},
		{"Targets.ValidateAuth", func(c *Client) { _, _ = c.Targets.ValidateAuth(ctx, TargetAuthValidationRequest{}) }, "mgmt", "POST", "/v1/target/validate-auth"},
		{"Eula.GetContent", func(c *Client) { _, _ = c.Eula.GetContent(ctx) }, "mgmt", "GET", "/v1/eula/content"},
		{"Eula.GetStatus", func(c *Client) { _, _ = c.Eula.GetStatus(ctx) }, "mgmt", "GET", "/v1/eula/status"},
		{"Eula.Accept", func(c *Client) { _, _ = c.Eula.Accept(ctx, EulaAcceptRequest{}) }, "mgmt", "POST", "/v1/eula/accept"},
		{"CustomAttacks.CreatePromptSet", func(c *Client) { _, _ = c.CustomAttacks.CreatePromptSet(ctx, CustomPromptSetCreateRequest{}) }, "mgmt", "POST", "/v1/custom-attack/custom-prompt-set"},
		{"CustomAttacks.ListPromptSets", func(c *Client) { _, _ = c.CustomAttacks.ListPromptSets(ctx, PromptSetListOpts{}) }, "mgmt", "GET", "/v1/custom-attack/list-custom-prompt-sets"},
		{"CustomAttacks.GetPromptSet", func(c *Client) { _, _ = c.CustomAttacks.GetPromptSet(ctx, s) }, "mgmt", "GET", "/v1/custom-attack/custom-prompt-set/S"},
		{"CustomAttacks.UpdatePromptSet", func(c *Client) { _, _ = c.CustomAttacks.UpdatePromptSet(ctx, s, CustomPromptSetUpdateRequest{}) }, "mgmt", "PUT", "/v1/custom-attack/custom-prompt-set/S"},
		{"CustomAttacks.ArchivePromptSet", func(c *Client) { _, _ = c.CustomAttacks.ArchivePromptSet(ctx, s, CustomPromptSetArchiveRequest{}) }, "mgmt", "PUT", "/v1/custom-attack/custom-prompt-set/S/archive"},
		{"CustomAttacks.GetPromptSetReference", func(c *Client) { _, _ = c.CustomAttacks.GetPromptSetReference(ctx, s) }, "mgmt", "GET", "/v1/custom-attack/custom-prompt-set/S/reference"},
		{"CustomAttacks.GetPromptSetVersionInfo", func(c *Client) { _, _ = c.CustomAttacks.GetPromptSetVersionInfo(ctx, s, "1") }, "mgmt", "GET", "/v1/custom-attack/custom-prompt-set/S/version-info"},
		{"CustomAttacks.ListActivePromptSets", func(c *Client) { _, _ = c.CustomAttacks.ListActivePromptSets(ctx) }, "mgmt", "GET", "/v1/custom-attack/active-custom-prompt-sets"},
		{"CustomAttacks.CreatePrompt", func(c *Client) { _, _ = c.CustomAttacks.CreatePrompt(ctx, CustomPromptCreateRequest{}) }, "mgmt", "POST", "/v1/custom-attack/custom-prompt-set/custom-prompt"},
		{"CustomAttacks.ListPrompts", func(c *Client) { _, _ = c.CustomAttacks.ListPrompts(ctx, s, PromptListOpts{}) }, "mgmt", "GET", "/v1/custom-attack/custom-prompt-set/S/list-custom-prompts"},
		{"CustomAttacks.GetPrompt", func(c *Client) { _, _ = c.CustomAttacks.GetPrompt(ctx, s, p) }, "mgmt", "GET", "/v1/custom-attack/custom-prompt-set/S/custom-prompt/P"},
		{"CustomAttacks.UpdatePrompt", func(c *Client) { _, _ = c.CustomAttacks.UpdatePrompt(ctx, s, p, CustomPromptUpdateRequest{}) }, "mgmt", "PUT", "/v1/custom-attack/custom-prompt-set/S/custom-prompt/P"},
		{"CustomAttacks.DeletePrompt", func(c *Client) { _, _ = c.CustomAttacks.DeletePrompt(ctx, s, p) }, "mgmt", "DELETE", "/v1/custom-attack/custom-prompt-set/S/custom-prompt/P"},
		{"CustomAttacks.GetPropertyNames", func(c *Client) { _, _ = c.CustomAttacks.GetPropertyNames(ctx) }, "mgmt", "GET", "/v1/custom-attack/property-names"},
		{"CustomAttacks.CreatePropertyName", func(c *Client) { _, _ = c.CustomAttacks.CreatePropertyName(ctx, PropertyNameCreateRequest{}) }, "mgmt", "POST", "/v1/custom-attack/property-names"},
		{"CustomAttacks.GetPropertyValues", func(c *Client) { _, _ = c.CustomAttacks.GetPropertyValues(ctx, "N") }, "mgmt", "GET", "/v1/custom-attack/property-values/N"},
		{"CustomAttacks.GetPropertyValuesMultiple", func(c *Client) { _, _ = c.CustomAttacks.GetPropertyValuesMultiple(ctx, []string{"N"}) }, "mgmt", "GET", "/v1/custom-attack/property-values"},
		{"CustomAttacks.CreatePropertyValue", func(c *Client) { _, _ = c.CustomAttacks.CreatePropertyValue(ctx, PropertyValueCreateRequest{}) }, "mgmt", "POST", "/v1/custom-attack/property-values"},
		{"CustomAttacks.UploadPromptsCsv", func(c *Client) {
			_, _ = c.CustomAttacks.UploadPromptsCsv(ctx, s, strings.NewReader("a"), "f.csv")
		}, "mgmt", "POST", "/v1/custom-attack/upload-custom-prompts-csv"},
		{"CustomAttacks.DownloadTemplate", func(c *Client) { _, _ = c.CustomAttacks.DownloadTemplate(ctx, s) }, "mgmt", "GET", "/v1/custom-attack/download-template/S"},
		{"Instances.Create", func(c *Client) { _, _ = c.Instances.Create(ctx, InstanceRequest{}) }, "mgmt", "POST", "/v1/instances"},
		{"Instances.Get", func(c *Client) { _, _ = c.Instances.Get(ctx, tn) }, "mgmt", "GET", "/v1/instances/T"},
		{"Instances.Update", func(c *Client) { _, _ = c.Instances.Update(ctx, tn, InstanceRequest{}) }, "mgmt", "PUT", "/v1/instances/T"},
		{"Instances.Delete", func(c *Client) { _, _ = c.Instances.Delete(ctx, tn) }, "mgmt", "DELETE", "/v1/instances/T"},
		{"Instances.CreateDevice", func(c *Client) { _, _ = c.Instances.CreateDevice(ctx, tn, DeviceRequest{}) }, "mgmt", "POST", "/v1/instances/T/devices"},
		{"Instances.UpdateDevice", func(c *Client) { _, _ = c.Instances.UpdateDevice(ctx, tn, DeviceRequest{}) }, "mgmt", "PATCH", "/v1/instances/T/devices"},
		{"Instances.DeleteDevice", func(c *Client) { _, _ = c.Instances.DeleteDevice(ctx, tn, "SN1") }, "mgmt", "DELETE", "/v1/instances/T/devices"},
	}

	client, rec := newRecordingClient(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec.reset()
			tc.call(client)
			got := rec.last(t)
			if got.Plane != tc.plane || got.Method != tc.method || got.Path != tc.path {
				t.Errorf("sent %s %s on the %s plane; spec says %s %s on the %s plane",
					got.Method, got.Path, got.Plane, tc.method, tc.path, tc.plane)
			}
		})
	}
}

func TestScoreTrend_SendsTargetAndDateRangeAsQueryParams(t *testing.T) {
	client, rec := newRecordingClient(t)
	_, _ = client.GetScoreTrend(context.Background(), "target-1")
	if q := rec.last(t).Query; q != "target_id=target-1" {
		t.Errorf("query = %q", q)
	}
	_, _ = client.GetScoreTrend(context.Background(), "target-1", ScoreTrendOpts{DateRange: DateRangeFilterLast7Days})
	if q := rec.last(t).Query; q != "date_range=LAST_7_DAYS&target_id=target-1" {
		t.Errorf("query = %q", q)
	}
	_, _ = client.GetScoreTrend(context.Background(), "t", ScoreTrendOpts{StartDate: "2026-01-01", EndDate: "2026-02-01"})
	if q := rec.last(t).Query; q != "end_date=2026-02-01&start_date=2026-01-01&target_id=t" {
		t.Errorf("query = %q", q)
	}
}

func TestListGoals_ForwardsPagingAndSearch(t *testing.T) {
	client, rec := newRecordingClient(t)
	_, _ = client.Reports.ListGoals(context.Background(), "J", GoalListOpts{Skip: 5, Limit: 10, Search: "x", GoalType: "BASE"})
	q := rec.last(t).Query
	for _, want := range []string{"skip=5", "limit=10", "search=x", "goal_type=BASE"} {
		if !strings.Contains(q, want) {
			t.Errorf("query %q missing %q", q, want)
		}
	}
}

// Caller-supplied identifiers must never be able to add path segments.
func TestPathSegmentsAreEscaped(t *testing.T) {
	client, rec := newRecordingClient(t)
	ctx := context.Background()

	_, _ = client.Reports.GetStaticReport(ctx, "a/../../admin")
	if got := rec.last(t).Path; got != "/v1/report/static/a%2F..%2F..%2Fadmin/report" {
		t.Errorf("path = %q", got)
	}
	_, _ = client.Targets.Get(ctx, "x?y=1#z")
	if got := rec.last(t); got.Path != "/v1/target/x%3Fy=1%23z" || got.Query != "" {
		t.Errorf("sent path %q query %q", got.Path, got.Query)
	}
	_, _ = client.Targets.Get(ctx, "..")
	if got := rec.last(t).Path; got != "/v1/target/%2E%2E" {
		t.Errorf("path = %q", got)
	}
	_, _ = client.CustomAttacks.GetPromptSet(ctx, "has space")
	if got := rec.last(t).Path; got != "/v1/custom-attack/custom-prompt-set/has%20space" {
		t.Errorf("path = %q", got)
	}
}
