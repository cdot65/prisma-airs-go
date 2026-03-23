package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdot65/prisma-airs-go/aisec"
)

func TestScanner_SyncScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/v1/scan/sync/request") {
			t.Errorf("path = %s", r.URL.Path)
		}

		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["ai_profile"] == nil {
			t.Error("missing ai_profile")
		}

		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(ScanResponse{
			ScanID:   "scan-123",
			ReportID: "rpt-123",
			Category: "benign",
			Action:   "allow",
		})
	}))
	defer server.Close()

	cfg := aisec.NewConfig(aisec.WithAPIKey("test-key"), aisec.WithEndpoint(server.URL))
	scanner := NewScanner(cfg)
	content, _ := NewContent(ContentOpts{Prompt: "hello"})

	resp, err := scanner.SyncScan(context.Background(), AiProfile{ProfileName: "test"}, content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Category != "benign" {
		t.Errorf("Category = %q", resp.Category)
	}
	if resp.ScanID != "scan-123" {
		t.Errorf("ScanID = %q", resp.ScanID)
	}
}

func TestScanner_SyncScan_TrIDTooLong(t *testing.T) {
	cfg := aisec.NewConfig(aisec.WithAPIKey("k"))
	scanner := NewScanner(cfg)
	content, _ := NewContent(ContentOpts{Prompt: "hello"})

	_, err := scanner.SyncScan(context.Background(), AiProfile{ProfileName: "test"}, content, SyncScanOpts{
		TrID: strings.Repeat("x", 101),
	})
	if err == nil {
		t.Fatal("expected error for long trId")
	}
}

func TestScanner_AsyncScan_EmptyObjects(t *testing.T) {
	cfg := aisec.NewConfig(aisec.WithAPIKey("k"))
	scanner := NewScanner(cfg)

	_, err := scanner.AsyncScan(context.Background(), []AsyncScanObject{})
	if err == nil {
		t.Fatal("expected error for empty objects")
	}
}

func TestScanner_AsyncScan_TooManyObjects(t *testing.T) {
	cfg := aisec.NewConfig(aisec.WithAPIKey("k"))
	scanner := NewScanner(cfg)

	objects := make([]AsyncScanObject, 6)
	_, err := scanner.AsyncScan(context.Background(), objects)
	if err == nil {
		t.Fatal("expected error for too many objects")
	}
}

func TestScanner_AsyncScan_WireFormat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)

		if len(body) != 1 {
			t.Fatalf("expected 1 object, got %d", len(body))
		}
		obj := body[0]

		// Verify req_id exists
		if _, ok := obj["req_id"]; !ok {
			t.Error("missing req_id in async scan object")
		}

		// Verify scan_req wrapper exists
		scanReq, ok := obj["scan_req"]
		if !ok {
			t.Error("missing scan_req wrapper in async scan object")
		}

		// Verify scan_req contains ai_profile and contents
		if sr, ok := scanReq.(map[string]any); ok {
			if sr["ai_profile"] == nil {
				t.Error("missing ai_profile in scan_req")
			}
			if sr["contents"] == nil {
				t.Error("missing contents in scan_req")
			}
		}

		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(AsyncScanResponse{
			ScanID: "async-123",
		})
	}))
	defer server.Close()

	cfg := aisec.NewConfig(aisec.WithAPIKey("k"), aisec.WithEndpoint(server.URL))
	scanner := NewScanner(cfg)

	objects := []AsyncScanObject{
		{
			ReqID: 1,
			ScanReq: ScanRequest{
				AiProfile: AiProfile{ProfileName: "test"},
				Contents:  []ContentInner{{Prompt: "hello"}},
			},
		},
	}

	resp, err := scanner.AsyncScan(context.Background(), objects)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ScanID != "async-123" {
		t.Errorf("ScanID = %q", resp.ScanID)
	}
}

func TestScanner_QueryByScanIDs_Valid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ids := r.URL.Query().Get("scan_ids")
		if ids == "" {
			t.Error("missing scan_ids param")
		}
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode([]ScanIDResult{{ScanID: "test-id", Status: "completed"}})
	}))
	defer server.Close()

	cfg := aisec.NewConfig(aisec.WithAPIKey("k"), aisec.WithEndpoint(server.URL))
	scanner := NewScanner(cfg)

	results, err := scanner.QueryByScanIDs(context.Background(), []string{"550e8400-e29b-41d4-a716-446655440000"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len = %d", len(results))
	}
}

func TestScanner_QueryByScanIDs_InvalidUUID(t *testing.T) {
	cfg := aisec.NewConfig(aisec.WithAPIKey("k"))
	scanner := NewScanner(cfg)

	_, err := scanner.QueryByScanIDs(context.Background(), []string{"not-a-uuid"})
	if err == nil {
		t.Fatal("expected error for invalid UUID")
	}
	var sdkErr *aisec.AISecSDKError
	if !errors.As(err, &sdkErr) || sdkErr.ErrorType != aisec.UserRequestPayloadError {
		t.Errorf("wrong error type: %v", err)
	}
}

func TestScanner_QueryByScanIDs_Empty(t *testing.T) {
	cfg := aisec.NewConfig(aisec.WithAPIKey("k"))
	scanner := NewScanner(cfg)

	_, err := scanner.QueryByScanIDs(context.Background(), []string{})
	if err == nil {
		t.Fatal("expected error for empty IDs")
	}
}

func TestScanner_QueryByScanIDs_TooMany(t *testing.T) {
	cfg := aisec.NewConfig(aisec.WithAPIKey("k"))
	scanner := NewScanner(cfg)

	ids := make([]string, 6)
	for i := range ids {
		ids[i] = "550e8400-e29b-41d4-a716-446655440000"
	}
	_, err := scanner.QueryByScanIDs(context.Background(), ids)
	if err == nil {
		t.Fatal("expected error for too many IDs")
	}
}

func TestScanner_QueryByReportIDs_Valid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode([]ThreatScanReport{{ReportID: "rpt-1"}})
	}))
	defer server.Close()

	cfg := aisec.NewConfig(aisec.WithAPIKey("k"), aisec.WithEndpoint(server.URL))
	scanner := NewScanner(cfg)

	reports, err := scanner.QueryByReportIDs(context.Background(), []string{"rpt-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("len = %d", len(reports))
	}
}

func TestScanner_QueryByReportIDs_Empty(t *testing.T) {
	cfg := aisec.NewConfig(aisec.WithAPIKey("k"))
	scanner := NewScanner(cfg)

	_, err := scanner.QueryByReportIDs(context.Background(), []string{})
	if err == nil {
		t.Fatal("expected error for empty IDs")
	}
}

func TestScanner_QueryByReportIDs_TooMany(t *testing.T) {
	cfg := aisec.NewConfig(aisec.WithAPIKey("k"))
	scanner := NewScanner(cfg)

	_, err := scanner.QueryByReportIDs(context.Background(), make([]string, 6))
	if err == nil {
		t.Fatal("expected error for too many IDs")
	}
}

func TestModels_JSONSerialization(t *testing.T) {
	resp := ScanResponse{
		ScanID:   "scan-1",
		ReportID: "rpt-1",
		Category: VerdictBenign,
		Action:   ActionAllow,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}

	var decoded ScanResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ScanID != "scan-1" || decoded.Category != "benign" {
		t.Errorf("decoded = %+v", decoded)
	}
}

func TestAsyncScanObject_JSONFormat(t *testing.T) {
	obj := AsyncScanObject{
		ReqID: 42,
		ScanReq: ScanRequest{
			AiProfile: AiProfile{ProfileName: "test-profile"},
			Contents:  []ContentInner{{Prompt: "hello"}},
		},
	}
	data, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded["req_id"] == nil {
		t.Error("missing req_id in JSON")
	}
	if decoded["scan_req"] == nil {
		t.Error("missing scan_req in JSON")
	}
	// Should NOT have ai_profile at top level
	if decoded["ai_profile"] != nil {
		t.Error("ai_profile should be inside scan_req, not at top level")
	}
}

func TestContentError_JSONFormat(t *testing.T) {
	ce := ContentError{
		ContentType: ContentErrorTypePrompt,
		Feature:     DetectionServiceDLP,
		Status:      ErrorStatusTimeout,
	}
	data, err := json.Marshal(ce)
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded["content_type"] != "prompt" {
		t.Errorf("content_type = %v", decoded["content_type"])
	}
	if decoded["feature"] != "dlp" {
		t.Errorf("feature = %v", decoded["feature"])
	}
	if decoded["status"] != "timeout" {
		t.Errorf("status = %v", decoded["status"])
	}
}

func TestPatternDetection_JSONFormat(t *testing.T) {
	pd := PatternDetection{
		Pattern:   "SSN",
		Locations: [][]int{{0, 11}, {20, 31}},
	}
	data, err := json.Marshal(pd)
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded["pattern"] != "SSN" {
		t.Errorf("pattern = %v", decoded["pattern"])
	}
	locs, ok := decoded["locations"].([]any)
	if !ok || len(locs) != 2 {
		t.Fatalf("locations = %v", decoded["locations"])
	}
	// Verify first location pair
	pair, ok := locs[0].([]any)
	if !ok || len(pair) != 2 {
		t.Errorf("first location pair = %v", locs[0])
	}
}

func TestIODetected_JSONFormat(t *testing.T) {
	io := IODetected{
		DetectionEntries: []ToolDetectionEntry{
			{
				ToolInvoked: "get_file",
				Detections:  &ToolDetectionFlags{DLP: true, Injection: true},
				Threats:     []string{"credential leakage"},
			},
		},
	}
	data, err := json.Marshal(io)
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	entries, ok := decoded["detection_entries"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("detection_entries = %v", decoded["detection_entries"])
	}

	// Should NOT have flat boolean fields
	if decoded["url_cats"] != nil || decoded["dlp"] != nil {
		t.Error("IODetected should not have flat boolean fields")
	}
}

func TestScanSummary_JSONFormat(t *testing.T) {
	ss := ScanSummary{
		Detections: &ToolDetectionFlags{DLP: true, MaliciousCode: true},
		Threats:    []string{"credential leakage", "context poisoning"},
	}
	data, err := json.Marshal(ss)
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded["detections"] == nil {
		t.Error("missing detections")
	}
	threats, ok := decoded["threats"].([]any)
	if !ok || len(threats) != 2 {
		t.Fatalf("threats = %v", decoded["threats"])
	}
	// Should NOT have verdict/action
	if decoded["verdict"] != nil || decoded["action"] != nil {
		t.Error("ScanSummary should not have verdict/action fields")
	}
}

func TestDetectionServiceResult_JSONFormat(t *testing.T) {
	dsr := DetectionServiceResult{
		DataType:         "prompt",
		DetectionService: "dlp",
		Verdict:          "malicious",
		Action:           "block",
		Metadata: &DSResultMetadata{
			Ecosystem: "mcp",
			Direction: "input",
		},
		ResultDetail: &DSDetailResult{
			DlpReport: &DlpReport{
				DlpReportID:    "rpt-1",
				DlpProfileName: "default",
			},
		},
	}
	data, err := json.Marshal(dsr)
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded["data_type"] != "prompt" {
		t.Errorf("data_type = %v", decoded["data_type"])
	}
	if decoded["detection_service"] != "dlp" {
		t.Errorf("detection_service = %v", decoded["detection_service"])
	}
	if decoded["metadata"] == nil {
		t.Error("missing metadata")
	}
	if decoded["result_detail"] == nil {
		t.Error("missing result_detail")
	}
}

func TestMcEntry_JSONFormat(t *testing.T) {
	entry := McEntry{FileType: "python", CodeSha256: "abc123"}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded["file_type"] != "python" {
		t.Errorf("file_type = %v", decoded["file_type"])
	}
	if decoded["code_sha256"] != "abc123" {
		t.Errorf("code_sha256 = %v", decoded["code_sha256"])
	}
	if decoded["code_type"] != nil {
		t.Error("code_type should not exist")
	}
	if decoded["verdict"] != nil {
		t.Error("verdict should not exist on McEntry")
	}
	if decoded["action"] != nil {
		t.Error("action should not exist on McEntry")
	}
}

func TestAgentEntry_JSONFormat(t *testing.T) {
	entry := AgentEntry{CategoryType: "prompt_injection", Verdict: "malicious"}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded["category_type"] != "prompt_injection" {
		t.Errorf("category_type = %v", decoded["category_type"])
	}
	if decoded["verdict"] != "malicious" {
		t.Errorf("verdict = %v", decoded["verdict"])
	}
	if decoded["pattern"] != nil {
		t.Error("pattern should not exist on AgentEntry")
	}
}

func TestUrlfEntry_JSONFormat(t *testing.T) {
	entry := UrlfEntry{
		URL:        "http://example.com",
		RiskLevel:  "high",
		Action:     "block",
		Categories: []string{"malware", "phishing"},
	}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	cats, ok := decoded["categories"].([]any)
	if !ok || len(cats) != 2 {
		t.Fatalf("categories = %v", decoded["categories"])
	}
	if cats[0] != "malware" {
		t.Errorf("categories[0] = %v", cats[0])
	}
}

func TestDlpReport_JSONFormat(t *testing.T) {
	report := DlpReport{
		DlpReportID:             "rpt-1",
		DataPatternRule1Verdict: "hit",
		DataPatternRule2Verdict: "miss",
		DataPatternDetectionOffsets: []DlpPatternDetections{
			{DataPatternID: "dp-1", Name: "SSN", HighConfidenceDetections: [][]int{{0, 11}}},
		},
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded["data_pattern_rule1_verdict"] != "hit" {
		t.Errorf("data_pattern_rule1_verdict = %v", decoded["data_pattern_rule1_verdict"])
	}
	if decoded["data_pattern_rule2_verdict"] != "miss" {
		t.Errorf("data_pattern_rule2_verdict = %v", decoded["data_pattern_rule2_verdict"])
	}
	offsets, ok := decoded["data_pattern_detection_offsets"].([]any)
	if !ok || len(offsets) != 1 {
		t.Fatalf("data_pattern_detection_offsets = %v", decoded["data_pattern_detection_offsets"])
	}
}

func TestMcReport_WithCmdInjection(t *testing.T) {
	report := McReport{
		Verdict:             "malicious",
		MalwareScriptReport: &MalwareReport{Verdict: "malicious"},
		CommandInjectionReport: []CmdEntry{
			{CodeBlock: "rm -rf /", Verdict: "malicious"},
		},
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	cmds, ok := decoded["command_injection_report"].([]any)
	if !ok || len(cmds) != 1 {
		t.Fatalf("command_injection_report = %v", decoded["command_injection_report"])
	}
	malware, ok := decoded["malware_script_report"].(map[string]any)
	if !ok {
		t.Fatal("malware_script_report should be an object")
	}
	if malware["verdict"] != "malicious" {
		t.Errorf("malware_script_report.verdict = %v", malware["verdict"])
	}
}

func TestDetectionDetails_JSONFormat(t *testing.T) {
	resp := ScanResponse{
		ScanID:   "scan-1",
		ReportID: "rpt-1",
		Category: "benign",
		Action:   "allow",
		PromptDetectionDetails: &DetectionDetails{
			TopicGuardrailsDetails: &TopicGuardRails{
				AllowedTopics: []string{"general"},
				BlockedTopics: []string{"violence"},
			},
		},
		ResponseDetectionDetails: &DetectionDetails{
			TopicGuardrailsDetails: &TopicGuardRails{
				BlockedTopics: []string{"pii"},
			},
		},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	pdd, ok := decoded["prompt_detection_details"].(map[string]any)
	if !ok {
		t.Fatal("prompt_detection_details should be an object")
	}
	tgd, ok := pdd["topic_guardrails_details"].(map[string]any)
	if !ok {
		t.Fatal("topic_guardrails_details should be an object")
	}
	allowed, ok := tgd["allowed_topics"].([]any)
	if !ok || len(allowed) != 1 || allowed[0] != "general" {
		t.Errorf("allowed_topics = %v", tgd["allowed_topics"])
	}

	rdd, ok := decoded["response_detection_details"].(map[string]any)
	if !ok {
		t.Fatal("response_detection_details should be an object")
	}
	if rdd["topic_guardrails_details"] == nil {
		t.Error("response_detection_details missing topic_guardrails_details")
	}
}

func TestToolDetected_FullRoundTrip(t *testing.T) {
	td := ToolDetected{
		Verdict: "malicious",
		Metadata: &ToolEventMetadata{
			Ecosystem:   "mcp",
			Method:      "tools/call",
			ServerName:  "test-server",
			ToolInvoked: "get_file",
		},
		Summary: &ScanSummary{
			Detections: &ToolDetectionFlags{DLP: true},
			Threats:    []string{"data leak"},
		},
		InputDetected: &IODetected{
			DetectionEntries: []ToolDetectionEntry{
				{ToolInvoked: "get_file", Threats: []string{"injection"}},
			},
		},
	}

	data, err := json.Marshal(td)
	if err != nil {
		t.Fatal(err)
	}

	var decoded ToolDetected
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Verdict != "malicious" {
		t.Errorf("Verdict = %q", decoded.Verdict)
	}
	if decoded.Summary == nil || decoded.Summary.Detections == nil || !decoded.Summary.Detections.DLP {
		t.Error("Summary.Detections.DLP should be true")
	}
	if decoded.InputDetected == nil || len(decoded.InputDetected.DetectionEntries) != 1 {
		t.Error("InputDetected should have 1 entry")
	}
}

func TestToxicContentDetails_JSON(t *testing.T) {
	j := `{"toxic_categories":["hate","violence"]}`
	var tc ToxicContentDetails
	if err := json.Unmarshal([]byte(j), &tc); err != nil {
		t.Fatal(err)
	}
	if len(tc.ToxicCategories) != 2 || tc.ToxicCategories[0] != "hate" {
		t.Errorf("ToxicCategories = %v", tc.ToxicCategories)
	}
}

func TestDetectionDetails_WithToxicContent(t *testing.T) {
	j := `{"topic_guardrails_details":{"allowed_topics":["math"]},"toxic_content_details":{"toxic_categories":["hate"]}}`
	var dd DetectionDetails
	if err := json.Unmarshal([]byte(j), &dd); err != nil {
		t.Fatal(err)
	}
	if dd.ToxicContentDetails == nil || len(dd.ToxicContentDetails.ToxicCategories) != 1 {
		t.Error("ToxicContentDetails should have 1 category")
	}
}

func TestTcReport_WithToxicCategories(t *testing.T) {
	j := `{"confidence":"high","verdict":"malicious","toxic_categories":["hate","bias"]}`
	var tc TcReport
	if err := json.Unmarshal([]byte(j), &tc); err != nil {
		t.Fatal(err)
	}
	if len(tc.ToxicCategories) != 2 {
		t.Errorf("ToxicCategories = %v", tc.ToxicCategories)
	}
}

func TestDlpPatternDetections_SpecStructure(t *testing.T) {
	j := `{"data_pattern_id":"dp-123","version":2,"name":"SSN","high_confidence_detections":[[0,9]],"medium_confidence_detections":[[10,19]],"low_confidence_detections":[]}`
	var dp DlpPatternDetections
	if err := json.Unmarshal([]byte(j), &dp); err != nil {
		t.Fatal(err)
	}
	if dp.DataPatternID != "dp-123" {
		t.Errorf("DataPatternID = %q", dp.DataPatternID)
	}
	if dp.Version != 2 {
		t.Errorf("Version = %d", dp.Version)
	}
	if dp.Name != "SSN" {
		t.Errorf("Name = %q", dp.Name)
	}
	if len(dp.HighConfidenceDetections) != 1 {
		t.Errorf("HighConfidenceDetections len = %d", len(dp.HighConfidenceDetections))
	}
}

func TestPiReport_JSON(t *testing.T) {
	j := `{"verdict":"malicious"}`
	var pi PiReport
	if err := json.Unmarshal([]byte(j), &pi); err != nil {
		t.Fatal(err)
	}
	if pi.Verdict != "malicious" {
		t.Errorf("Verdict = %q", pi.Verdict)
	}
}

func TestDlpSnippetMeta_JSON(t *testing.T) {
	j := `{"data_pattern":"SSN","confidence_level":"high","data_pattern_type":"regex","occurrence":3}`
	var m DlpSnippetMeta
	if err := json.Unmarshal([]byte(j), &m); err != nil {
		t.Fatal(err)
	}
	if m.DataPattern != "SSN" || m.ConfidenceLevel != "high" || m.Occurrence != 3 {
		t.Errorf("got %+v", m)
	}
}

func TestDlpSnippetObject_JSON(t *testing.T) {
	j := `{"meta":{"data_pattern":"SSN","confidence_level":"high","occurrence":1},"snippets":["123-45-6789"]}`
	var s DlpSnippetObject
	if err := json.Unmarshal([]byte(j), &s); err != nil {
		t.Fatal(err)
	}
	if s.Meta == nil || s.Meta.DataPattern != "SSN" {
		t.Error("Meta.DataPattern should be SSN")
	}
	if len(s.Snippets) != 1 {
		t.Errorf("Snippets len = %d", len(s.Snippets))
	}
}

func TestDSDetailResult_AllFields(t *testing.T) {
	j := `{
		"urlf_report":[],
		"dlp_report":{"dlp_report_id":"r1"},
		"dlp_snippets":{"meta":{"data_pattern":"SSN","confidence_level":"high","occurrence":1},"snippets":["xxx"]},
		"dbs_report":[],
		"dbs_snippets":["snippet1"],
		"tc_report":{"confidence":"high","verdict":"benign"},
		"tc_snippets":["toxic snippet"],
		"mc_report":{"verdict":"benign"},
		"agent_report":{"model_verdict":"benign"},
		"topic_guardrails_report":{},
		"cg_report":{},
		"pi_report":{"verdict":"benign"},
		"pi_snippets":["injection attempt"]
	}`
	var ds DSDetailResult
	if err := json.Unmarshal([]byte(j), &ds); err != nil {
		t.Fatal(err)
	}
	if ds.DlpSnippets == nil || ds.DlpSnippets.Meta.DataPattern != "SSN" {
		t.Error("DlpSnippets should have SSN pattern")
	}
	if len(ds.DbsSnippets) != 1 {
		t.Errorf("DbsSnippets len = %d", len(ds.DbsSnippets))
	}
	if len(ds.TcSnippets) != 1 {
		t.Errorf("TcSnippets len = %d", len(ds.TcSnippets))
	}
	if ds.PiReport == nil || ds.PiReport.Verdict != "benign" {
		t.Error("PiReport should be benign")
	}
	if len(ds.PiSnippets) != 1 {
		t.Errorf("PiSnippets len = %d", len(ds.PiSnippets))
	}
}
