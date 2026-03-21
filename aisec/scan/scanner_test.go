package scan

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
