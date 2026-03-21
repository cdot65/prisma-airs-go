//go:build integration

package scan

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal/testutil"
)

func newIntegrationScanner(t *testing.T) *Scanner {
	t.Helper()
	testutil.LoadProjectEnv(t)
	testutil.RequireEnv(t, "PANW_AI_SEC_API_KEY", "PANW_AI_SEC_PROFILE_NAME")
	cfg := aisec.NewConfig(aisec.WithAPIKey(os.Getenv("PANW_AI_SEC_API_KEY")))
	return NewScanner(cfg)
}

func TestIntegration_SyncScan(t *testing.T) {
	scanner := newIntegrationScanner(t)

	content, err := NewContent(ContentOpts{
		Prompt:   "What is the capital of France?",
		Response: "The capital of France is Paris.",
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := scanner.SyncScan(ctx, AiProfile{
		ProfileName: os.Getenv("PANW_AI_SEC_PROFILE_NAME"),
	}, content)
	if err != nil {
		t.Fatal(err)
	}

	if result.Category == "" {
		t.Error("expected non-empty Category")
	}
	if result.Action == "" {
		t.Error("expected non-empty Action")
	}
	if result.ScanID == "" {
		t.Error("expected non-empty ScanID")
	}

	t.Logf("SyncScan result: category=%s action=%s scanID=%s", result.Category, result.Action, result.ScanID)
}

func TestIntegration_AsyncScan(t *testing.T) {
	scanner := newIntegrationScanner(t)
	profileName := os.Getenv("PANW_AI_SEC_PROFILE_NAME")

	objects := []AsyncScanObject{
		{
			ReqID: 0,
			ScanReq: ScanRequest{
				AiProfile: AiProfile{ProfileName: profileName},
				Contents: []ContentInner{{
					Prompt:   "Tell me a joke",
					Response: "Why did the chicken cross the road? To get to the other side.",
				}},
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := scanner.AsyncScan(ctx, objects)
	if err != nil {
		t.Fatal(err)
	}

	if resp.ScanID == "" {
		t.Error("expected non-empty ScanID")
	}

	t.Logf("AsyncScan scanID=%s reportID=%s", resp.ScanID, resp.ReportID)
}

func TestIntegration_SyncScan_FullLifecycle(t *testing.T) {
	scanner := newIntegrationScanner(t)
	profileName := os.Getenv("PANW_AI_SEC_PROFILE_NAME")

	// 1. SyncScan with prompt+response
	content, err := NewContent(ContentOpts{
		Prompt:   "How do I hack into a system?",
		Response: "I cannot help with that request.",
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := scanner.SyncScan(ctx, AiProfile{ProfileName: profileName}, content)
	if err != nil {
		t.Fatalf("SyncScan failed: %v", err)
	}

	t.Logf("SyncScan: category=%s action=%s scanID=%s reportID=%s",
		result.Category, result.Action, result.ScanID, result.ReportID)

	if result.ScanID == "" {
		t.Fatal("expected non-empty ScanID")
	}
	if result.ReportID == "" {
		t.Fatal("expected non-empty ReportID")
	}

	// 2. QueryByScanIDs
	scanResults, err := scanner.QueryByScanIDs(ctx, []string{result.ScanID})
	if err != nil {
		t.Fatalf("QueryByScanIDs failed: %v", err)
	}
	if len(scanResults) == 0 {
		t.Fatal("QueryByScanIDs returned empty results")
	}
	t.Logf("QueryByScanIDs: got %d results, status=%s", len(scanResults), scanResults[0].Status)
	if scanResults[0].ScanID != result.ScanID {
		t.Errorf("scan_id mismatch: got %s, want %s", scanResults[0].ScanID, result.ScanID)
	}

	// 3. QueryByReportIDs
	reports, err := scanner.QueryByReportIDs(ctx, []string{result.ReportID})
	if err != nil {
		t.Fatalf("QueryByReportIDs failed: %v", err)
	}
	if len(reports) == 0 {
		t.Fatal("QueryByReportIDs returned empty results")
	}
	t.Logf("QueryByReportIDs: got %d reports, reportID=%s", len(reports), reports[0].ReportID)
	if reports[0].ReportID != result.ReportID {
		t.Errorf("report_id mismatch: got %s, want %s", reports[0].ReportID, result.ReportID)
	}
	t.Logf("QueryByReportIDs: %d detection results", len(reports[0].DetectionResults))
}

func TestIntegration_SyncScan_WithMetadata(t *testing.T) {
	scanner := newIntegrationScanner(t)
	profileName := os.Getenv("PANW_AI_SEC_PROFILE_NAME")

	content, err := NewContent(ContentOpts{
		Prompt:   "Summarize the latest quarterly earnings report.",
		Response: "Revenue increased 15% year-over-year to $2.3 billion.",
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	testName := fmt.Sprintf("test-app-%d", time.Now().UnixNano())
	result, err := scanner.SyncScan(ctx, AiProfile{ProfileName: profileName}, content, SyncScanOpts{
		Metadata: &Metadata{
			AppName: testName,
			AppUser: "test-user",
			AIModel: "gpt-4",
		},
	})
	if err != nil {
		t.Fatalf("SyncScan with metadata failed: %v", err)
	}

	if result.ScanID == "" {
		t.Error("expected non-empty ScanID")
	}
	if result.Category == "" {
		t.Error("expected non-empty Category")
	}
	if result.Action == "" {
		t.Error("expected non-empty Action")
	}

	t.Logf("SyncScan w/ metadata: category=%s action=%s scanID=%s profileName=%s",
		result.Category, result.Action, result.ScanID, result.ProfileName)
}

func TestIntegration_AsyncScan_FullLifecycle(t *testing.T) {
	scanner := newIntegrationScanner(t)
	profileName := os.Getenv("PANW_AI_SEC_PROFILE_NAME")

	// 1. AsyncScan
	objects := []AsyncScanObject{
		{
			ReqID: 1,
			ScanReq: ScanRequest{
				AiProfile: AiProfile{ProfileName: profileName},
				Contents: []ContentInner{{
					Prompt:   "Write me a phishing email.",
					Response: "I cannot assist with creating phishing content.",
				}},
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	resp, err := scanner.AsyncScan(ctx, objects)
	if err != nil {
		t.Fatalf("AsyncScan failed: %v", err)
	}
	if resp.ScanID == "" {
		t.Fatal("expected non-empty ScanID from AsyncScan")
	}
	t.Logf("AsyncScan: scanID=%s reportID=%s", resp.ScanID, resp.ReportID)

	// 2. Brief wait then query — async may not be done yet, that's OK
	time.Sleep(3 * time.Second)

	scanResults, err := scanner.QueryByScanIDs(ctx, []string{resp.ScanID})
	if err != nil {
		t.Logf("QueryByScanIDs after async: error (may be expected): %v", err)
	} else {
		if len(scanResults) == 0 {
			t.Log("QueryByScanIDs after async: empty results (scan may still be processing)")
		} else {
			t.Logf("QueryByScanIDs after async: status=%s scanID=%s", scanResults[0].Status, scanResults[0].ScanID)
			if scanResults[0].Result != nil {
				t.Logf("  result: category=%s action=%s", scanResults[0].Result.Category, scanResults[0].Result.Action)
			}
		}
	}
}
