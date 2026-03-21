//go:build integration

package scan

import (
	"context"
	"os"
	"testing"

	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal/testutil"
)

func TestIntegration_SyncScan(t *testing.T) {
	testutil.LoadProjectEnv(t)
	testutil.RequireEnv(t, "PANW_AI_SEC_API_KEY", "PANW_AI_SEC_PROFILE_NAME")

	cfg := aisec.NewConfig(aisec.WithAPIKey(os.Getenv("PANW_AI_SEC_API_KEY")))
	scanner := NewScanner(cfg)

	content, err := NewContent(ContentOpts{
		Prompt:   "What is the capital of France?",
		Response: "The capital of France is Paris.",
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := scanner.SyncScan(context.Background(), AiProfile{
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
	testutil.LoadProjectEnv(t)
	testutil.RequireEnv(t, "PANW_AI_SEC_API_KEY", "PANW_AI_SEC_PROFILE_NAME")

	cfg := aisec.NewConfig(aisec.WithAPIKey(os.Getenv("PANW_AI_SEC_API_KEY")))
	scanner := NewScanner(cfg)

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

	resp, err := scanner.AsyncScan(context.Background(), objects)
	if err != nil {
		t.Fatal(err)
	}

	if resp.ScanID == "" {
		t.Error("expected non-empty ScanID")
	}

	t.Logf("AsyncScan scanID=%s reportID=%s", resp.ScanID, resp.ReportID)
}
