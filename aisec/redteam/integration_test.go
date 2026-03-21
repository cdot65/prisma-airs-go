//go:build integration

package redteam

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cdot65/prisma-airs-go/aisec/internal/testutil"
)

func newIntegrationClient(t *testing.T) *Client {
	t.Helper()
	testutil.LoadProjectEnv(t)
	testutil.RequireEnv(t, "PANW_MGMT_CLIENT_ID", "PANW_MGMT_CLIENT_SECRET", "PANW_MGMT_TSG_ID")

	client, err := NewClient(Opts{})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestIntegration_Targets_CRUD(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	targetName := fmt.Sprintf("test-target-%d", time.Now().UnixNano())

	// 1. Create target
	created, err := client.Targets.Create(ctx, TargetCreateRequest{
		Name:           targetName,
		Description:    "Integration test target",
		TargetType:     TargetTypeApplication,
		ConnectionType: TargetConnectionTypeCustom,
		ConnectionParams: map[string]any{
			"url": "https://httpbin.org/post",
			"headers": map[string]any{
				"Content-Type": "application/json",
			},
			"request_json": map[string]any{
				"prompt": "{INPUT}",
			},
			"response_json": map[string]any{
				"output": "{RESPONSE}",
			},
			"response_key": "output",
		},
		APIEndpointType: APIEndpointTypePublic,
		ResponseMode:    "REST",
	}, false) // validate=false to avoid actual connectivity check
	if err != nil {
		t.Fatalf("Create target: %v", err)
	}
	t.Logf("Created target: uuid=%s name=%s status=%s", created.UUID, created.Name, created.Status)

	// Register cleanup to delete even on failure
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanCancel()
		if _, delErr := client.Targets.Delete(cleanCtx, created.UUID); delErr != nil {
			t.Logf("WARNING: cleanup delete target %s failed: %v", created.UUID, delErr)
		} else {
			t.Logf("Cleanup: deleted target %s", created.UUID)
		}
	})

	if created.UUID == "" {
		t.Fatal("Created target has empty UUID")
	}
	if created.Name != targetName {
		t.Errorf("Name mismatch: got %q want %q", created.Name, targetName)
	}

	// 2. List targets, verify new target appears
	listResp, err := client.Targets.List(ctx, TargetListOpts{Limit: 50})
	if err != nil {
		t.Fatalf("List targets: %v", err)
	}
	t.Logf("Listed %d targets", len(listResp.Items))

	found := false
	for _, tgt := range listResp.Items {
		if tgt.UUID == created.UUID {
			found = true
			break
		}
	}
	if !found {
		t.Logf("WARNING: created target %s not found in list (may be DRAFT status filtered)", created.UUID)
	}

	// 3. Get target by UUID
	got, err := client.Targets.Get(ctx, created.UUID)
	if err != nil {
		t.Fatalf("Get target: %v", err)
	}
	t.Logf("Got target: uuid=%s name=%s status=%s connectionType=%s", got.UUID, got.Name, got.Status, got.ConnectionType)

	if got.Name != targetName {
		t.Errorf("Get name mismatch: got %q want %q", got.Name, targetName)
	}

	// 4. Update target description (PUT requires full object)
	updatedDesc := "test-updated-description"
	updated, err := client.Targets.Update(ctx, created.UUID, TargetUpdateRequest{
		Name:           targetName,
		Description:    updatedDesc,
		TargetType:     TargetTypeApplication,
		ConnectionType: TargetConnectionTypeCustom,
		ConnectionParams: map[string]any{
			"url": "https://httpbin.org/post",
			"headers": map[string]any{
				"Content-Type": "application/json",
			},
			"request_json": map[string]any{
				"prompt": "{INPUT}",
			},
			"response_json": map[string]any{
				"output": "{RESPONSE}",
			},
			"response_key": "output",
		},
	}, false)
	if err != nil {
		t.Logf("WARNING: Update target: %v", err)
	} else {
		t.Logf("Updated target: uuid=%s description=%q", updated.UUID, updated.Description)
		if updated.Description != updatedDesc {
			t.Errorf("Description mismatch: got %q want %q", updated.Description, updatedDesc)
		}
	}

	// 5. Delete is handled by t.Cleanup above
	t.Log("Targets CRUD complete (delete via cleanup)")
}

func TestIntegration_Scans_Read(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.Scans.List(ctx, ScanListOpts{Limit: 5})
	if err != nil {
		t.Fatalf("List scans: %v", err)
	}
	t.Logf("RedTeam Scans: %d items", len(resp.Items))

	for i, s := range resp.Items {
		t.Logf("  Scan[%d]: uuid=%s name=%q type=%s status=%s", i, s.UUID, s.Name, s.JobType, s.Status)
	}

	// Get first scan detail if available
	if len(resp.Items) > 0 {
		first := resp.Items[0]
		got, err := client.Scans.Get(ctx, first.UUID)
		if err != nil {
			t.Logf("WARNING: Get scan %s: %v", first.UUID, err)
		} else {
			t.Logf("Scan detail: uuid=%s name=%q status=%s score=%.2f asr=%.2f", got.UUID, got.Name, got.Status, got.Score, got.ASR)
		}
	}
}

func TestIntegration_Categories_Read(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	categories, err := client.Scans.GetCategories(ctx)
	if err != nil {
		t.Fatalf("GetCategories: %v", err)
	}
	t.Logf("Attack categories: %d", len(categories))

	for i, c := range categories {
		t.Logf("  Category[%d]: id=%s name=%s subCategories=%d", i, c.ID, c.Name, len(c.SubCategories))
	}
}

func TestIntegration_DashboardOverview(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	overview, err := client.GetDashboardOverview(ctx)
	if err != nil {
		t.Fatalf("GetDashboardOverview: %v", err)
	}
	t.Logf("Dashboard overview keys: %d", len(overview.Overview))
	for k, v := range overview.Overview {
		t.Logf("  %s: %v", k, v)
	}
}

func TestIntegration_GetQuota(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	quota, err := client.GetQuota(ctx)
	if err != nil {
		t.Fatalf("GetQuota: %v", err)
	}
	t.Logf("Quota: %+v", quota)
}

func TestIntegration_Targets_List(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.Targets.List(ctx, TargetListOpts{Limit: 5})
	if err != nil {
		t.Fatalf("List targets: %v", err)
	}
	t.Logf("Targets: %d items", len(resp.Items))

	for i, tgt := range resp.Items {
		t.Logf("  Target[%d]: uuid=%s name=%q type=%s status=%s", i, tgt.UUID, tgt.Name, tgt.TargetType, tgt.Status)
	}
}
