//go:build integration

package redteam

import (
	"context"
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

func TestIntegration_Scans_List(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.Scans.List(ctx, ScanListOpts{Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("RedTeam Scans: %d items", len(resp.Items))
}

func TestIntegration_Targets_List(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.Targets.List(ctx, TargetListOpts{Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Targets: %d items", len(resp.Items))
}

func TestIntegration_GetCategories(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	categories, err := client.Scans.GetCategories(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Attack categories: %d", len(categories))
}

func TestIntegration_GetQuota(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	quota, err := client.GetQuota(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Quota: %+v", quota)
}
