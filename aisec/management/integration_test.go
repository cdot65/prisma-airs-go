//go:build integration

package management

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

func TestIntegration_Profiles_List(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.Profiles.List(ctx, ListOpts{Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Profiles: %d items", len(resp.Items))
}

func TestIntegration_Topics_List(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.Topics.List(ctx, ListOpts{Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Topics: %d items", len(resp.Items))
}

func TestIntegration_ApiKeys_List(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.ApiKeys.List(ctx, ListOpts{Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ApiKeys: %d items", len(resp.Items))
}

func TestIntegration_ScanLogs_List(t *testing.T) {
	// ScanLogs endpoint consistently times out (>30s). Increase timeout
	// to 2 minutes to accommodate slow API responses.
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	resp, err := client.ScanLogs.List(ctx, ScanLogListOpts{Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ScanLogs: %d items, total=%d", len(resp.Items), resp.TotalCount)
}
