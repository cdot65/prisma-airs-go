//go:build integration

package modelsecurity

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
	t.Logf("ModelSecurity Scans: %d items", len(resp.Items))
}

func TestIntegration_SecurityGroups_List(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.SecurityGroups.List(ctx, GroupListOpts{Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("SecurityGroups: %d items", len(resp.Items))
}

func TestIntegration_SecurityRules_List(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.SecurityRules.List(ctx, RuleListOpts{Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("SecurityRules: %d items", len(resp.Items))
}
