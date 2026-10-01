//go:build integration

package gateway

import (
	"context"
	"github.com/cdot65/prisma-airs-go/aisec/gateway/schema"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	"github.com/cdot65/prisma-airs-go/aisec/internal/testutil"
	"testing"
	"time"
)

func newIntegrationClient(t *testing.T) (*Client, string) {
	t.Helper()
	testutil.RequireEnv(t, "PANW_MGMT_CLIENT_ID", "PANW_MGMT_CLIENT_SECRET", "PANW_MGMT_TSG_ID")
	c, err := NewClient(Opts{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := internal.DoMgmtRequest[struct {
		Data []struct {
			ID   string `json:"id"`
			Slug string `json:"slug"`
		} `json:"data"`
	}](ctx, c.adminCfg, internal.MgmtRequestOptions{Method: "GET", Path: "/workspaces"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Data.Data) == 0 {
		t.Fatal("no existing Gateway workspace")
	}
	return c, resp.Data.Data[0].ID
}
func TestIntegration_GatewayReadDiscovery(t *testing.T) {
	c, workspace := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	check := func(name string, err error) {
		t.Helper()
		if err != nil {
			t.Errorf("%s: %v", name, err)
		} else {
			t.Logf("%s: passed", name)
		}
	}
	_, err := c.Configs.List(ctx, schema.ConfigsListOptions{WorkspaceID: workspace})
	check("configs", err)
	_, err = c.Guardrails.List(ctx, schema.GuardrailsListOptions{WorkspaceID: &workspace})
	check("guardrails", err)
	_, err = c.OrgGuardrails.List(ctx, schema.OrgGuardrailsListOptions{})
	check("org_guardrails", err)
	_, err = c.Providers.List(ctx, schema.ProvidersListOptions{WorkspaceID: &workspace})
	check("providers", err)
	_, err = c.Integrations.List(ctx, schema.IntegrationsListOptions{})
	check("integrations", err)
	_, err = c.MCPIntegrations.List(ctx, schema.MCPIntegrationsListOptions{})
	check("mcp_integrations", err)
	_, err = c.MCPServers.List(ctx, schema.MCPServersListOptions{WorkspaceID: &workspace})
	check("mcp_servers", err)
	_, err = c.APIKeys.ListForKind(ctx, APIKeyService, schema.APIKeysListOptions{WorkspaceID: &workspace})
	check("service_api_keys", err)
	_, err = c.APIKeys.ListForKind(ctx, APIKeyUser, schema.APIKeysListOptions{WorkspaceID: &workspace})
	check("user_api_keys", err)
	_, err = c.UsageLimits.List(ctx, schema.UsageLimitsListOptions{WorkspaceID: &workspace})
	check("usage_limits", err)
	_, err = c.RateLimits.List(ctx, schema.RateLimitsListOptions{WorkspaceID: &workspace})
	check("rate_limits", err)
	_, err = c.SecretReferences.List(ctx, schema.SecretReferencesListOptions{})
	check("secret_references", err)
	_, err = c.Deployments.List(ctx, schema.DeploymentsListOptions{})
	check("deployments", err)
}
