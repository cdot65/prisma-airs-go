//go:build integration

package gateway

import (
	"context"
	"fmt"
	"github.com/cdot65/prisma-airs-go/aisec/gateway/schema"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	"strings"
	"testing"
	"time"
)

func TestIntegration_GatewayIntegrationGraphs(t *testing.T) {
	c, workspace := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	name := fmt.Sprintf("sdk-graph-%d", time.Now().UnixNano())
	org := c.dataCfg.TsgID
	t.Run("integrations_and_providers", func(t *testing.T) {
		catalog, err := internal.DoMgmtRequest[struct {
			Data []struct{ ID, Name, Slug string } `json:"data"`
		}](ctx, c.adminCfg, internal.MgmtRequestOptions{Method: "GET", Path: "/utils/static-resources/ai-providers"})
		if err != nil {
			t.Fatal(err)
		}
		providerID := ""
		for _, provider := range catalog.Data.Data {
			if strings.ReplaceAll(strings.ToLower(provider.Name), " ", "") == "openai" || provider.Slug == "open-ai" {
				providerID = provider.ID
				break
			}
		}
		if providerID == "" {
			t.Fatal("OpenAI provider family unavailable")
		}
		created, err := c.Integrations.Create(ctx, liveValue[schema.CreateIntegrationRequest](t, map[string]any{"name": name, "ai_provider_id": providerID, "key": "sdk-verification-placeholder", "organisation_id": org, "create_default_provider": false}))
		if err != nil {
			t.Fatal(err)
		}
		id := receiptID(t, created)
		cleanupResource(t, func(ctx context.Context) error { _, err := c.Integrations.Delete(ctx, id); return err })
		if _, err := c.Integrations.Get(ctx, id); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Integrations.Update(ctx, id, liveValue[schema.UpdateIntegrationRequest](t, map[string]any{"description": "updated"})); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Integrations.ListModels(ctx, id); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Integrations.ListWorkspaces(ctx, id); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Integrations.SetWorkspaces(ctx, id, liveValue[schema.BulkUpdateWorkspacesRequest](t, map[string]any{"workspaces": []any{map[string]any{"id": workspace, "enabled": true}}, "create_default_provider": false})); err != nil {
			t.Fatal(err)
		}
		provider, err := c.Providers.Create(ctx, liveValue[schema.ProvidersCreateRequest](t, map[string]any{"name": name, "workspace_id": workspace, "integration_id": id}))
		if err != nil {
			t.Fatal(err)
		}
		providerUUID := receiptID(t, provider)
		cleanupResource(t, func(ctx context.Context) error {
			_, err := c.Providers.Delete(ctx, providerUUID, schema.ProvidersDeleteOptions{WorkspaceID: &workspace})
			return err
		})
		if _, err := c.Providers.Get(ctx, providerUUID, schema.ProvidersGetOptions{WorkspaceID: &workspace}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Providers.Update(ctx, providerUUID, liveValue[schema.ProvidersUpdateRequest](t, map[string]any{"note": "updated"}), schema.ProvidersUpdateOptions{WorkspaceID: &workspace}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("mcp_integrations_and_servers", func(t *testing.T) {
		created, err := c.MCPIntegrations.Create(ctx, liveValue[schema.CreateMCPIntegration](t, map[string]any{"name": name, "organisation_id": org, "url": "https://mcp.deepwiki.com/mcp", "auth_type": "none", "transport": "http", "configurations": map[string]any{}}))
		if err != nil {
			t.Fatal(err)
		}
		id := receiptID(t, created)
		cleanupResource(t, func(ctx context.Context) error { _, err := c.MCPIntegrations.Delete(ctx, id); return err })
		if _, err := c.MCPIntegrations.Get(ctx, id); err != nil {
			t.Fatal(err)
		}
		if _, err := c.MCPIntegrations.Update(ctx, id, liveValue[schema.UpdateMCPIntegration](t, map[string]any{"description": "updated", "configurations": map[string]any{}})); err != nil {
			t.Fatal(err)
		}
		if _, err := c.MCPIntegrations.ListWorkspaces(ctx, id, schema.MCPIntegrationsListWorkspacesOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.MCPIntegrations.GetMetadata(ctx, id); err != nil {
			t.Fatal(err)
		}
		if _, err := c.MCPIntegrations.SetWorkspaces(ctx, id, liveValue[schema.BulkUpdateMCPIntegrationWorkspaces](t, map[string]any{"workspaces": []any{map[string]any{"id": workspace, "enabled": true}}})); err != nil {
			t.Fatal(err)
		}
		server, err := c.MCPServers.Create(ctx, liveValue[schema.CreateMCPServer](t, map[string]any{"name": name, "workspace_id": workspace, "mcp_integration_id": id}))
		if err != nil {
			t.Fatal(err)
		}
		serverID := receiptID(t, server)
		cleanupResource(t, func(ctx context.Context) error { _, err := c.MCPServers.Delete(ctx, serverID); return err })
		if _, err := c.MCPServers.Get(ctx, serverID); err != nil {
			t.Fatal(err)
		}
		if _, err := c.MCPServers.Update(ctx, serverID, liveValue[schema.UpdateMCPServer](t, map[string]any{"description": "updated"})); err != nil {
			t.Fatal(err)
		}
		if _, err := c.MCPServers.ListCapabilities(ctx, serverID, schema.MCPServersListCapabilitiesOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.MCPServers.ListConnections(ctx, serverID, schema.MCPServersListConnectionsOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.MCPServers.ListUserAccess(ctx, serverID, schema.MCPServersListUserAccessOptions{}); err != nil {
			t.Fatal(err)
		}
	})
}
