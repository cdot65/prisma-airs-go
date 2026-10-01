package gateway

import (
	"context"
	"encoding/json"
	"github.com/cdot65/prisma-airs-go/aisec/gateway/schema"
	"os"
	"testing"
)

func currentContractCases(t *testing.T) []contractCase {
	ctx := context.Background()
	return []contractCase{
		{"GuardrailsCreate", "data", "POST", "/guardrails", "/guardrails", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Guardrails.Create(ctx, contractValue[schema.CreateGuardrailRequest](t, f.Request)))
		}},
		{"GuardrailsList", "data", "GET", "/guardrails", "/guardrails", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Guardrails.List(ctx, contractValue[schema.GuardrailsListOptions](t, f.Options)))
		}},
		{"GuardrailsGet", "data", "GET", "/guardrails/{guardrailId}", "/guardrails/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Guardrails.Get(ctx, "id/part"))
		}},
		{"GuardrailsUpdate", "data", "PUT", "/guardrails/{guardrailId}", "/guardrails/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Guardrails.Update(ctx, "id/part", contractValue[schema.UpdateGuardrailRequest](t, f.Request)))
		}},
		{"GuardrailsDelete", "data", "DELETE", "/guardrails/{guardrailId}", "/guardrails/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return nil, c.Guardrails.Delete(ctx, "id/part")
		}},
		{"GuardrailsSetMCPServers", "data", "PUT", "/guardrails/{guardrailId}/mcp-servers", "/guardrails/id%2Fpart/mcp-servers", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Guardrails.SetMCPServers(ctx, "id/part", contractValue[schema.BulkSyncMCPServerMappingsRequest](t, f.Request)))
		}},
		{"GuardrailsListMCPServers", "data", "GET", "/guardrails/{guardrailId}/mcp-servers", "/guardrails/id%2Fpart/mcp-servers", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Guardrails.ListMCPServers(ctx, "id/part"))
		}},
		{"GuardrailsUpsertMCPServer", "data", "PUT", "/guardrails/{guardrailId}/mcp-servers/{mcpServerId}", "/guardrails/id%2Fpart/mcp-servers/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Guardrails.UpsertMCPServer(ctx, "id/part", "id/part", contractValue[schema.UpsertMCPServerMappingRequest](t, f.Request)))
		}},
		{"OrgGuardrailsCreate", "admin", "POST", "/admin/v2/guardrails", "/guardrails", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.OrgGuardrails.Create(ctx, contractValue[schema.CreateGuardrailRequest](t, f.Request)))
		}},
		{"OrgGuardrailsList", "admin", "GET", "/admin/v2/guardrails", "/guardrails", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.OrgGuardrails.List(ctx, contractValue[schema.OrgGuardrailsListOptions](t, f.Options)))
		}},
		{"OrgGuardrailsGet", "admin", "GET", "/admin/v2/guardrails/{guardrailId}", "/guardrails/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.OrgGuardrails.Get(ctx, "id/part"))
		}},
		{"OrgGuardrailsUpdate", "admin", "PUT", "/admin/v2/guardrails/{guardrailId}", "/guardrails/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.OrgGuardrails.Update(ctx, "id/part", contractValue[schema.UpdateGuardrailRequest](t, f.Request)))
		}},
		{"OrgGuardrailsDelete", "admin", "DELETE", "/admin/v2/guardrails/{guardrailId}", "/guardrails/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return nil, c.OrgGuardrails.Delete(ctx, "id/part")
		}},
		{"OrgGuardrailsSetMCPServers", "admin", "PUT", "/admin/v2/guardrails/{guardrailId}/mcp-servers", "/guardrails/id%2Fpart/mcp-servers", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.OrgGuardrails.SetMCPServers(ctx, "id/part", contractValue[schema.BulkSyncMCPServerMappingsRequest](t, f.Request)))
		}},
		{"OrgGuardrailsListMCPServers", "admin", "GET", "/admin/v2/guardrails/{guardrailId}/mcp-servers", "/guardrails/id%2Fpart/mcp-servers", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.OrgGuardrails.ListMCPServers(ctx, "id/part"))
		}},
		{"OrgGuardrailsUpsertMCPServer", "admin", "PUT", "/admin/v2/guardrails/{guardrailId}/mcp-servers/{mcpServerId}", "/guardrails/id%2Fpart/mcp-servers/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.OrgGuardrails.UpsertMCPServer(ctx, "id/part", "id/part", contractValue[schema.UpsertMCPServerMappingRequest](t, f.Request)))
		}},
		{"ConfigsList", "data", "GET", "/configs", "/configs", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Configs.List(ctx, contractValue[schema.ConfigsListOptions](t, f.Options)))
		}},
		{"ConfigsCreate", "data", "POST", "/configs", "/configs", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Configs.Create(ctx, contractValue[schema.ConfigsCreateRequest](t, f.Request)))
		}},
		{"ConfigsDelete", "data", "DELETE", "/configs/{slug}", "/configs/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Configs.Delete(ctx, "id/part"))
		}},
		{"ConfigsGet", "data", "GET", "/configs/{slug}", "/configs/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Configs.Get(ctx, "id/part"))
		}},
		{"ConfigsUpdate", "data", "PUT", "/configs/{slug}", "/configs/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Configs.Update(ctx, "id/part", contractValue[schema.ConfigsUpdateRequest](t, f.Request)))
		}},
		{"ConfigsListVersions", "data", "GET", "/configs/{slug}/versions", "/configs/id%2Fpart/versions", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Configs.ListVersions(ctx, "id/part"))
		}},
		{"IntegrationsList", "admin", "GET", "/integrations", "/integrations", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Integrations.List(ctx, contractValue[schema.IntegrationsListOptions](t, f.Options)))
		}},
		{"IntegrationsCreate", "admin", "POST", "/integrations", "/integrations", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Integrations.Create(ctx, contractValue[schema.CreateIntegrationRequest](t, f.Request)))
		}},
		{"IntegrationsGet", "admin", "GET", "/integrations/{slug}", "/integrations/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Integrations.Get(ctx, "id/part"))
		}},
		{"IntegrationsUpdate", "admin", "PUT", "/integrations/{slug}", "/integrations/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Integrations.Update(ctx, "id/part", contractValue[schema.UpdateIntegrationRequest](t, f.Request)))
		}},
		{"IntegrationsDelete", "admin", "DELETE", "/integrations/{slug}", "/integrations/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Integrations.Delete(ctx, "id/part"))
		}},
		{"IntegrationsListModels", "admin", "GET", "/integrations/{slug}/models", "/integrations/id%2Fpart/models", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Integrations.ListModels(ctx, "id/part"))
		}},
		{"IntegrationsSetModels", "admin", "PUT", "/integrations/{slug}/models", "/integrations/id%2Fpart/models", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Integrations.SetModels(ctx, "id/part", contractValue[schema.BulkUpdateModelsRequest](t, f.Request)))
		}},
		{"IntegrationsDeleteModels", "admin", "DELETE", "/integrations/{slug}/models", "/integrations/id%2Fpart/models", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Integrations.DeleteModels(ctx, "id/part", contractValue[schema.IntegrationsDeleteModelsOptions](t, f.Options)))
		}},
		{"IntegrationsListWorkspaces", "admin", "GET", "/integrations/{slug}/workspaces", "/integrations/id%2Fpart/workspaces", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Integrations.ListWorkspaces(ctx, "id/part"))
		}},
		{"IntegrationsSetWorkspaces", "admin", "PUT", "/integrations/{slug}/workspaces", "/integrations/id%2Fpart/workspaces", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Integrations.SetWorkspaces(ctx, "id/part", contractValue[schema.BulkUpdateWorkspacesRequest](t, f.Request)))
		}},
		{"ProvidersList", "data", "GET", "/providers", "/providers", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Providers.List(ctx, contractValue[schema.ProvidersListOptions](t, f.Options)))
		}},
		{"ProvidersCreate", "data", "POST", "/providers", "/providers", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Providers.Create(ctx, contractValue[schema.ProvidersCreateRequest](t, f.Request)))
		}},
		{"ProvidersGet", "data", "GET", "/providers/{slug}", "/providers/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Providers.Get(ctx, "id/part", contractValue[schema.ProvidersGetOptions](t, f.Options)))
		}},
		{"ProvidersUpdate", "data", "PUT", "/providers/{slug}", "/providers/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Providers.Update(ctx, "id/part", contractValue[schema.ProvidersUpdateRequest](t, f.Request), contractValue[schema.ProvidersUpdateOptions](t, f.Options)))
		}},
		{"ProvidersDelete", "data", "DELETE", "/providers/{slug}", "/providers/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Providers.Delete(ctx, "id/part", contractValue[schema.ProvidersDeleteOptions](t, f.Options)))
		}},
		{"MCPIntegrationsCreate", "admin", "POST", "/mcp-integrations", "/mcp-integrations", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.MCPIntegrations.Create(ctx, contractValue[schema.CreateMCPIntegration](t, f.Request)))
		}},
		{"MCPIntegrationsList", "admin", "GET", "/mcp-integrations", "/mcp-integrations", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.MCPIntegrations.List(ctx, contractValue[schema.MCPIntegrationsListOptions](t, f.Options)))
		}},
		{"MCPIntegrationsGet", "admin", "GET", "/mcp-integrations/{mcpIntegrationId}", "/mcp-integrations/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.MCPIntegrations.Get(ctx, "id/part"))
		}},
		{"MCPIntegrationsUpdate", "admin", "PUT", "/mcp-integrations/{mcpIntegrationId}", "/mcp-integrations/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.MCPIntegrations.Update(ctx, "id/part", contractValue[schema.UpdateMCPIntegration](t, f.Request)))
		}},
		{"MCPIntegrationsDelete", "admin", "DELETE", "/mcp-integrations/{mcpIntegrationId}", "/mcp-integrations/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.MCPIntegrations.Delete(ctx, "id/part"))
		}},
		{"MCPIntegrationsListWorkspaces", "admin", "GET", "/mcp-integrations/{mcpIntegrationId}/workspaces", "/mcp-integrations/id%2Fpart/workspaces", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.MCPIntegrations.ListWorkspaces(ctx, "id/part", contractValue[schema.MCPIntegrationsListWorkspacesOptions](t, f.Options)))
		}},
		{"MCPIntegrationsSetWorkspaces", "admin", "PUT", "/mcp-integrations/{mcpIntegrationId}/workspaces", "/mcp-integrations/id%2Fpart/workspaces", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.MCPIntegrations.SetWorkspaces(ctx, "id/part", contractValue[schema.BulkUpdateMCPIntegrationWorkspaces](t, f.Request)))
		}},
		{"MCPIntegrationsListCapabilities", "admin", "GET", "/mcp-integrations/{mcpIntegrationId}/capabilities", "/mcp-integrations/id%2Fpart/capabilities", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.MCPIntegrations.ListCapabilities(ctx, "id/part", contractValue[schema.MCPIntegrationsListCapabilitiesOptions](t, f.Options)))
		}},
		{"MCPIntegrationsSetCapabilities", "admin", "PUT", "/mcp-integrations/{mcpIntegrationId}/capabilities", "/mcp-integrations/id%2Fpart/capabilities", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.MCPIntegrations.SetCapabilities(ctx, "id/part", contractValue[schema.BulkUpdateMCPIntegrationCapabilities](t, f.Request)))
		}},
		{"MCPIntegrationsGetMetadata", "admin", "GET", "/mcp-integrations/{mcpIntegrationId}/metadata", "/mcp-integrations/id%2Fpart/metadata", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.MCPIntegrations.GetMetadata(ctx, "id/part"))
		}},
		{"MCPServersCreate", "data", "POST", "/mcp-servers", "/mcp-servers", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.MCPServers.Create(ctx, contractValue[schema.CreateMCPServer](t, f.Request)))
		}},
		{"MCPServersList", "data", "GET", "/mcp-servers", "/mcp-servers", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.MCPServers.List(ctx, contractValue[schema.MCPServersListOptions](t, f.Options)))
		}},
		{"MCPServersGet", "data", "GET", "/mcp-servers/{mcpServerId}", "/mcp-servers/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.MCPServers.Get(ctx, "id/part"))
		}},
		{"MCPServersUpdate", "data", "PUT", "/mcp-servers/{mcpServerId}", "/mcp-servers/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.MCPServers.Update(ctx, "id/part", contractValue[schema.UpdateMCPServer](t, f.Request)))
		}},
		{"MCPServersDelete", "data", "DELETE", "/mcp-servers/{mcpServerId}", "/mcp-servers/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.MCPServers.Delete(ctx, "id/part"))
		}},
		{"MCPServersTest", "data", "POST", "/mcp-servers/{mcpServerId}/test", "/mcp-servers/id%2Fpart/test", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.MCPServers.Test(ctx, "id/part"))
		}},
		{"MCPServersListCapabilities", "data", "GET", "/mcp-servers/{mcpServerId}/capabilities", "/mcp-servers/id%2Fpart/capabilities", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.MCPServers.ListCapabilities(ctx, "id/part", contractValue[schema.MCPServersListCapabilitiesOptions](t, f.Options)))
		}},
		{"MCPServersSetCapabilities", "data", "PUT", "/mcp-servers/{mcpServerId}/capabilities", "/mcp-servers/id%2Fpart/capabilities", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.MCPServers.SetCapabilities(ctx, "id/part", contractValue[schema.BulkUpdateMCPServerCapabilities](t, f.Request)))
		}},
		{"MCPServersListUserAccess", "data", "GET", "/mcp-servers/{mcpServerId}/user-access", "/mcp-servers/id%2Fpart/user-access", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.MCPServers.ListUserAccess(ctx, "id/part", contractValue[schema.MCPServersListUserAccessOptions](t, f.Options)))
		}},
		{"MCPServersSetUserAccess", "data", "PUT", "/mcp-servers/{mcpServerId}/user-access", "/mcp-servers/id%2Fpart/user-access", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.MCPServers.SetUserAccess(ctx, "id/part", contractValue[schema.BulkUpdateMCPServerUserAccess](t, f.Request)))
		}},
		{"MCPServersListConnections", "data", "GET", "/mcp-servers/{mcpServerId}/connections", "/mcp-servers/id%2Fpart/connections", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.MCPServers.ListConnections(ctx, "id/part", contractValue[schema.MCPServersListConnectionsOptions](t, f.Options)))
		}},
		{"MCPServersDeleteConnections", "data", "DELETE", "/mcp-servers/{mcpServerId}/connections", "/mcp-servers/id%2Fpart/connections", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.MCPServers.DeleteConnections(ctx, "id/part", contractValue[schema.MCPServersDeleteConnectionsOptions](t, f.Options)))
		}},
		{"APIKeysCreate", "data", "POST", "/api-keys/{sub-type}", "/api-keys/service", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.APIKeys.Create(ctx, APIKeyService, contractValue[schema.CreateAPIKeyObject](t, f.Request)))
		}},
		{"APIKeysList", "data", "GET", "/api-keys", "/api-keys", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.APIKeys.List(ctx, contractValue[schema.APIKeysListOptions](t, f.Options)))
		}},
		{"APIKeysUpdate", "data", "PUT", "/api-keys/{id}", "/api-keys/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.APIKeys.Update(ctx, "id/part", contractValue[schema.UpdateAPIKeyObject](t, f.Request)))
		}},
		{"APIKeysGet", "data", "GET", "/api-keys/{id}", "/api-keys/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.APIKeys.Get(ctx, "id/part"))
		}},
		{"APIKeysDelete", "data", "DELETE", "/api-keys/{id}", "/api-keys/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.APIKeys.Delete(ctx, "id/part"))
		}},
		{"APIKeysRotate", "data", "POST", "/api-keys/{id}/rotate", "/api-keys/id%2Fpart/rotate", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.APIKeys.Rotate(ctx, "id/part", contractValue[schema.RotateAPIKeyRequest](t, f.Request)))
		}},
		{"UsageLimitsCreate", "data", "POST", "/policies/usage-limits", "/policies/usage-limits", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.UsageLimits.Create(ctx, contractValue[schema.CreateUsageLimitsPolicyRequest](t, f.Request)))
		}},
		{"UsageLimitsList", "data", "GET", "/policies/usage-limits", "/policies/usage-limits", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.UsageLimits.List(ctx, contractValue[schema.UsageLimitsListOptions](t, f.Options)))
		}},
		{"UsageLimitsGet", "data", "GET", "/policies/usage-limits/{policyUsageLimitsId}", "/policies/usage-limits/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.UsageLimits.Get(ctx, "id/part", contractValue[schema.UsageLimitsGetOptions](t, f.Options)))
		}},
		{"UsageLimitsUpdate", "data", "PUT", "/policies/usage-limits/{policyUsageLimitsId}", "/policies/usage-limits/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.UsageLimits.Update(ctx, "id/part", contractValue[schema.UpdateUsageLimitsPolicyRequest](t, f.Request)))
		}},
		{"UsageLimitsDelete", "data", "DELETE", "/policies/usage-limits/{policyUsageLimitsId}", "/policies/usage-limits/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.UsageLimits.Delete(ctx, "id/part"))
		}},
		{"UsageLimitsListEntities", "data", "GET", "/policies/usage-limits/{policyUsageLimitsId}/entities", "/policies/usage-limits/id%2Fpart/entities", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.UsageLimits.ListEntities(ctx, "id/part", contractValue[schema.UsageLimitsListEntitiesOptions](t, f.Options)))
		}},
		{"UsageLimitsResetEntity", "data", "PUT", "/policies/usage-limits/{policyUsageLimitsId}/entities/{entityId}/reset", "/policies/usage-limits/id%2Fpart/entities/id%2Fpart/reset", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.UsageLimits.ResetEntity(ctx, "id/part", "id/part"))
		}},
		{"RateLimitsCreate", "data", "POST", "/policies/rate-limits", "/policies/rate-limits", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.RateLimits.Create(ctx, contractValue[schema.CreateRateLimitsPolicyRequest](t, f.Request)))
		}},
		{"RateLimitsList", "data", "GET", "/policies/rate-limits", "/policies/rate-limits", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.RateLimits.List(ctx, contractValue[schema.RateLimitsListOptions](t, f.Options)))
		}},
		{"RateLimitsGet", "data", "GET", "/policies/rate-limits/{rateLimitsPolicyId}", "/policies/rate-limits/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.RateLimits.Get(ctx, "id/part", contractValue[schema.RateLimitsGetOptions](t, f.Options)))
		}},
		{"RateLimitsUpdate", "data", "PUT", "/policies/rate-limits/{rateLimitsPolicyId}", "/policies/rate-limits/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.RateLimits.Update(ctx, "id/part", contractValue[schema.UpdateRateLimitsPolicyRequest](t, f.Request)))
		}},
		{"RateLimitsDelete", "data", "DELETE", "/policies/rate-limits/{rateLimitsPolicyId}", "/policies/rate-limits/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.RateLimits.Delete(ctx, "id/part"))
		}},
		{"SecretReferencesList", "admin", "GET", "/secret-references", "/secret-references", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.SecretReferences.List(ctx, contractValue[schema.SecretReferencesListOptions](t, f.Options)))
		}},
		{"SecretReferencesCreate", "admin", "POST", "/secret-references", "/secret-references", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.SecretReferences.Create(ctx, contractValue[schema.CreateSecretReferenceRequest](t, f.Request)))
		}},
		{"SecretReferencesGet", "admin", "GET", "/secret-references/{secretReferenceId}", "/secret-references/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.SecretReferences.Get(ctx, "id/part"))
		}},
		{"SecretReferencesUpdate", "admin", "PUT", "/secret-references/{secretReferenceId}", "/secret-references/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.SecretReferences.Update(ctx, "id/part", contractValue[schema.UpdateSecretReferenceRequest](t, f.Request)))
		}},
		{"SecretReferencesDelete", "admin", "DELETE", "/secret-references/{secretReferenceId}", "/secret-references/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.SecretReferences.Delete(ctx, "id/part"))
		}},
		{"DeploymentsList", "admin", "GET", "/deployments", "/deployments", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Deployments.List(ctx, contractValue[schema.DeploymentsListOptions](t, f.Options)))
		}},
		{"DeploymentsCreate", "admin", "POST", "/deployments", "/deployments", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Deployments.Create(ctx, contractValue[schema.CreateDeploymentRequest](t, f.Request)))
		}},
		{"DeploymentsGet", "admin", "GET", "/deployments/{deploymentId}", "/deployments/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Deployments.Get(ctx, "id/part"))
		}},
		{"DeploymentsUpdate", "admin", "PUT", "/deployments/{deploymentId}", "/deployments/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Deployments.Update(ctx, "id/part", contractValue[schema.UpdateDeploymentRequest](t, f.Request)))
		}},
		{"DeploymentsDelete", "admin", "DELETE", "/deployments/{deploymentId}", "/deployments/id%2Fpart", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Deployments.Delete(ctx, "id/part"))
		}},
		{"DeploymentsPing", "admin", "GET", "/deployments/{deploymentId}/ping", "/deployments/id%2Fpart/ping", func(t *testing.T, c *Client, f contractFixture) (any, error) {
			return contractResult(c.Deployments.Ping(ctx, "id/part"))
		}},
	}
}
func TestAllGatewayContracts(t *testing.T) {
	var fixtures map[string]contractFixture
	b, err := os.ReadFile("testdata/contracts.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &fixtures); err != nil {
		t.Fatal(err)
	}
	cases := currentContractCases(t)
	runContracts(t, cases, fixtures)
	verifyScope(t, cases)
}
