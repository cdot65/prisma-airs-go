package gateway

import (
	"context"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/gateway/schema"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	"net/http"
)

// Create creates a resource and returns its creation receipt.
func (c *GuardrailsClient) Create(ctx context.Context, req schema.CreateGuardrailRequest) (*schema.CreateGuardrailResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.CreateGuardrailResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.GatewayGuardrailsPath, Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// List lists resources with explicit scope and pagination.
func (c *GuardrailsClient) List(ctx context.Context, opts schema.GuardrailsListOptions) (*schema.ListGuardrailsResponse, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.ListGuardrailsResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayGuardrailsPath, Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Get reads the resource.
func (c *GuardrailsClient) Get(ctx context.Context, guardrailID string) (*schema.GuardrailDetails, error) {
	resp, err := internal.DoMgmtRequest[schema.GuardrailDetails](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayGuardrailsPath + "/" + seg(guardrailID)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Update updates supplied fields; nested documents may replace stored values.
func (c *GuardrailsClient) Update(ctx context.Context, guardrailID string, req schema.UpdateGuardrailRequest) (*schema.UpdateGuardrailResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.UpdateGuardrailResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayGuardrailsPath + "/" + seg(guardrailID), Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Delete deletes the resource.
func (c *GuardrailsClient) Delete(ctx context.Context, guardrailID string) error {
	_, err := internal.DoMgmtRequest[any](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodDelete, Path: aisec.GatewayGuardrailsPath + "/" + seg(guardrailID), ResponsePolicy: internal.AllowEmptyJSON})
	return err
}

// SetMCPServers calls the explicit SetMCPServers lifecycle operation.
func (c *GuardrailsClient) SetMCPServers(ctx context.Context, guardrailID string, req schema.BulkSyncMCPServerMappingsRequest) (*schema.BulkSyncMCPServerMappingsResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.BulkSyncMCPServerMappingsResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayGuardrailsPath + "/" + seg(guardrailID) + "/mcp-servers", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListMCPServers calls the explicit ListMCPServers lifecycle operation.
func (c *GuardrailsClient) ListMCPServers(ctx context.Context, guardrailID string) (*schema.GuardrailsListMCPServersResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.GuardrailsListMCPServersResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayGuardrailsPath + "/" + seg(guardrailID) + "/mcp-servers"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// UpsertMCPServer calls the explicit UpsertMCPServer lifecycle operation.
func (c *GuardrailsClient) UpsertMCPServer(ctx context.Context, guardrailID string, mcpServerID string, req schema.UpsertMCPServerMappingRequest) (*schema.UpsertMCPServerMappingResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.UpsertMCPServerMappingResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayGuardrailsPath + "/" + seg(guardrailID) + "/mcp-servers/" + seg(mcpServerID), Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Create creates a resource and returns its creation receipt.
func (c *OrgGuardrailsClient) Create(ctx context.Context, req schema.CreateGuardrailRequest) (*schema.CreateGuardrailResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.CreateGuardrailResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.GatewayOrgGuardrailsPath, Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// List lists resources with explicit scope and pagination.
func (c *OrgGuardrailsClient) List(ctx context.Context, opts schema.OrgGuardrailsListOptions) (*schema.ListGuardrailsResponse, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.ListGuardrailsResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayOrgGuardrailsPath, Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Get reads the resource.
func (c *OrgGuardrailsClient) Get(ctx context.Context, guardrailID string) (*schema.GuardrailDetails, error) {
	resp, err := internal.DoMgmtRequest[schema.GuardrailDetails](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayOrgGuardrailsPath + "/" + seg(guardrailID)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Update updates supplied fields; nested documents may replace stored values.
func (c *OrgGuardrailsClient) Update(ctx context.Context, guardrailID string, req schema.UpdateGuardrailRequest) (*schema.UpdateGuardrailResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.UpdateGuardrailResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayOrgGuardrailsPath + "/" + seg(guardrailID), Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Delete deletes the resource.
func (c *OrgGuardrailsClient) Delete(ctx context.Context, guardrailID string) error {
	_, err := internal.DoMgmtRequest[any](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodDelete, Path: aisec.GatewayOrgGuardrailsPath + "/" + seg(guardrailID), ResponsePolicy: internal.AllowEmptyJSON})
	return err
}

// SetMCPServers calls the explicit SetMCPServers lifecycle operation.
func (c *OrgGuardrailsClient) SetMCPServers(ctx context.Context, guardrailID string, req schema.BulkSyncMCPServerMappingsRequest) (*schema.BulkSyncMCPServerMappingsResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.BulkSyncMCPServerMappingsResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayOrgGuardrailsPath + "/" + seg(guardrailID) + "/mcp-servers", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListMCPServers calls the explicit ListMCPServers lifecycle operation.
func (c *OrgGuardrailsClient) ListMCPServers(ctx context.Context, guardrailID string) (*schema.OrgGuardrailsListMCPServersResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.OrgGuardrailsListMCPServersResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayOrgGuardrailsPath + "/" + seg(guardrailID) + "/mcp-servers"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// UpsertMCPServer calls the explicit UpsertMCPServer lifecycle operation.
func (c *OrgGuardrailsClient) UpsertMCPServer(ctx context.Context, guardrailID string, mcpServerID string, req schema.UpsertMCPServerMappingRequest) (*schema.UpsertMCPServerMappingResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.UpsertMCPServerMappingResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayOrgGuardrailsPath + "/" + seg(guardrailID) + "/mcp-servers/" + seg(mcpServerID), Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// List lists resources with explicit scope and pagination.
func (c *ConfigsClient) List(ctx context.Context, opts schema.ConfigsListOptions) (*schema.ConfigsListResponse, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.ConfigsListResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayConfigsPath, Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Create creates a resource and returns its creation receipt.
func (c *ConfigsClient) Create(ctx context.Context, req schema.ConfigsCreateRequest) (*schema.ConfigsCreateResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.ConfigsCreateResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.GatewayConfigsPath, Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Delete deletes the resource.
func (c *ConfigsClient) Delete(ctx context.Context, slug string) (*schema.ConfigsDeleteResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.ConfigsDeleteResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodDelete, Path: aisec.GatewayConfigsPath + "/" + seg(slug)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Get reads the resource.
func (c *ConfigsClient) Get(ctx context.Context, slug string) (*schema.ConfigsGetResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.ConfigsGetResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayConfigsPath + "/" + seg(slug)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Update updates supplied fields; nested documents may replace stored values.
func (c *ConfigsClient) Update(ctx context.Context, slug string, req schema.ConfigsUpdateRequest) (*schema.ConfigsUpdateResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.ConfigsUpdateResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayConfigsPath + "/" + seg(slug), Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListVersions calls the explicit ListVersions lifecycle operation.
func (c *ConfigsClient) ListVersions(ctx context.Context, slug string) (*schema.ConfigsListVersionsResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.ConfigsListVersionsResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayConfigsPath + "/" + seg(slug) + "/versions"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// List lists resources with explicit scope and pagination.
func (c *IntegrationsClient) List(ctx context.Context, opts schema.IntegrationsListOptions) (*schema.IntegrationsListResponse, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.IntegrationsListResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayIntegrationsPath, Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Create creates a resource and returns its creation receipt.
func (c *IntegrationsClient) Create(ctx context.Context, req schema.CreateIntegrationRequest) (*schema.IntegrationsCreateResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.IntegrationsCreateResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.GatewayIntegrationsPath, Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Get reads the resource.
func (c *IntegrationsClient) Get(ctx context.Context, slug string) (*schema.IntegrationDetailResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.IntegrationDetailResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayIntegrationsPath + "/" + seg(slug)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Update updates supplied fields; nested documents may replace stored values.
func (c *IntegrationsClient) Update(ctx context.Context, slug string, req schema.UpdateIntegrationRequest) (*schema.IntegrationsUpdateResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.IntegrationsUpdateResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayIntegrationsPath + "/" + seg(slug), Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Delete deletes the resource.
func (c *IntegrationsClient) Delete(ctx context.Context, slug string) (*schema.IntegrationsDeleteResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.IntegrationsDeleteResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodDelete, Path: aisec.GatewayIntegrationsPath + "/" + seg(slug)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListModels calls the explicit ListModels lifecycle operation.
func (c *IntegrationsClient) ListModels(ctx context.Context, slug string) (*schema.IntegrationModelsResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.IntegrationModelsResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayIntegrationsPath + "/" + seg(slug) + "/models"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// SetModels calls the explicit SetModels lifecycle operation.
func (c *IntegrationsClient) SetModels(ctx context.Context, slug string, req schema.BulkUpdateModelsRequest) (*schema.IntegrationsSetModelsResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.IntegrationsSetModelsResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayIntegrationsPath + "/" + seg(slug) + "/models", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// DeleteModels calls the explicit DeleteModels lifecycle operation.
func (c *IntegrationsClient) DeleteModels(ctx context.Context, slug string, opts schema.IntegrationsDeleteModelsOptions) (*schema.IntegrationsDeleteModelsResponse, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.IntegrationsDeleteModelsResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodDelete, Path: aisec.GatewayIntegrationsPath + "/" + seg(slug) + "/models", Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListWorkspaces calls the explicit ListWorkspaces lifecycle operation.
func (c *IntegrationsClient) ListWorkspaces(ctx context.Context, slug string) (*schema.IntegrationWorkspacesResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.IntegrationWorkspacesResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayIntegrationsPath + "/" + seg(slug) + "/workspaces"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// SetWorkspaces calls the explicit SetWorkspaces lifecycle operation.
func (c *IntegrationsClient) SetWorkspaces(ctx context.Context, slug string, req schema.BulkUpdateWorkspacesRequest) (*schema.IntegrationsSetWorkspacesResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.IntegrationsSetWorkspacesResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayIntegrationsPath + "/" + seg(slug) + "/workspaces", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// List lists resources with explicit scope and pagination.
func (c *ProvidersClient) List(ctx context.Context, opts schema.ProvidersListOptions) (*schema.ProvidersListResponse, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.ProvidersListResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayProvidersPath, Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Create creates a resource and returns its creation receipt.
func (c *ProvidersClient) Create(ctx context.Context, req schema.ProvidersCreateRequest) (*schema.ProvidersCreateResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.ProvidersCreateResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.GatewayProvidersPath, Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Get reads the resource.
func (c *ProvidersClient) Get(ctx context.Context, slug string, opts schema.ProvidersGetOptions) (*schema.Providers, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.Providers](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayProvidersPath + "/" + seg(slug), Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Update updates supplied fields; nested documents may replace stored values.
func (c *ProvidersClient) Update(ctx context.Context, slug string, req schema.ProvidersUpdateRequest, opts schema.ProvidersUpdateOptions) (*schema.ProvidersUpdateResponse, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.ProvidersUpdateResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayProvidersPath + "/" + seg(slug), Body: req, Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Delete deletes the resource.
func (c *ProvidersClient) Delete(ctx context.Context, slug string, opts schema.ProvidersDeleteOptions) (*schema.ProvidersDeleteResponse, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.ProvidersDeleteResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodDelete, Path: aisec.GatewayProvidersPath + "/" + seg(slug), Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Create creates a resource and returns its creation receipt.
func (c *MCPIntegrationsClient) Create(ctx context.Context, req schema.CreateMCPIntegration) (*schema.MCPIntegrationCreateResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.MCPIntegrationCreateResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.GatewayMCPIntegrationsPath, Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// List lists resources with explicit scope and pagination.
func (c *MCPIntegrationsClient) List(ctx context.Context, opts schema.MCPIntegrationsListOptions) (*schema.MCPIntegrationListResponse, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.MCPIntegrationListResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayMCPIntegrationsPath, Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Get reads the resource.
func (c *MCPIntegrationsClient) Get(ctx context.Context, mcpIntegrationID string) (*schema.MCPIntegration, error) {
	resp, err := internal.DoMgmtRequest[schema.MCPIntegration](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayMCPIntegrationsPath + "/" + seg(mcpIntegrationID)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Update updates supplied fields; nested documents may replace stored values.
func (c *MCPIntegrationsClient) Update(ctx context.Context, mcpIntegrationID string, req schema.UpdateMCPIntegration) (*schema.MCPIntegrationsUpdateResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.MCPIntegrationsUpdateResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayMCPIntegrationsPath + "/" + seg(mcpIntegrationID), Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Delete deletes the resource.
func (c *MCPIntegrationsClient) Delete(ctx context.Context, mcpIntegrationID string) (*schema.MCPIntegrationsDeleteResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.MCPIntegrationsDeleteResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodDelete, Path: aisec.GatewayMCPIntegrationsPath + "/" + seg(mcpIntegrationID)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListWorkspaces calls the explicit ListWorkspaces lifecycle operation.
func (c *MCPIntegrationsClient) ListWorkspaces(ctx context.Context, mcpIntegrationID string, opts schema.MCPIntegrationsListWorkspacesOptions) (*schema.MCPIntegrationsListWorkspacesResponse, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.MCPIntegrationsListWorkspacesResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayMCPIntegrationsPath + "/" + seg(mcpIntegrationID) + "/workspaces", Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// SetWorkspaces calls the explicit SetWorkspaces lifecycle operation.
func (c *MCPIntegrationsClient) SetWorkspaces(ctx context.Context, mcpIntegrationID string, req schema.BulkUpdateMCPIntegrationWorkspaces) (*schema.MCPIntegrationsSetWorkspacesResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.MCPIntegrationsSetWorkspacesResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayMCPIntegrationsPath + "/" + seg(mcpIntegrationID) + "/workspaces", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListCapabilities calls the explicit ListCapabilities lifecycle operation.
func (c *MCPIntegrationsClient) ListCapabilities(ctx context.Context, mcpIntegrationID string, opts schema.MCPIntegrationsListCapabilitiesOptions) (*schema.MCPIntegrationCapabilitiesListResponse, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.MCPIntegrationCapabilitiesListResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayMCPIntegrationsPath + "/" + seg(mcpIntegrationID) + "/capabilities", Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// SetCapabilities calls the explicit SetCapabilities lifecycle operation.
func (c *MCPIntegrationsClient) SetCapabilities(ctx context.Context, mcpIntegrationID string, req schema.BulkUpdateMCPIntegrationCapabilities) (*schema.MCPIntegrationCapabilitiesBulkUpdateResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.MCPIntegrationCapabilitiesBulkUpdateResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayMCPIntegrationsPath + "/" + seg(mcpIntegrationID) + "/capabilities", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetMetadata calls the explicit GetMetadata lifecycle operation.
func (c *MCPIntegrationsClient) GetMetadata(ctx context.Context, mcpIntegrationID string) (*schema.MCPIntegrationMetadata, error) {
	resp, err := internal.DoMgmtRequest[schema.MCPIntegrationMetadata](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayMCPIntegrationsPath + "/" + seg(mcpIntegrationID) + "/metadata"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Create creates a resource and returns its creation receipt.
func (c *MCPServersClient) Create(ctx context.Context, req schema.CreateMCPServer) (*schema.MCPServerCreateResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.MCPServerCreateResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.GatewayMCPServersPath, Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// List lists resources with explicit scope and pagination.
func (c *MCPServersClient) List(ctx context.Context, opts schema.MCPServersListOptions) (*schema.MCPServerListResponse, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.MCPServerListResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayMCPServersPath, Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Get reads the resource.
func (c *MCPServersClient) Get(ctx context.Context, mcpServerID string) (*schema.MCPServer, error) {
	resp, err := internal.DoMgmtRequest[schema.MCPServer](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayMCPServersPath + "/" + seg(mcpServerID)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Update updates supplied fields; nested documents may replace stored values.
func (c *MCPServersClient) Update(ctx context.Context, mcpServerID string, req schema.UpdateMCPServer) (*schema.MCPServersUpdateResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.MCPServersUpdateResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayMCPServersPath + "/" + seg(mcpServerID), Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Delete deletes the resource.
func (c *MCPServersClient) Delete(ctx context.Context, mcpServerID string) (*schema.MCPServersDeleteResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.MCPServersDeleteResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodDelete, Path: aisec.GatewayMCPServersPath + "/" + seg(mcpServerID)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Test calls the explicit Test lifecycle operation.
func (c *MCPServersClient) Test(ctx context.Context, mcpServerID string) (*schema.MCPServerTestResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.MCPServerTestResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.GatewayMCPServersPath + "/" + seg(mcpServerID) + "/test"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListCapabilities calls the explicit ListCapabilities lifecycle operation.
func (c *MCPServersClient) ListCapabilities(ctx context.Context, mcpServerID string, opts schema.MCPServersListCapabilitiesOptions) (*schema.MCPServerCapabilitiesListResponse, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.MCPServerCapabilitiesListResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayMCPServersPath + "/" + seg(mcpServerID) + "/capabilities", Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// SetCapabilities calls the explicit SetCapabilities lifecycle operation.
func (c *MCPServersClient) SetCapabilities(ctx context.Context, mcpServerID string, req schema.BulkUpdateMCPServerCapabilities) (*schema.MCPServerCapabilitiesBulkUpdateResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.MCPServerCapabilitiesBulkUpdateResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayMCPServersPath + "/" + seg(mcpServerID) + "/capabilities", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListUserAccess calls the explicit ListUserAccess lifecycle operation.
func (c *MCPServersClient) ListUserAccess(ctx context.Context, mcpServerID string, opts schema.MCPServersListUserAccessOptions) (*schema.MCPServerUserAccessListResponse, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.MCPServerUserAccessListResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayMCPServersPath + "/" + seg(mcpServerID) + "/user-access", Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// SetUserAccess calls the explicit SetUserAccess lifecycle operation.
func (c *MCPServersClient) SetUserAccess(ctx context.Context, mcpServerID string, req schema.BulkUpdateMCPServerUserAccess) (*schema.MCPServerUserAccessBulkUpdateResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.MCPServerUserAccessBulkUpdateResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayMCPServersPath + "/" + seg(mcpServerID) + "/user-access", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListConnections calls the explicit ListConnections lifecycle operation.
func (c *MCPServersClient) ListConnections(ctx context.Context, mcpServerID string, opts schema.MCPServersListConnectionsOptions) (*schema.MCPServerConnectionsListResponse, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.MCPServerConnectionsListResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayMCPServersPath + "/" + seg(mcpServerID) + "/connections", Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// DeleteConnections calls the explicit DeleteConnections lifecycle operation.
func (c *MCPServersClient) DeleteConnections(ctx context.Context, mcpServerID string, opts schema.MCPServersDeleteConnectionsOptions) (*schema.MCPServerConnectionDeleteResponse, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.MCPServerConnectionDeleteResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodDelete, Path: aisec.GatewayMCPServersPath + "/" + seg(mcpServerID) + "/connections", Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Create creates a resource and returns its creation receipt.
func (c *APIKeysClient) Create(ctx context.Context, kind APIKeyKind, req schema.CreateAPIKeyObject) (*schema.APIKeysCreateResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.APIKeysCreateResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.GatewayAPIKeysPath + "/" + seg(string(kind)), Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// List lists resources with explicit scope and pagination.
func (c *APIKeysClient) List(ctx context.Context, opts schema.APIKeysListOptions) (*schema.APIKeyObjectList, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.APIKeyObjectList](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayAPIKeysPath, Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Update updates supplied fields; nested documents may replace stored values.
func (c *APIKeysClient) Update(ctx context.Context, id string, req schema.UpdateAPIKeyObject) (*schema.APIKeysUpdateResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.APIKeysUpdateResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayAPIKeysPath + "/" + seg(id), Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Get reads the resource.
func (c *APIKeysClient) Get(ctx context.Context, id string) (*schema.APIKeyObject, error) {
	resp, err := internal.DoMgmtRequest[schema.APIKeyObject](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayAPIKeysPath + "/" + seg(id)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Delete deletes the resource.
func (c *APIKeysClient) Delete(ctx context.Context, id string) (*schema.APIKeysDeleteResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.APIKeysDeleteResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodDelete, Path: aisec.GatewayAPIKeysPath + "/" + seg(id)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Rotate rotates key material explicitly; capture the one-time secret.
func (c *APIKeysClient) Rotate(ctx context.Context, id string, req schema.RotateAPIKeyRequest) (*schema.RotateAPIKeyResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.RotateAPIKeyResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.GatewayAPIKeysPath + "/" + seg(id) + "/rotate", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Create creates a resource and returns its creation receipt.
func (c *UsageLimitsClient) Create(ctx context.Context, req schema.CreateUsageLimitsPolicyRequest) (*schema.CreatePolicyResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.CreatePolicyResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.GatewayUsageLimitsPath, Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// List lists resources with explicit scope and pagination.
func (c *UsageLimitsClient) List(ctx context.Context, opts schema.UsageLimitsListOptions) (*schema.UsageLimitsPolicyListResponse, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.UsageLimitsPolicyListResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayUsageLimitsPath, Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Get reads the resource.
func (c *UsageLimitsClient) Get(ctx context.Context, policyUsageLimitsID string, opts schema.UsageLimitsGetOptions) (*schema.UsageLimitsPolicyResponse, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.UsageLimitsPolicyResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayUsageLimitsPath + "/" + seg(policyUsageLimitsID), Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Update updates supplied fields; nested documents may replace stored values.
func (c *UsageLimitsClient) Update(ctx context.Context, policyUsageLimitsID string, req schema.UpdateUsageLimitsPolicyRequest) (*schema.UsageLimitsUpdateResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.UsageLimitsUpdateResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayUsageLimitsPath + "/" + seg(policyUsageLimitsID), Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Delete deletes the resource.
func (c *UsageLimitsClient) Delete(ctx context.Context, policyUsageLimitsID string) (*schema.UsageLimitsDeleteResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.UsageLimitsDeleteResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodDelete, Path: aisec.GatewayUsageLimitsPath + "/" + seg(policyUsageLimitsID)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListEntities calls the explicit ListEntities lifecycle operation.
func (c *UsageLimitsClient) ListEntities(ctx context.Context, policyUsageLimitsID string, opts schema.UsageLimitsListEntitiesOptions) (*schema.UsageLimitsPolicyEntityListResponse, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.UsageLimitsPolicyEntityListResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayUsageLimitsPath + "/" + seg(policyUsageLimitsID) + "/entities", Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ResetEntity calls the explicit ResetEntity lifecycle operation.
func (c *UsageLimitsClient) ResetEntity(ctx context.Context, policyUsageLimitsID string, entityID string) (*schema.UsageLimitsResetEntityResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.UsageLimitsResetEntityResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayUsageLimitsPath + "/" + seg(policyUsageLimitsID) + "/entities/" + seg(entityID) + "/reset"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Create creates a resource and returns its creation receipt.
func (c *RateLimitsClient) Create(ctx context.Context, req schema.CreateRateLimitsPolicyRequest) (*schema.CreatePolicyResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.CreatePolicyResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.GatewayRateLimitsPath, Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// List lists resources with explicit scope and pagination.
func (c *RateLimitsClient) List(ctx context.Context, opts schema.RateLimitsListOptions) (*schema.RateLimitsPolicyListResponse, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.RateLimitsPolicyListResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayRateLimitsPath, Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Get reads the resource.
func (c *RateLimitsClient) Get(ctx context.Context, rateLimitsPolicyID string, opts schema.RateLimitsGetOptions) (*schema.RateLimitsPolicyResponse, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.RateLimitsPolicyResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayRateLimitsPath + "/" + seg(rateLimitsPolicyID), Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Update updates supplied fields; nested documents may replace stored values.
func (c *RateLimitsClient) Update(ctx context.Context, rateLimitsPolicyID string, req schema.UpdateRateLimitsPolicyRequest) (*schema.RateLimitsUpdateResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.RateLimitsUpdateResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayRateLimitsPath + "/" + seg(rateLimitsPolicyID), Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Delete deletes the resource.
func (c *RateLimitsClient) Delete(ctx context.Context, rateLimitsPolicyID string) (*schema.RateLimitsDeleteResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.RateLimitsDeleteResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodDelete, Path: aisec.GatewayRateLimitsPath + "/" + seg(rateLimitsPolicyID)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// List lists resources with explicit scope and pagination.
func (c *SecretReferencesClient) List(ctx context.Context, opts schema.SecretReferencesListOptions) (*schema.SecretReferencesListResponse, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.SecretReferencesListResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewaySecretReferencesPath, Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Create creates a resource and returns its creation receipt.
func (c *SecretReferencesClient) Create(ctx context.Context, req schema.CreateSecretReferenceRequest) (*schema.SecretReferencesCreateResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.SecretReferencesCreateResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.GatewaySecretReferencesPath, Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Get reads the resource.
func (c *SecretReferencesClient) Get(ctx context.Context, secretReferenceID string) (*schema.SecretReferenceDetailResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.SecretReferenceDetailResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewaySecretReferencesPath + "/" + seg(secretReferenceID)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Update updates supplied fields; nested documents may replace stored values.
func (c *SecretReferencesClient) Update(ctx context.Context, secretReferenceID string, req schema.UpdateSecretReferenceRequest) (*schema.SecretReferencesUpdateResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.SecretReferencesUpdateResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewaySecretReferencesPath + "/" + seg(secretReferenceID), Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Delete deletes the resource.
func (c *SecretReferencesClient) Delete(ctx context.Context, secretReferenceID string) (*schema.SecretReferencesDeleteResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.SecretReferencesDeleteResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodDelete, Path: aisec.GatewaySecretReferencesPath + "/" + seg(secretReferenceID)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// List lists resources with explicit scope and pagination.
func (c *DeploymentsClient) List(ctx context.Context, opts schema.DeploymentsListOptions) (*schema.DeploymentsListResponse, error) {
	query, err := queryValues(opts, []string{"tags"})
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.DeploymentsListResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayDeploymentsPath, Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Create creates a resource and returns its creation receipt.
func (c *DeploymentsClient) Create(ctx context.Context, req schema.CreateDeploymentRequest) (*schema.DeploymentCreateResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.DeploymentCreateResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.GatewayDeploymentsPath, Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Get reads the resource.
func (c *DeploymentsClient) Get(ctx context.Context, deploymentID string) (*schema.DeploymentDetailResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.DeploymentDetailResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayDeploymentsPath + "/" + seg(deploymentID)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Update updates supplied fields; nested documents may replace stored values.
func (c *DeploymentsClient) Update(ctx context.Context, deploymentID string, req schema.UpdateDeploymentRequest) (*schema.DeploymentsUpdateResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.DeploymentsUpdateResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayDeploymentsPath + "/" + seg(deploymentID), Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Delete archives the deployment; archived records remain readable.
func (c *DeploymentsClient) Delete(ctx context.Context, deploymentID string) (*schema.DeploymentsDeleteResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.DeploymentsDeleteResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodDelete, Path: aisec.GatewayDeploymentsPath + "/" + seg(deploymentID)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Ping checks deployment connectivity without provisioning.
func (c *DeploymentsClient) Ping(ctx context.Context, deploymentID string) (*schema.DeploymentPingResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.DeploymentPingResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayDeploymentsPath + "/" + seg(deploymentID) + "/ping"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}
