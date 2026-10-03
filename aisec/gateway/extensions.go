package gateway

import (
	"context"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	"github.com/cdot65/prisma-airs-go/aisec/internal/typedhttp"
	parity "github.com/cdot65/prisma-airs-go/aisec/parity/schema"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// OrganisationsClient exposes the pinned TypeScript Gateway management surface.
type OrganisationsClient struct{ cfg *internal.OAuthServiceConfig }

// GetInfo calls GET /organisations/{tsgId}/info on its explicitly configured SCM plane.
func (c *OrganisationsClient) GetInfo(ctx context.Context, tsgId string) (*parity.GatewayOrganisationInfo, error) {
	if !numericTenantPattern.MatchString(tsgId) {
		return nil, invalidInput("organisation ID must be numeric")
	}
	return typedhttp.Do[parity.GatewayOrganisationInfo](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayOrganisationsPath + "/" + seg(tsgId) + aisec.GatewayInfoPath}, ResponseSchema: "GatewayOrganisationInfoSchema"})
}

// GetSelf calls GET /organisations/self on its explicitly configured SCM plane.
func (c *OrganisationsClient) GetSelf(ctx context.Context) (*parity.OrganisationSelfResponse, error) {
	return typedhttp.Do[parity.OrganisationSelfResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayOrganisationsSelfPath}, ResponseSchema: "OrganisationSelfResponseSchema"})
}

// UpdateSelf calls PUT /organisations/self on its explicitly configured SCM plane.
func (c *OrganisationsClient) UpdateSelf(ctx context.Context, body parity.GatewayOrganisationUpdateRequest) (*parity.GatewayWriteResponse, error) {
	return typedhttp.Do[parity.GatewayWriteResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayOrganisationsSelfPath, Body: body}, RequestSchema: "GatewayOrganisationUpdateRequestSchema", ResponseSchema: "GatewayWriteResponseSchema"})
}

// GetAuthSettings calls GET /organisations/{tsgId}/auth-settings on its explicitly configured SCM plane.
func (c *OrganisationsClient) GetAuthSettings(ctx context.Context, tsgId string) (*parity.AuthSettingsResponse, error) {
	if !numericTenantPattern.MatchString(tsgId) {
		return nil, invalidInput("organisation ID must be numeric")
	}
	return typedhttp.Do[parity.AuthSettingsResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayOrganisationsPath + "/" + seg(tsgId) + aisec.GatewayAuthSettingsPath}, ResponseSchema: "AuthSettingsResponseSchema"})
}

// UpdateAuthSettings calls PUT /organisations/{tsgId}/auth-settings on its explicitly configured SCM plane.
func (c *OrganisationsClient) UpdateAuthSettings(ctx context.Context, tsgId string, body parity.GatewayOrganisationAuthSettingsUpdateRequest) (*parity.GatewayWriteResponse, error) {
	if !numericTenantPattern.MatchString(tsgId) {
		return nil, invalidInput("organisation ID must be numeric")
	}
	return typedhttp.Do[parity.GatewayWriteResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayOrganisationsPath + "/" + seg(tsgId) + aisec.GatewayAuthSettingsPath, Body: body}, RequestSchema: "GatewayOrganisationAuthSettingsUpdateRequestSchema", ResponseSchema: "GatewayWriteResponseSchema"})
}

// PluginsClient exposes the pinned TypeScript Gateway management surface.
type PluginsClient struct{ cfg *internal.OAuthServiceConfig }

// List calls GET /plugins on its explicitly configured SCM plane.
func (c *PluginsClient) List(ctx context.Context) (*parity.ListPluginsResponse, error) {
	return typedhttp.Do[parity.ListPluginsResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayPluginsPath}, ResponseSchema: "ListPluginsResponseSchema"})
}

// Create calls POST /plugins on its explicitly configured SCM plane.
func (c *PluginsClient) Create(ctx context.Context, body parity.GatewayPluginCreateRequest) (*parity.GatewayWriteResponse, error) {
	return typedhttp.Do[parity.GatewayWriteResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.GatewayPluginsPath, Body: body}, RequestSchema: "GatewayPluginCreateRequestSchema", ResponseSchema: "GatewayWriteResponseSchema"})
}

// AuditLogsClient exposes the pinned TypeScript Gateway management surface.
type AuditLogsClient struct{ cfg *internal.OAuthServiceConfig }

// List calls GET /audit-logs on its explicitly configured SCM plane.
func (c *AuditLogsClient) List(ctx context.Context, opts AuditLogListOptions) (*parity.GatewayAuditLogsResponse, error) {
	if opts.Start.IsZero() || opts.End.IsZero() || opts.Start.After(opts.End) {
		return nil, invalidInput("invalid audit-log time window")
	}
	return typedhttp.Do[parity.GatewayAuditLogsResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayAuditLogsPath, Params: map[string]string{"start_time": opts.Start.UTC().Format("2006-01-02T15:04:05.000Z07:00"), "end_time": opts.End.UTC().Format("2006-01-02T15:04:05.000Z07:00")}}, ResponseSchema: "GatewayAuditLogsResponseSchema"})
}

// LogExportsClient exposes the pinned TypeScript Gateway management surface.
type LogExportsClient struct{ cfg *internal.OAuthServiceConfig }

// List calls GET /logs/exports on its explicitly configured SCM plane.
func (c *LogExportsClient) List(ctx context.Context, opts parity.GatewayLogExportsClientListOptions) (*parity.GatewayLogExportsClientListResponse, error) {
	if err := parity.Validate("GatewayLogExportsClientListOptionsSchema", opts); err != nil {
		return nil, aisec.WrapError("invalid log export query", aisec.UserRequestPayloadError, err)
	}
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.GatewayLogExportsClientListResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayLogsExportsPath, Query: query}, ResponseSchema: "GatewayLogExportsClientListResponseSchema"})
}

// Create calls POST /logs/exports on its explicitly configured SCM plane.
func (c *LogExportsClient) Create(ctx context.Context, body parity.GatewayLogExportsClientCreateRequest) (*parity.GatewayLogExportsClientCreateResponse, error) {
	return typedhttp.Do[parity.GatewayLogExportsClientCreateResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.GatewayLogsExportsPath, Body: body}, RequestSchema: "GatewayLogExportsClientCreateRequestSchema", ResponseSchema: "GatewayLogExportsClientCreateResponseSchema"})
}

// Get calls GET /logs/exports/{exportId} on its explicitly configured SCM plane.
func (c *LogExportsClient) Get(ctx context.Context, exportId string) (*parity.GatewayLogExportsClientGetResponse, error) {
	if err := validateResourceID(exportId); err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.GatewayLogExportsClientGetResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayLogsExportsPath + "/" + seg(exportId) + ""}, ResponseSchema: "GatewayLogExportsClientGetResponseSchema"})
}

// Update calls PUT /logs/exports/{exportId} on its explicitly configured SCM plane.
func (c *LogExportsClient) Update(ctx context.Context, exportId string, body parity.GatewayLogExportsClientUpdateRequest) (*parity.GatewayLogExportsClientUpdateResponse, error) {
	if err := validateResourceID(exportId); err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.GatewayLogExportsClientUpdateResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayLogsExportsPath + "/" + seg(exportId) + "", Body: body}, RequestSchema: "GatewayLogExportsClientUpdateRequestSchema", ResponseSchema: "GatewayLogExportsClientUpdateResponseSchema"})
}

// Start calls POST /logs/exports/{exportId}/start on its explicitly configured SCM plane.
func (c *LogExportsClient) Start(ctx context.Context, exportId string) (*parity.GatewayLogExportsClientStartResponse, error) {
	if err := validateResourceID(exportId); err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.GatewayLogExportsClientStartResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.GatewayLogsExportsPath + "/" + seg(exportId) + aisec.GatewayStartPath}, ResponseSchema: "GatewayLogExportsClientStartResponseSchema"})
}

// Cancel calls POST /logs/exports/{exportId}/cancel on its explicitly configured SCM plane.
func (c *LogExportsClient) Cancel(ctx context.Context, exportId string) (*parity.GatewayLogExportsClientCancelResponse, error) {
	if err := validateResourceID(exportId); err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.GatewayLogExportsClientCancelResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.GatewayLogsExportsPath + "/" + seg(exportId) + aisec.GatewayCancelPath}, ResponseSchema: "GatewayLogExportsClientCancelResponseSchema"})
}

// Download calls GET /logs/exports/{exportId}/download on its explicitly configured SCM plane.
func (c *LogExportsClient) Download(ctx context.Context, exportId string) (*parity.GatewayLogExportsClientDownloadResponse, error) {
	if err := validateResourceID(exportId); err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.GatewayLogExportsClientDownloadResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayLogsExportsPath + "/" + seg(exportId) + aisec.GatewayDownloadPath}, ResponseSchema: "GatewayLogExportsClientDownloadResponseSchema"})
}

// AuditLogListOptions bounds sensitive audit records; raw request bodies may contain secrets.
type AuditLogListOptions struct{ Start, End time.Time }

func validateResourceID(value string) error {
	if strings.TrimSpace(value) == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > 512 || value == "." || value == ".." {
		return invalidInput("nonempty resource identifier required")
	}
	return nil
}
