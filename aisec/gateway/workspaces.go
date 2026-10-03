package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	"github.com/cdot65/prisma-airs-go/aisec/internal/typedhttp"
	parity "github.com/cdot65/prisma-airs-go/aisec/parity/schema"
)

// WorkspaceCreateRequest is the captured SCM create body; ScopeName must already exist for Create.
// Provision may generate ScopeName or reuse a caller-provided one.
type WorkspaceCreateRequest = parity.GatewayWorkspaceCreateRequest

// WorkspaceUpdateRequest changes supplied fields; nested settings may be replaced.
type WorkspaceUpdateRequest = parity.GatewayWorkspaceUpdateRequest

// WorkspaceCreateResponse is a creation receipt; Get returns the additional settings.
type WorkspaceCreateResponse = parity.GatewayWorkspaceCreateResponse

// WorkspaceDetail preserves nullable descriptions/settings and unknown response fields.
type WorkspaceDetail = parity.GatewayWorkspaceDetail

// WorkspaceListResponse preserves list rows, lifecycle status and the list envelope.
type WorkspaceListResponse = parity.ListWorkspacesResponse

// WorkspacePlane chooses scoped management reads or tenant-wide admin reads.
type WorkspacePlane string

const (
	WorkspaceData  WorkspacePlane = "data"
	WorkspaceAdmin WorkspacePlane = "admin"
)

// WorkspaceListOptions filters lifecycle state; the server defaults to active workspaces.
type WorkspaceListOptions struct {
	Plane  WorkspacePlane
	Status string
}

// WorkspaceGetOptions defaults to the scoped data/control plane.
type WorkspaceGetOptions struct{ Plane WorkspacePlane }

// WorkspaceProvisionOptions can reuse an existing scope, preserving all its bindings.
type WorkspaceProvisionOptions struct{ ExistingScope bool }

// WorkspaceProvisionResult retains created identities even when provisioning fails.
type WorkspaceProvisionResult struct {
	ScopeName    string
	ScopeCreated bool
	ScopeDeleted bool
	Scope        *IAMScope
	Workspace    *WorkspaceCreateResponse
}

// WorkspaceProvisionError identifies the failed stage and any best-effort cleanup result.
// Unwrap preserves errors.Is/As for the underlying HTTP or transport failure.
type WorkspaceProvisionError struct {
	Stage            string
	Result           *WorkspaceProvisionResult
	Cause            error
	CleanupAttempted bool
	CleanupError     error
}

func (e *WorkspaceProvisionError) Error() string {
	return fmt.Sprintf("workspace provisioning failed at %s (scope %s): %v", e.Stage, e.Result.ScopeName, e.Cause)
}
func (e *WorkspaceProvisionError) Unwrap() error { return e.Cause }

// WorkspacesClient handles management reads, admin writes and IAM-first provisioning.
type WorkspacesClient struct {
	dataCfg, adminCfg *internal.OAuthServiceConfig
	scopes            *IAMScopesClient
}

var workspaceRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

func (c *WorkspacesClient) plane(p WorkspacePlane) (*internal.OAuthServiceConfig, error) {
	switch p {
	case "", WorkspaceData:
		return c.dataCfg, nil
	case WorkspaceAdmin:
		return c.adminCfg, nil
	default:
		return nil, invalidInput("workspace plane must be data or admin")
	}
}

// List reads scoped workspaces, or tenant workspaces on the admin plane.
// It preserves Total and HasMore; the captured contract provides no paging parameters.
func (c *WorkspacesClient) List(ctx context.Context, opts WorkspaceListOptions) (*WorkspaceListResponse, error) {
	cfg, err := c.plane(opts.Plane)
	if err != nil {
		return nil, err
	}
	params := map[string]string{}
	if opts.Status != "" {
		params["status"] = opts.Status
	}
	r, err := typedhttp.Do[WorkspaceListResponse](ctx, cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayWorkspacesPath, Params: params}, ResponseSchema: "ListWorkspacesResponseSchema"})
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Get reads a workspace UUID or slug; archived workspaces return 404 in recorded traffic.
func (c *WorkspacesClient) Get(ctx context.Context, ref string, opts WorkspaceGetOptions) (*WorkspaceDetail, error) {
	if !workspaceRefPattern.MatchString(ref) {
		return nil, invalidInput("expected a workspace UUID or slug")
	}
	cfg, err := c.plane(opts.Plane)
	if err != nil {
		return nil, err
	}
	r, err := typedhttp.Do[WorkspaceDetail](ctx, cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayWorkspacesPath + "/" + seg(ref)}, ResponseSchema: "GatewayWorkspaceDetailSchema"})
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Create creates an admin-plane workspace using an existing IAM scope.
func (c *WorkspacesClient) Create(ctx context.Context, req WorkspaceCreateRequest) (*WorkspaceCreateResponse, error) {
	if req.Name == "" {
		return nil, invalidInput("workspace name is required")
	}
	if err := validateScopeName(string(req.ScopeName)); err != nil {
		return nil, err
	}
	if err := parity.Validate("GatewayWorkspaceCreateRequestSchema", req); err != nil {
		return nil, aisec.WrapError("invalid workspace request", aisec.UserRequestPayloadError, err)
	}
	cfg := *c.adminCfg
	cfg.NumRetries = 0
	r, err := typedhttp.Do[WorkspaceCreateResponse](ctx, &cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.GatewayWorkspacesPath, Body: req}, ResponseSchema: "GatewayWorkspaceCreateResponseSchema"})
	if err != nil {
		return nil, err
	}
	if r.ID == "" || !workspaceRefPattern.MatchString(r.Slug) {
		return nil, aisec.NewAISecSDKError("workspace creation response lacks its ID or slug; creation outcome is uncertain", aisec.AISecSDKInternalError)
	}
	return r, nil
}

// Update sends an admin-plane partial update. The recorded response is an empty JSON acknowledgement;
// Get on the admin plane obtains the resulting settings.
func (c *WorkspacesClient) Update(ctx context.Context, ref string, req WorkspaceUpdateRequest) error {
	if !workspaceRefPattern.MatchString(ref) {
		return invalidInput("expected a workspace UUID or slug")
	}
	if req.Name == nil && req.Description == nil && req.Icon == nil && req.Defaults == nil && req.UsageLimits == nil && req.RateLimits == nil {
		return invalidInput("at least one workspace field must be supplied")
	}
	if req.Name != nil && *req.Name == "" {
		return invalidInput("workspace name must be nonempty")
	}
	if err := parity.Validate("GatewayWorkspaceUpdateRequestSchema", req); err != nil {
		return aisec.WrapError("invalid workspace update", aisec.UserRequestPayloadError, err)
	}
	_, err := internal.DoMgmtRequest[any](ctx, c.adminCfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayWorkspacesPath + "/" + seg(ref), Body: req, ResponsePolicy: internal.AllowEmptyJSON})
	return err
}

// Delete archives a workspace, rather than hard-deleting it. Archived list rows remain available.
func (c *WorkspacesClient) Delete(ctx context.Context, ref string) error {
	if !workspaceRefPattern.MatchString(ref) {
		return invalidInput("expected a workspace UUID or slug")
	}
	_, err := internal.DoMgmtRequest[any](ctx, c.adminCfg, internal.MgmtRequestOptions{Method: http.MethodDelete, Path: aisec.GatewayWorkspacesPath + "/" + seg(ref), ResponsePolicy: internal.AllowEmptyJSON})
	return err
}

// Provision creates/reuses an IAM scope, creates the workspace, then binds its slug.
// No role assignment is made. Writes are not automatically replayed. On an explicit client rejection,
// a newly created scope is cleaned up best-effort through the unverified IAM DELETE route. Ambiguous
// creation outcomes retain the scope. Binding failures retain both objects and report their identities.
func (c *WorkspacesClient) Provision(ctx context.Context, req WorkspaceCreateRequest, opts WorkspaceProvisionOptions) (*WorkspaceProvisionResult, error) {
	if req.Name == "" {
		return nil, invalidInput("workspace name is required")
	}
	if c.scopes == nil {
		return nil, aisec.NewAISecSDKError("workspace provisioning requires an IAM scopes client", aisec.MissingVariableError)
	}
	name := string(req.ScopeName)
	if name == "" {
		if opts.ExistingScope {
			return nil, invalidInput("existing scope requires ScopeName")
		}
		var err error
		name, err = GenerateWorkspaceScopeName(req.Name)
		if err != nil {
			return nil, err
		}
	}
	if err := validateScopeName(name); err != nil {
		return nil, err
	}
	req.ScopeName = parity.GatewayWorkspaceCreateRequestSchemaRef1(name)
	if err := parity.Validate("GatewayWorkspaceCreateRequestSchema", req); err != nil {
		return nil, aisec.WrapError("invalid workspace request", aisec.UserRequestPayloadError, err)
	}
	result := &WorkspaceProvisionResult{ScopeName: name}
	fail := func(stage string, cause error) *WorkspaceProvisionError {
		return &WorkspaceProvisionError{Stage: stage, Result: result, Cause: cause}
	}
	if !opts.ExistingScope {
		desc := ""
		if req.Description != nil {
			desc = *req.Description
		}
		scope, err := c.scopes.Create(ctx, IAMScopeCreateInput{Name: name, Description: desc})
		if err != nil {
			return result, fail("scope_create", err)
		}
		result.Scope = scope
		result.ScopeCreated = true
	}

	workspace, err := c.Create(ctx, req)
	if err != nil {
		failure := fail("workspace_create", err)
		var httpErr *aisec.AISecSDKError
		if result.ScopeCreated && errors.As(err, &httpErr) && httpErr.StatusCode >= 400 && httpErr.StatusCode < 500 && httpErr.StatusCode != 408 && httpErr.StatusCode != 425 && httpErr.StatusCode != 429 {
			failure.CleanupAttempted = true
			failure.CleanupError = c.scopes.Delete(ctx, name)
			if failure.CleanupError == nil {
				result.Scope = nil
				result.ScopeDeleted = true
			}
		}
		return result, failure
	}
	result.Workspace = workspace
	scope, err := c.scopes.BindWorkspace(ctx, name, workspace.Slug)
	if err != nil {
		return result, fail("scope_bind", err)
	}
	result.Scope = scope
	return result, nil
}
