package gateway

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"net/http"
	"regexp"
	"strings"

	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	"github.com/cdot65/prisma-airs-go/aisec/internal/typedhttp"
)

// IAMScopeResource binds a resource to an SCM IAM scope. Workspace ResourceID is its slug, not UUID.
type IAMScopeResource struct {
	ResourceType     string                     `json:"resource_type"`
	ResourceID       string                     `json:"resource_id"`
	Metadata         []any                      `json:"metadata"`
	AdditionalFields map[string]json.RawMessage `json:"-"`
}

// IAMScope is keyed by Name; ID (name:tsg) is display-only.
type IAMScope struct {
	Name             string                     `json:"name"`
	Description      string                     `json:"description"`
	Resources        []IAMScopeResource         `json:"resources"`
	TSGID            string                     `json:"tsg_id"`
	ID               string                     `json:"id"`
	AdditionalFields map[string]json.RawMessage `json:"-"`
}

// IAMScopeListResponse preserves the observed, unpaginated list envelope.
type IAMScopeListResponse struct {
	Count            int                        `json:"count"`
	Items            []IAMScope                 `json:"items"`
	AdditionalFields map[string]json.RawMessage `json:"-"`
}

// IAMScopeCreateInput defaults Description and Resources to empty values on the wire.
type IAMScopeCreateInput struct {
	Name        string
	Description string
	Resources   []IAMScopeResource
}

// IAMScopeUpdateInput replaces both description and all resource bindings; omitted Resources clears them.
type IAMScopeUpdateInput struct {
	Description string
	Resources   []IAMScopeResource
}

// IAMScopesClient manages SCM IAM scopes using captured TypeScript SDK contracts, outside published Gateway coverage.
type IAMScopesClient struct{ cfg *internal.OAuthServiceConfig }

var scopeNamePattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
var workspaceStemPattern = regexp.MustCompile(`[^a-z0-9]+`)

func invalidInput(message string) error {
	return aisec.NewAISecSDKError(message, aisec.UserRequestPayloadError)
}
func validateScopeName(name string) error {
	if !scopeNamePattern.MatchString(name) {
		return invalidInput("expected an IAM scope name, not a composite scope ID")
	}
	return nil
}
func scopeBody(name, description string, resources []IAMScopeResource) (IAMScope, error) {
	if err := validateScopeName(name); err != nil {
		return IAMScope{}, err
	}
	normalized := make([]IAMScopeResource, len(resources))
	for i, r := range resources {
		if r.ResourceType == "" || r.ResourceID == "" {
			return IAMScope{}, invalidInput("scope resource type and ID must be nonempty")
		}
		normalized[i] = IAMScopeResource{ResourceType: r.ResourceType, ResourceID: r.ResourceID, Metadata: r.Metadata}
		if r.Metadata == nil {
			normalized[i].Metadata = []any{}
		}
	}
	return IAMScope{Name: name, Description: description, Resources: normalized}, nil
}

// GenerateWorkspaceScopeName creates ws_<normalized-name>_<six random alphanumerics>, without contacting SCM.
func GenerateWorkspaceScopeName(workspaceName string) (string, error) {
	stem := strings.Trim(workspaceStemPattern.ReplaceAllString(strings.ToLower(workspaceName), "_"), "_")
	if stem == "" {
		stem = "workspace"
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	suffix := make([]byte, 6)
	for i := range suffix {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", aisec.WrapError("could not generate scope name", aisec.AISecSDKInternalError, err)
		}
		suffix[i] = alphabet[n.Int64()]
	}
	return "ws_" + stem + "_" + string(suffix), nil
}

// List reads all scopes returned by the observed IAM list contract.
func (c *IAMScopesClient) List(ctx context.Context) (*IAMScopeListResponse, error) {
	r, err := typedhttp.Do[IAMScopeListResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.IAMScopesPath}, ResponseSchema: "IamScopeListResponseSchema"})
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Get reads a scope by name, never by its composite ID.
func (c *IAMScopesClient) Get(ctx context.Context, name string) (*IAMScope, error) {
	if err := validateScopeName(name); err != nil {
		return nil, err
	}
	r, err := typedhttp.Do[IAMScope](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.IAMScopesPath + "/" + seg(name)}, ResponseSchema: "IamScopeSchema"})
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Create creates an unbound scope unless explicit resource bindings are supplied.
func (c *IAMScopesClient) Create(ctx context.Context, input IAMScopeCreateInput) (*IAMScope, error) {
	body, err := scopeBody(input.Name, input.Description, input.Resources)
	if err != nil {
		return nil, err
	}
	return c.write(ctx, http.MethodPost, aisec.IAMScopesPath, body)
}

// Update fully replaces a scope; use BindWorkspace for an additive binding.
func (c *IAMScopesClient) Update(ctx context.Context, name string, input IAMScopeUpdateInput) (*IAMScope, error) {
	body, err := scopeBody(name, input.Description, input.Resources)
	if err != nil {
		return nil, err
	}
	return c.write(ctx, http.MethodPut, aisec.IAMScopesPath+"/"+seg(name), body)
}
func (c *IAMScopesClient) write(ctx context.Context, method, path string, body IAMScope) (*IAMScope, error) {
	// Do not send the display-only ID or tenant fields back to IAM.
	input := struct {
		Name        string             `json:"name"`
		Description string             `json:"description"`
		Resources   []IAMScopeResource `json:"resources"`
	}{body.Name, body.Description, body.Resources}
	cfg := *c.cfg
	cfg.NumRetries = 0 // POST outcomes must remain identifiable; no replay after ambiguous failures.
	requestSchema := "IamScopeCreateRequestSchema"
	if method == http.MethodPut {
		requestSchema = "IamScopeUpdateRequestSchema"
	}
	r, err := typedhttp.Do[IAMScope](ctx, &cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: method, Path: path, Body: input}, RequestSchema: requestSchema, ResponseSchema: "IamScopeSchema"})
	if err != nil {
		return nil, err
	}
	return r, nil
}

// BindWorkspace preserves existing bindings and description, then PUTs a binding by workspace slug.
// This read/replace operation is idempotent, but is not atomic with concurrent scope updates.
// It does not assign a service-account role or access policy.
func (c *IAMScopesClient) BindWorkspace(ctx context.Context, name, workspaceSlug string) (*IAMScope, error) {
	if !workspaceRefPattern.MatchString(workspaceSlug) {
		return nil, invalidInput("expected a workspace slug")
	}
	current, err := c.Get(ctx, name)
	if err != nil {
		return nil, err
	}
	resources := append([]IAMScopeResource(nil), current.Resources...)
	found := false
	for _, r := range resources {
		if r.ResourceType == "workspace" && r.ResourceID == workspaceSlug {
			found = true
		}
	}
	if !found {
		resources = append(resources, IAMScopeResource{ResourceType: "workspace", ResourceID: workspaceSlug, Metadata: []any{}})
	}
	return c.Update(ctx, name, IAMScopeUpdateInput{Description: current.Description, Resources: resources})
}

// Delete attempts the TypeScript SDK's inferred scope-delete route. This route is not live-verified.
// A 404/405 is returned as an error, not interpreted as successful cleanup.
func (c *IAMScopesClient) Delete(ctx context.Context, name string) error {
	if err := validateScopeName(name); err != nil {
		return err
	}
	_, err := internal.DoMgmtRequest[any](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodDelete, Path: aisec.IAMScopesPath + "/" + seg(name), ResponsePolicy: internal.AllowEmptyJSON})
	return err
}

func (x IAMScopeResource) MarshalJSON() ([]byte, error) {
	type plain IAMScopeResource
	return scopeMarshalExtra(plain(x), x.AdditionalFields, []string{"resource_type", "resource_id", "metadata"})
}
func (x *IAMScopeResource) UnmarshalJSON(data []byte) error {
	type plain IAMScopeResource
	var value plain
	extra, err := scopeUnmarshalExtra(data, &value, []string{"resource_type", "resource_id", "metadata"})
	if err != nil {
		return err
	}
	value.AdditionalFields = extra
	*x = IAMScopeResource(value)
	return nil
}

func (x IAMScope) MarshalJSON() ([]byte, error) {
	type plain IAMScope
	return scopeMarshalExtra(plain(x), x.AdditionalFields, []string{"name", "description", "resources", "tsg_id", "id"})
}
func (x *IAMScope) UnmarshalJSON(data []byte) error {
	type plain IAMScope
	var value plain
	extra, err := scopeUnmarshalExtra(data, &value, []string{"name", "description", "resources", "tsg_id", "id"})
	if err != nil {
		return err
	}
	value.AdditionalFields = extra
	*x = IAMScope(value)
	return nil
}

func (x IAMScopeListResponse) MarshalJSON() ([]byte, error) {
	type plain IAMScopeListResponse
	return scopeMarshalExtra(plain(x), x.AdditionalFields, []string{"count", "items"})
}
func (x *IAMScopeListResponse) UnmarshalJSON(data []byte) error {
	type plain IAMScopeListResponse
	var value plain
	extra, err := scopeUnmarshalExtra(data, &value, []string{"count", "items"})
	if err != nil {
		return err
	}
	value.AdditionalFields = extra
	*x = IAMScopeListResponse(value)
	return nil
}

func scopeMarshalExtra(value any, extra map[string]json.RawMessage, keys []string) ([]byte, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(b, &fields); err != nil {
		return nil, err
	}
	for k, v := range extra {
		known := false
		for _, key := range keys {
			known = known || k == key
		}
		if !known {
			fields[k] = v
		}
	}
	return json.Marshal(fields)
}
func scopeUnmarshalExtra(data []byte, value any, keys []string) (map[string]json.RawMessage, error) {
	if err := json.Unmarshal(data, value); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	for _, k := range keys {
		delete(fields, k)
	}
	return fields, nil
}
