package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
)

// Opts are options for creating a ManagementClient.
type Opts struct {
	ClientID      string
	ClientSecret  string
	TsgID         string
	APIEndpoint   string
	TokenEndpoint string
	NumRetries    int
	// HTTPClient overrides the HTTP client used for API and token requests
	// (timeouts, proxies, transports, tracing). Defaults to the SDK client.
	HTTPClient *http.Client
}

// Client is the Management API client with 8 sub-clients.
type Client struct {
	Profiles           *ProfilesClient
	Topics             *TopicsClient
	ApiKeys            *ApiKeysClient
	CustomerApps       *CustomerAppsClient
	DlpProfiles        *DlpProfilesClient
	DeploymentProfiles *DeploymentProfilesClient
	ScanLogs           *ScanLogsClient
	OAuth              *OAuthManagementClient

	svcCfg *internal.OAuthServiceConfig
}

// NewClient creates a new Management API client.
func NewClient(opts Opts) (*Client, error) {
	// Base URL: option -> PANW_MGMT_ENDPOINT -> default.
	endpoint := internal.ResolveEndpoint(opts.APIEndpoint, aisec.EnvMgmtEndpoint, aisec.DefaultMgmtEndpoint)

	svcCfg, err := internal.ResolveOAuthConfig(internal.ResolveOAuthConfigOpts{
		ClientID:         opts.ClientID,
		ClientSecret:     opts.ClientSecret,
		TsgID:            opts.TsgID,
		BaseURL:          endpoint,
		NumRetries:       opts.NumRetries,
		TokenEndpoint:    opts.TokenEndpoint,
		PrimaryEnvPrefix: "PANW_MGMT",
		HTTPClient:       opts.HTTPClient,
	})
	if err != nil {
		return nil, err
	}

	c := &Client{svcCfg: svcCfg}
	c.Profiles = &ProfilesClient{svcCfg: svcCfg, tsgID: svcCfg.TsgID}
	c.Topics = &TopicsClient{svcCfg: svcCfg, tsgID: svcCfg.TsgID}
	c.ApiKeys = &ApiKeysClient{svcCfg: svcCfg, tsgID: svcCfg.TsgID}
	c.CustomerApps = &CustomerAppsClient{svcCfg: svcCfg, tsgID: svcCfg.TsgID}
	c.DlpProfiles = &DlpProfilesClient{svcCfg: svcCfg}
	c.DeploymentProfiles = &DeploymentProfilesClient{svcCfg: svcCfg}
	c.ScanLogs = &ScanLogsClient{svcCfg: svcCfg}
	c.OAuth = &OAuthManagementClient{svcCfg: svcCfg}

	return c, nil
}

func buildListParams(opts ListOpts) map[string]string {
	params := map[string]string{}
	if opts.Limit > 0 {
		params["limit"] = fmt.Sprintf("%d", opts.Limit)
	}
	// Always include offset — the API requires the query parameter even when 0.
	params["offset"] = fmt.Sprintf("%d", opts.Offset)
	return params
}

// ProfilesClient provides CRUD for security profiles.
type ProfilesClient struct {
	svcCfg *internal.OAuthServiceConfig
	tsgID  string
}

func (c *ProfilesClient) Create(ctx context.Context, req CreateProfileRequest) (*SecurityProfile, error) {
	resp, err := internal.DoMgmtRequest[SecurityProfile](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.MgmtProfilePath, Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ProfilesClient) List(ctx context.Context, opts ListOpts) (*SecurityProfileListResponse, error) {
	resp, err := internal.DoMgmtRequest[SecurityProfileListResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.MgmtProfilesTsgPath + "/" + c.tsgID, Params: buildListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ProfilesClient) Update(ctx context.Context, profileID string, req UpdateProfileRequest) (*SecurityProfile, error) {
	resp, err := internal.DoMgmtRequest[SecurityProfile](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodPut, Path: aisec.MgmtProfilePath + "/uuid/" + seg(profileID), Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ProfilesClient) Delete(ctx context.Context, profileID string) (*DeleteProfileResponse, error) {
	resp, err := internal.DoMgmtRequest[DeleteProfileResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodDelete, Path: aisec.MgmtProfilePath + "/" + seg(profileID),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// lookupPageSize is the page size used by the client-side lookups below.
const lookupPageSize = 1000

// maxLookupPages bounds client-side lookups so a misbehaving server that never
// ends its pagination cannot loop forever.
const maxLookupPages = 1000

// paginate walks a list endpoint page by page, calling visit for every item
// until visit returns true or the pages run out. fetch returns the page items
// and the server's next offset (0 when it does not provide one).
func paginate[T any](fetch func(opts ListOpts) ([]T, int, error), visit func(T) (stop bool)) error {
	offset := 0
	for page := 0; page < maxLookupPages; page++ {
		items, next, err := fetch(ListOpts{Limit: lookupPageSize, Offset: offset})
		if err != nil {
			return err
		}
		for _, item := range items {
			if visit(item) {
				return nil
			}
		}
		switch {
		case next > offset:
			offset = next
		case len(items) >= lookupPageSize:
			offset += len(items)
		default:
			return nil
		}
	}
	return nil
}

// notFound builds a client-side "not found" error. It carries HTTP 404 so that
// errors.Is(err, aisec.ErrNotFound) behaves the same as for a server 404.
func notFound(what, key string) error {
	return aisec.NewHTTPError(what+" not found: "+key, aisec.ClientSideError, http.StatusNotFound)
}

// GetByID retrieves a single profile by UUID. No dedicated API endpoint exists,
// so this pages through the profile list and filters client-side.
func (c *ProfilesClient) GetByID(ctx context.Context, profileID string) (*SecurityProfile, error) {
	var found *SecurityProfile
	err := paginate(func(o ListOpts) ([]SecurityProfile, int, error) {
		resp, err := c.List(ctx, o)
		if err != nil {
			return nil, 0, err
		}
		return resp.Items, resp.NextOffset, nil
	}, func(p SecurityProfile) bool {
		if p.ProfileID == profileID {
			match := p
			found = &match
			return true
		}
		return false
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, notFound("profile", profileID)
	}
	return found, nil
}

// GetByName retrieves a profile by name. When multiple revisions exist for the
// same name, the one with the highest revision is returned. No dedicated API
// endpoint exists, so this pages through the whole profile list and filters
// client-side.
func (c *ProfilesClient) GetByName(ctx context.Context, name string) (*SecurityProfile, error) {
	var best *SecurityProfile
	err := paginate(func(o ListOpts) ([]SecurityProfile, int, error) {
		resp, err := c.List(ctx, o)
		if err != nil {
			return nil, 0, err
		}
		return resp.Items, resp.NextOffset, nil
	}, func(p SecurityProfile) bool {
		if p.ProfileName == name && (best == nil || p.Revision > best.Revision) {
			match := p
			best = &match
		}
		return false
	})
	if err != nil {
		return nil, err
	}
	if best == nil {
		return nil, notFound("profile", name)
	}
	return best, nil
}

// ForceDelete force-deletes a profile: DELETE /v1/mgmt/profile/{profile_id}/force?updated_by=
func (c *ProfilesClient) ForceDelete(ctx context.Context, profileID string, updatedBy string) (*DeleteProfileResponse, error) {
	resp, err := internal.DoMgmtRequest[deleteMessageResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodDelete,
		Path:   aisec.MgmtProfileForcePath + "/" + seg(profileID) + "/force",
		Params: map[string]string{"updated_by": updatedBy},
		// This endpoint can return plain text on success.
		ResponsePolicy: internal.AllowTextOrEmpty,
	})
	if err != nil {
		return nil, err
	}
	result := DeleteProfileResponse(resp.Data)
	return &result, nil
}

// TopicsClient provides CRUD for custom detection topics.
type TopicsClient struct {
	svcCfg *internal.OAuthServiceConfig
	tsgID  string
}

func (c *TopicsClient) Create(ctx context.Context, req CreateTopicRequest) (*CustomTopic, error) {
	resp, err := internal.DoMgmtRequest[CustomTopic](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.MgmtTopicPath, Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *TopicsClient) List(ctx context.Context, opts ListOpts) (*CustomTopicListResponse, error) {
	resp, err := internal.DoMgmtRequest[CustomTopicListResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.MgmtTopicsTsgPath + "/" + c.tsgID, Params: buildListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *TopicsClient) Update(ctx context.Context, topicID string, req UpdateTopicRequest) (*CustomTopic, error) {
	resp, err := internal.DoMgmtRequest[CustomTopic](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodPut, Path: aisec.MgmtTopicPath + "/uuid/" + seg(topicID), Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// deleteMessageResponse adapts a JSON string or message object for runtime
// deletions without changing their public response types.
type deleteMessageResponse struct {
	Message string `json:"message,omitempty"`
}

func (r *deleteMessageResponse) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		return json.Unmarshal(data, &r.Message)
	}
	// The local type has no UnmarshalJSON method, avoiding recursive decoding.
	type messageObject deleteMessageResponse
	return json.Unmarshal(data, (*messageObject)(r))
}

func (c *TopicsClient) Delete(ctx context.Context, topicID string) (*DeleteTopicResponse, error) {
	resp, err := internal.DoMgmtRequest[deleteMessageResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodDelete, Path: aisec.MgmtTopicPath + "/" + seg(topicID),
		// Preserve the legacy non-JSON success exception; API_ISSUES.md records
		// a parse failure but does not establish the original body's format.
		ResponsePolicy: internal.AllowTextOrEmpty,
	})
	if err != nil {
		return nil, err
	}
	result := DeleteTopicResponse(resp.Data)
	return &result, nil
}

// ForceDelete force-deletes a topic: DELETE /v1/mgmt/topic/force/{topic_id}?updated_by=
func (c *TopicsClient) ForceDelete(ctx context.Context, topicID string, updatedBy string) (*DeleteTopicResponse, error) {
	resp, err := internal.DoMgmtRequest[deleteMessageResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method:         http.MethodDelete,
		Path:           aisec.MgmtTopicForcePath + "/force/" + seg(topicID),
		Params:         map[string]string{"updated_by": updatedBy},
		ResponsePolicy: internal.AllowTextOrEmpty,
	})
	if err != nil {
		return nil, err
	}
	result := DeleteTopicResponse(resp.Data)
	return &result, nil
}

// ApiKeysClient provides API key lifecycle operations.
type ApiKeysClient struct {
	svcCfg *internal.OAuthServiceConfig
	tsgID  string
}

func (c *ApiKeysClient) Create(ctx context.Context, req CreateApiKeyRequest) (*ApiKey, error) {
	resp, err := internal.DoMgmtRequest[ApiKey](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.MgmtAPIKeyPath, Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ApiKeysClient) List(ctx context.Context, opts ListOpts) (*ApiKeyListResponse, error) {
	resp, err := internal.DoMgmtRequest[ApiKeyListResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.MgmtAPIKeysTsgPath + "/" + c.tsgID, Params: buildListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ApiKeysClient) Delete(ctx context.Context, keyName, updatedBy string) (*ApiKeyDeleteResponse, error) {
	resp, err := internal.DoMgmtRequest[ApiKeyDeleteResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodDelete, Path: aisec.MgmtAPIKeyPath + "/delete/" + seg(keyName),
		Params: map[string]string{"updated_by": updatedBy},
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ApiKeysClient) Regenerate(ctx context.Context, keyID string, req RegenerateKeyRequest) (*ApiKey, error) {
	resp, err := internal.DoMgmtRequest[ApiKey](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.MgmtAPIKeyPath + "/" + seg(keyID) + "/regenerate", Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// CustomerAppsClient provides customer app management.
type CustomerAppsClient struct {
	svcCfg *internal.OAuthServiceConfig
	tsgID  string
}

func (c *CustomerAppsClient) List(ctx context.Context, opts ListOpts) (*CustomerAppListResponse, error) {
	resp, err := internal.DoMgmtRequest[CustomerAppListResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.MgmtCustomerAppsPath, Params: buildListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Get retrieves a customer app by name: GET /v1/mgmt/customerapp?app_name=
func (c *CustomerAppsClient) Get(ctx context.Context, appName string) (*CustomerApp, error) {
	resp, err := internal.DoMgmtRequest[CustomerApp](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.MgmtCustomerAppPath,
		Params: map[string]string{"app_name": appName},
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Update updates a customer app: PUT /v1/mgmt/customerapp?customer_app_id=
func (c *CustomerAppsClient) Update(ctx context.Context, customerAppID string, req UpdateAppRequest) (*CustomerApp, error) {
	resp, err := internal.DoMgmtRequest[CustomerApp](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodPut, Path: aisec.MgmtCustomerAppPath,
		Params: map[string]string{"customer_app_id": customerAppID},
		Body:   req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Delete deletes a customer app: DELETE /v1/mgmt/customerapp?app_name=&updated_by=
func (c *CustomerAppsClient) Delete(ctx context.Context, appName string, updatedBy string) (*DeleteAppResponse, error) {
	resp, err := internal.DoMgmtRequest[DeleteAppResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodDelete, Path: aisec.MgmtCustomerAppPath,
		Params: map[string]string{"app_name": appName, "updated_by": updatedBy},
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// DlpProfilesClient provides read-only access to DLP profiles.
type DlpProfilesClient struct {
	svcCfg *internal.OAuthServiceConfig
}

func (c *DlpProfilesClient) List(ctx context.Context, opts ListOpts) (*DlpProfileListResponse, error) {
	resp, err := internal.DoMgmtRequest[DlpProfileListResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.MgmtDLPProfilesPath, Params: buildListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *DlpProfilesClient) Get(ctx context.Context, profileID string) (*DlpProfile, error) {
	// No dedicated get-by-ID endpoint in the API spec.
	// The list endpoint takes no pagination parameters in the spec (it returns
	// every profile), so one call is enough; filter client-side.
	resp, err := c.List(ctx, ListOpts{})
	if err != nil {
		return nil, err
	}
	for _, p := range resp.Items {
		if p.ID == profileID {
			return &p, nil
		}
	}
	return nil, notFound("DLP profile", profileID)
}

// DeploymentProfilesClient provides read-only access to deployment profiles.
type DeploymentProfilesClient struct {
	svcCfg *internal.OAuthServiceConfig
}

func (c *DeploymentProfilesClient) List(ctx context.Context, opts ListOpts) (*DeploymentProfileListResponse, error) {
	resp, err := internal.DoMgmtRequest[DeploymentProfileListResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.MgmtDeploymentProfilesPath, Params: buildListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *DeploymentProfilesClient) Get(ctx context.Context, profileID string) (*DeploymentProfile, error) {
	resp, err := internal.DoMgmtRequest[DeploymentProfile](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.MgmtDeploymentProfilesPath + "/" + seg(profileID),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ScanLogsClient provides access to scan logs.
type ScanLogsClient struct {
	svcCfg *internal.OAuthServiceConfig
}

// List retrieves scan logs: POST /v1/mgmt/scanlogs with required query params and optional body.
func (c *ScanLogsClient) List(ctx context.Context, opts ScanLogListOpts) (*ScanLogListResponse, error) {
	params := map[string]string{
		"time_interval": fmt.Sprintf("%d", opts.TimeInterval),
		"time_unit":     opts.TimeUnit,
		"pageNumber":    fmt.Sprintf("%d", opts.PageNumber),
		"pageSize":      fmt.Sprintf("%d", opts.PageSize),
		"filter":        opts.Filter,
	}

	var body any
	if opts.PageToken != "" {
		body = PageTokenRequest{PageToken: opts.PageToken}
	}

	resp, err := internal.DoMgmtRequest[ScanLogListResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.MgmtScanLogsPath, Params: params, Body: body,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// OAuthManagementClient provides OAuth token management operations.
type OAuthManagementClient struct {
	svcCfg *internal.OAuthServiceConfig
}

func (c *OAuthManagementClient) GetToken(ctx context.Context, req OAuthTokenRequest) (*OAuthToken, error) {
	resp, err := internal.DoMgmtRequest[OAuthToken](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.MgmtOAuthTokenPath,
		Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *OAuthManagementClient) InvalidateToken(ctx context.Context) (*InvalidateTokenResponse, error) {
	resp, err := internal.DoMgmtRequest[InvalidateTokenResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.MgmtOAuthInvalidatePath,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// seg escapes a caller-supplied identifier for use as a single URL path segment.
func seg(s string) string { return internal.PathSeg(s) }
