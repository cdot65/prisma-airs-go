package management

import (
	"context"
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
	endpoint := opts.APIEndpoint
	if endpoint == "" {
		endpoint = aisec.DefaultMgmtEndpoint
	}

	svcCfg, err := internal.ResolveOAuthConfig(internal.ResolveOAuthConfigOpts{
		ClientID:         opts.ClientID,
		ClientSecret:     opts.ClientSecret,
		TsgID:            opts.TsgID,
		BaseURL:          endpoint,
		NumRetries:       opts.NumRetries,
		TokenEndpoint:    opts.TokenEndpoint,
		PrimaryEnvPrefix: "PANW_MGMT",
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
		Method: http.MethodPut, Path: aisec.MgmtProfilePath + "/" + profileID, Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ProfilesClient) Delete(ctx context.Context, profileID string) (*DeleteProfileResponse, error) {
	resp, err := internal.DoMgmtRequest[DeleteProfileResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodDelete, Path: aisec.MgmtProfilePath + "/" + profileID,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ProfilesClient) GetByName(ctx context.Context, name string) (*SecurityProfile, error) {
	resp, err := internal.DoMgmtRequest[SecurityProfile](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.MgmtProfilePath, Params: map[string]string{"profile_name": name},
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ForceDelete force-deletes a profile: DELETE /v1/mgmt/profile/{profile_id}/force?updated_by=
func (c *ProfilesClient) ForceDelete(ctx context.Context, profileID string, updatedBy string) (*DeleteProfileResponse, error) {
	resp, err := internal.DoMgmtRequest[DeleteProfileResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodDelete,
		Path:   aisec.MgmtProfileForcePath + "/" + profileID + "/force",
		Params: map[string]string{"updated_by": updatedBy},
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
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
		Method: http.MethodPut, Path: aisec.MgmtTopicPath + "/" + topicID, Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *TopicsClient) Delete(ctx context.Context, topicID string) (*DeleteTopicResponse, error) {
	resp, err := internal.DoMgmtRequest[DeleteTopicResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodDelete, Path: aisec.MgmtTopicPath + "/" + topicID,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ForceDelete force-deletes a topic: DELETE /v1/mgmt/topic/{topic_id}/force?updated_by=
func (c *TopicsClient) ForceDelete(ctx context.Context, topicID string, updatedBy string) (*DeleteTopicResponse, error) {
	resp, err := internal.DoMgmtRequest[DeleteTopicResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodDelete,
		Path:   aisec.MgmtTopicForcePath + "/" + topicID + "/force",
		Params: map[string]string{"updated_by": updatedBy},
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
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
		Method: http.MethodDelete, Path: aisec.MgmtAPIKeyPath + "/delete/" + keyName,
		Params: map[string]string{"updated_by": updatedBy},
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ApiKeysClient) Regenerate(ctx context.Context, keyID string, req RegenerateKeyRequest) (*ApiKey, error) {
	resp, err := internal.DoMgmtRequest[ApiKey](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.MgmtAPIKeyPath + "/" + keyID + "/regenerate", Body: req,
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

func (c *CustomerAppsClient) Create(ctx context.Context, req CreateAppRequest) (*CustomerApp, error) {
	resp, err := internal.DoMgmtRequest[CustomerApp](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.MgmtCustomerAppPath, Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *CustomerAppsClient) List(ctx context.Context, opts ListOpts) (*CustomerAppListResponse, error) {
	resp, err := internal.DoMgmtRequest[CustomerAppListResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.MgmtCustomerAppsTsgPath + "/" + c.tsgID, Params: buildListParams(opts),
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
	resp, err := internal.DoMgmtRequest[DlpProfile](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.MgmtDLPProfilesPath + "/" + profileID,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
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
		Method: http.MethodGet, Path: aisec.MgmtDeploymentProfilesPath + "/" + profileID,
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

func (c *OAuthManagementClient) GetToken(ctx context.Context) (*OAuthToken, error) {
	resp, err := internal.DoMgmtRequest[OAuthToken](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.MgmtOAuthTokenPath,
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
