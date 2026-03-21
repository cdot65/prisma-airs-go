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

func (c *TopicsClient) ForceDelete(ctx context.Context, topicID string) (*DeleteTopicResponse, error) {
	resp, err := internal.DoMgmtRequest[DeleteTopicResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodDelete, Path: aisec.MgmtTopicForcePath + "/" + topicID,
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
		Method: http.MethodDelete, Path: aisec.MgmtAPIKeyPath,
		Params: map[string]string{"api_key_name": keyName, "updated_by": updatedBy},
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

func (c *CustomerAppsClient) Get(ctx context.Context, appID string) (*CustomerApp, error) {
	resp, err := internal.DoMgmtRequest[CustomerApp](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.MgmtCustomerAppPath + "/" + appID,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *CustomerAppsClient) Update(ctx context.Context, appID string, req UpdateAppRequest) (*CustomerApp, error) {
	resp, err := internal.DoMgmtRequest[CustomerApp](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodPut, Path: aisec.MgmtCustomerAppPath + "/" + appID, Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *CustomerAppsClient) Delete(ctx context.Context, appID string) (*DeleteAppResponse, error) {
	resp, err := internal.DoMgmtRequest[DeleteAppResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodDelete, Path: aisec.MgmtCustomerAppPath + "/" + appID,
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

// ScanLogsClient provides read-only access to scan logs.
type ScanLogsClient struct {
	svcCfg *internal.OAuthServiceConfig
}

func (c *ScanLogsClient) List(ctx context.Context, opts ScanLogListOpts) (*ScanLogListResponse, error) {
	params := map[string]string{}
	if opts.Limit > 0 {
		params["limit"] = fmt.Sprintf("%d", opts.Limit)
	}
	if opts.Offset > 0 {
		params["offset"] = fmt.Sprintf("%d", opts.Offset)
	}
	resp, err := internal.DoMgmtRequest[ScanLogListResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.MgmtScanLogsPath, Params: params,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ScanLogsClient) Get(ctx context.Context, logID string) (*ScanLog, error) {
	resp, err := internal.DoMgmtRequest[ScanLog](ctx, c.svcCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.MgmtScanLogsPath + "/" + logID,
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
