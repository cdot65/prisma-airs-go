package runtime

import (
	"context"
	"fmt"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	"net/http"
)

// ListWithOptions lists profile revisions; Latest=nil leaves the API default.
// The TSG-qualified route is a recorded live exception to the supplied spec.
func (c *ProfilesClient) ListWithOptions(ctx context.Context, opts ProfileListOpts) (*SecurityProfileListResponse, error) {
	params := buildListParams(opts.ListOpts)
	if opts.Latest != nil {
		params["latest"] = fmt.Sprint(*opts.Latest)
	}
	r, err := internal.DoMgmtRequest[SecurityProfileListResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.MgmtProfilesTsgPath + "/" + seg(c.tsgID), Params: params})
	if err != nil {
		return nil, err
	}
	return &r.Data, nil
}

// ListWithOptions selects activation state without changing legacy List calls.
func (c *DeploymentProfilesClient) ListWithOptions(ctx context.Context, opts DeploymentProfileListOpts) (*DeploymentProfileListResponse, error) {
	params := map[string]string{}
	if opts.Unactivated != nil {
		params["unactivated"] = fmt.Sprint(*opts.Unactivated)
	}
	r, err := internal.DoMgmtRequest[DeploymentProfileListResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.MgmtDeploymentProfilesPath, Params: params})
	if err != nil {
		return nil, err
	}
	return &r.Data, nil
}

// UpdateFields updates a topic while preserving explicit empty/false values.
func (c *TopicsClient) UpdateFields(ctx context.Context, id string, req UpdateTopicFieldsRequest) (*CustomTopic, error) {
	r, err := internal.DoMgmtRequest[CustomTopic](ctx, c.svcCfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.MgmtTopicPath + "/uuid/" + seg(id), Body: req})
	if err != nil {
		return nil, err
	}
	return &r.Data, nil
}

// GetTokenWithTTL requests an application token with explicit lifetime options.
func (c *OAuthManagementClient) GetTokenWithTTL(ctx context.Context, req OAuthTokenRequest, opts TokenTTLOpts) (*OAuthToken, error) {
	params := map[string]string{}
	if opts.Interval != nil {
		params["tokenTtlInterval"] = fmt.Sprint(*opts.Interval)
	}
	if opts.Unit != "" {
		params["tokenTtlUnit"] = opts.Unit
	}
	r, err := internal.DoMgmtRequest[OAuthToken](ctx, c.svcCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.MgmtOAuthTokenPath, Params: params, Body: req})
	if err != nil {
		return nil, err
	}
	return &r.Data, nil
}
