package runtime

import (
	"context"
	"fmt"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	"net/http"
)

func tokenListParams(opts ListOpts) (map[string]string, error) {
	if opts.Offset < 0 || opts.Limit < 0 {
		return nil, aisec.NewAISecSDKError("listing bounds must be nonnegative", aisec.UserRequestPayloadError)
	}
	if opts.Limit == 0 {
		opts.Limit = 100
	}
	return buildListParams(opts), nil
}

// ListForToken uses the token-scoped OpenAPI route without a tenant path suffix.
func (c *ProfilesClient) ListForToken(ctx context.Context, opts ProfileListOpts) (*SecurityProfileListResponse, error) {
	params, err := tokenListParams(opts.ListOpts)
	if err != nil {
		return nil, err
	}
	if opts.Latest != nil {
		params["latest"] = fmt.Sprint(*opts.Latest)
	}
	r, err := internal.DoMgmtRequest[SecurityProfileListResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.MgmtProfilesTokenPath, Params: params})
	if err != nil {
		return nil, err
	}
	return &r.Data, nil
}

// ListForToken uses the token-scoped OpenAPI route without a tenant path suffix.
func (c *TopicsClient) ListForToken(ctx context.Context, opts ListOpts) (*CustomTopicListResponse, error) {
	params, err := tokenListParams(opts)
	if err != nil {
		return nil, err
	}
	r, err := internal.DoMgmtRequest[CustomTopicListResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.MgmtTopicsTokenPath, Params: params})
	if err != nil {
		return nil, err
	}
	return &r.Data, nil
}

// ListForToken uses the token-scoped OpenAPI route without a tenant path suffix.
func (c *ApiKeysClient) ListForToken(ctx context.Context, opts ListOpts) (*ApiKeyListResponse, error) {
	params, err := tokenListParams(opts)
	if err != nil {
		return nil, err
	}
	r, err := internal.DoMgmtRequest[ApiKeyListResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.MgmtAPIKeysTokenPath, Params: params})
	if err != nil {
		return nil, err
	}
	return &r.Data, nil
}

// ListForToken uses the token-scoped OpenAPI route without a tenant path suffix.
func (c *CustomerAppsClient) ListForToken(ctx context.Context, opts ListOpts) (*CustomerAppListResponse, error) {
	params, err := tokenListParams(opts)
	if err != nil {
		return nil, err
	}
	r, err := internal.DoMgmtRequest[CustomerAppListResponse](ctx, c.svcCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.MgmtCustomerAppsTokenPath, Params: params})
	if err != nil {
		return nil, err
	}
	return &r.Data, nil
}

// InvalidateTokenForApp invalidates the supplied application token using its client/application body.
func (c *OAuthManagementClient) InvalidateTokenForApp(ctx context.Context, token string, body OAuthTokenRequest) (string, error) {
	if token == "" {
		return "", aisec.NewAISecSDKError("token is required", aisec.UserRequestPayloadError)
	}
	r, err := internal.DoMgmtRequest[string](ctx, c.svcCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.MgmtOAuthInvalidatePath, Params: map[string]string{"token": token}, Body: body})
	if err != nil {
		return "", err
	}
	return r.Data, nil
}
