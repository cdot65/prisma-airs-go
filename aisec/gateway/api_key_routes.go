package gateway

import (
	"context"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/gateway/schema"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	"net/http"
)

// ListForKind uses the explicit SCM service/user route and lists resources with explicit scope and pagination.
func (c *APIKeysClient) ListForKind(ctx context.Context, kind APIKeyKind, opts schema.APIKeysListOptions) (*schema.APIKeyObjectList, error) {
	query, err := queryValues(opts, nil)
	if err != nil {
		return nil, err
	}
	resp, err := internal.DoMgmtRequest[schema.APIKeyObjectList](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayAPIKeysPath + "/" + seg(string(kind)), Query: query})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetForKind uses the explicit SCM service/user route and reads the resource.
func (c *APIKeysClient) GetForKind(ctx context.Context, kind APIKeyKind, id string) (*schema.APIKeyObject, error) {
	resp, err := internal.DoMgmtRequest[schema.APIKeyObject](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.GatewayAPIKeysPath + "/" + seg(string(kind)) + "/" + seg(id)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// UpdateForKind uses the explicit SCM service/user route and updates supplied fields; nested documents may replace stored values.
func (c *APIKeysClient) UpdateForKind(ctx context.Context, kind APIKeyKind, id string, req schema.UpdateAPIKeyObject) (*schema.APIKeysUpdateResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.APIKeysUpdateResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayAPIKeysPath + "/" + seg(string(kind)) + "/" + seg(id), Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// DeleteForKind deletes a service/user key through its explicit ownership route.
func (c *APIKeysClient) DeleteForKind(ctx context.Context, kind APIKeyKind, id string) (*schema.APIKeysDeleteResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.APIKeysDeleteResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodDelete, Path: aisec.GatewayAPIKeysPath + "/" + seg(string(kind)) + "/" + seg(id)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// RotateForKind uses the explicit SCM service/user route and rotates key material explicitly; capture the one-time secret.
func (c *APIKeysClient) RotateForKind(ctx context.Context, kind APIKeyKind, id string, req schema.RotateAPIKeyRequest) (*schema.RotateAPIKeyResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.RotateAPIKeyResponse](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.GatewayAPIKeysPath + "/" + seg(string(kind)) + "/" + seg(id) + "/rotate", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}
