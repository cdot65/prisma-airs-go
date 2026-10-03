package redteam

import (
	"context"
	"errors"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
)

// GetScanMetadata reads the data-plane metadata route. On the TypeScript SDK's recorded 422
// routing incompatibility it falls back to the equivalent management target metadata endpoint.
func (c *Client) GetScanMetadata(ctx context.Context) (map[string]any, error) {
	r, err := internal.DoMgmtRequest[map[string]any](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: "GET", Path: aisec.RedTeamScanMetadataPath})
	if err == nil {
		return r.Data, nil
	}
	var e *aisec.AISecSDKError
	if errors.As(err, &e) && e.StatusCode == 422 {
		return c.GetTargetMetadata(ctx)
	}
	return nil, err
}
