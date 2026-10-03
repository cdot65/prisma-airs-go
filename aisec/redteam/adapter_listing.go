package redteam

import (
	"context"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	"github.com/cdot65/prisma-airs-go/aisec/redteam/schema"
)

// ListAll collects adapter pages without losing filters or target-count options.
func (c *AdaptersClient) ListAll(ctx context.Context, opts AdapterListOpts, bounds aisec.CollectOptions) ([]schema.CustomTargetAdapterListItem, error) {
	return internal.CollectPages(ctx, bounds, func(ctx context.Context, offset, limit int) (aisec.ListPage[schema.CustomTargetAdapterListItem], error) {
		opts.Limit = limit
		opts.Skip = offset
		response, err := c.List(ctx, opts)
		if err != nil {
			return aisec.ListPage[schema.CustomTargetAdapterListItem]{}, err
		}
		items := []schema.CustomTargetAdapterListItem{}
		if response.Data != nil {
			items = *response.Data
		}
		var total *int
		if n, ok := response.Pagination.TotalItems.Get(); ok {
			value := int(n)
			total = &value
		}
		return aisec.ListPage[schema.CustomTargetAdapterListItem]{Items: items, Total: total}, nil
	})
}
