package runtime

import (
	"context"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
)

// ListAll collects pages with caller-selected bounds and rejects nonprogressing cursors.
func (c *ProfilesClient) ListAll(ctx context.Context, opts ProfileListOpts, bounds aisec.CollectOptions) ([]SecurityProfile, error) {
	return internal.CollectPages(ctx, bounds, func(ctx context.Context, offset, limit int) (aisec.ListPage[SecurityProfile], error) {
		opts.Limit = limit
		opts.Offset = offset
		response, err := c.ListWithOptions(ctx, opts)
		if err != nil {
			return aisec.ListPage[SecurityProfile]{}, err
		}
		var next *int
		candidate := response.NextOffset
		if candidate > 0 {
			next = &candidate
		}
		return aisec.ListPage[SecurityProfile]{Items: response.Items, Done: candidate == 0 && len(response.Items) < limit, Next: next, Total: nil}, nil
	})
}

// ListAll collects pages with caller-selected bounds and rejects nonprogressing cursors.
func (c *TopicsClient) ListAll(ctx context.Context, opts ListOpts, bounds aisec.CollectOptions) ([]CustomTopic, error) {
	return internal.CollectPages(ctx, bounds, func(ctx context.Context, offset, limit int) (aisec.ListPage[CustomTopic], error) {
		opts.Limit = limit
		opts.Offset = offset
		response, err := c.List(ctx, opts)
		if err != nil {
			return aisec.ListPage[CustomTopic]{}, err
		}
		var next *int
		candidate := response.NextOffset
		if candidate > 0 {
			next = &candidate
		}
		return aisec.ListPage[CustomTopic]{Items: response.Items, Done: candidate == 0 && len(response.Items) < limit, Next: next, Total: nil}, nil
	})
}

// ListAll collects pages with caller-selected bounds and rejects nonprogressing cursors.
func (c *ApiKeysClient) ListAll(ctx context.Context, opts ListOpts, bounds aisec.CollectOptions) ([]ApiKey, error) {
	return internal.CollectPages(ctx, bounds, func(ctx context.Context, offset, limit int) (aisec.ListPage[ApiKey], error) {
		opts.Limit = limit
		opts.Offset = offset
		response, err := c.List(ctx, opts)
		if err != nil {
			return aisec.ListPage[ApiKey]{}, err
		}
		var next *int
		candidate := response.NextOffset
		if candidate > 0 {
			next = &candidate
		}
		return aisec.ListPage[ApiKey]{Items: response.Items, Done: candidate == 0 && len(response.Items) < limit, Next: next, Total: nil}, nil
	})
}

// ListAll collects pages with caller-selected bounds and rejects nonprogressing cursors.
func (c *CustomerAppsClient) ListAll(ctx context.Context, opts ListOpts, bounds aisec.CollectOptions) ([]CustomerApp, error) {
	return internal.CollectPages(ctx, bounds, func(ctx context.Context, offset, limit int) (aisec.ListPage[CustomerApp], error) {
		opts.Limit = limit
		opts.Offset = offset
		response, err := c.List(ctx, opts)
		if err != nil {
			return aisec.ListPage[CustomerApp]{}, err
		}
		var next *int
		candidate := response.NextOffset
		if candidate > 0 {
			next = &candidate
		}
		return aisec.ListPage[CustomerApp]{Items: response.Items, Done: candidate == 0 && len(response.Items) < limit, Next: next, Total: nil}, nil
	})
}
