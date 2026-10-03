package redteam

import (
	"context"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
)

// ListAll collects offset pages with caller-selected bounds and the server total.
func (c *ScansClient) ListAll(ctx context.Context, opts ScanListOpts, bounds aisec.CollectOptions) ([]JobResponse, error) {
	return internal.CollectPages(ctx, bounds, func(ctx context.Context, offset, limit int) (aisec.ListPage[JobResponse], error) {
		opts.Limit = limit
		opts.Skip = offset
		response, err := c.List(ctx, opts)
		if err != nil {
			return aisec.ListPage[JobResponse]{}, err
		}
		return aisec.ListPage[JobResponse]{Items: response.Data, Total: redTeamTotal(response.Pagination)}, nil
	})
}

// ListAll collects offset pages with caller-selected bounds and the server total.
func (c *TargetsClient) ListAll(ctx context.Context, opts TargetListOpts, bounds aisec.CollectOptions) ([]TargetListItem, error) {
	return internal.CollectPages(ctx, bounds, func(ctx context.Context, offset, limit int) (aisec.ListPage[TargetListItem], error) {
		opts.Limit = limit
		opts.Skip = offset
		response, err := c.List(ctx, opts)
		if err != nil {
			return aisec.ListPage[TargetListItem]{}, err
		}
		return aisec.ListPage[TargetListItem]{Items: response.Data, Total: redTeamTotal(response.Pagination)}, nil
	})
}

// ListAllPromptSets collects offset pages with caller-selected bounds and the server total.
func (c *CustomAttacksClient) ListAllPromptSets(ctx context.Context, opts PromptSetListOpts, bounds aisec.CollectOptions) ([]CustomPromptSetResponse, error) {
	return internal.CollectPages(ctx, bounds, func(ctx context.Context, offset, limit int) (aisec.ListPage[CustomPromptSetResponse], error) {
		opts.Limit = limit
		opts.Skip = offset
		response, err := c.ListPromptSets(ctx, opts)
		if err != nil {
			return aisec.ListPage[CustomPromptSetResponse]{}, err
		}
		return aisec.ListPage[CustomPromptSetResponse]{Items: response.Data, Total: redTeamTotal(response.Pagination)}, nil
	})
}

// ListAllPrompts collects offset pages with caller-selected bounds and the server total.
func (c *CustomAttacksClient) ListAllPrompts(ctx context.Context, id string, opts PromptListOpts, bounds aisec.CollectOptions) ([]CustomPromptResponse, error) {
	return internal.CollectPages(ctx, bounds, func(ctx context.Context, offset, limit int) (aisec.ListPage[CustomPromptResponse], error) {
		opts.Limit = limit
		opts.Skip = offset
		response, err := c.ListPrompts(ctx, id, opts)
		if err != nil {
			return aisec.ListPage[CustomPromptResponse]{}, err
		}
		return aisec.ListPage[CustomPromptResponse]{Items: response.Data, Total: redTeamTotal(response.Pagination)}, nil
	})
}

func redTeamTotal(p RedTeamPagination) *int {
	if p.TotalItems != nil {
		return p.TotalItems
	}
	if p.Total > 0 {
		return &p.Total
	}
	return nil
}
