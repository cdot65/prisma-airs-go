package modelsecurity

import (
	"context"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	"github.com/cdot65/prisma-airs-go/aisec/modelsecurity/schema"
)

// ListAll collects offset pages with caller-selected bounds and the server total.
func (c *ScansClient) ListAll(ctx context.Context, opts ScanListOpts, bounds aisec.CollectOptions) ([]ScanBaseResponse, error) {
	return internal.CollectPages(ctx, bounds, func(ctx context.Context, offset, limit int) (aisec.ListPage[ScanBaseResponse], error) {
		opts.Limit = limit
		opts.Skip = offset
		response, err := c.List(ctx, opts)
		if err != nil {
			return aisec.ListPage[ScanBaseResponse]{}, err
		}
		return aisec.ListPage[ScanBaseResponse]{Items: response.Items, Total: response.Metadata.TotalItems}, nil
	})
}

// ListAll collects offset pages with caller-selected bounds and the server total.
func (c *SecurityGroupsClient) ListAll(ctx context.Context, opts GroupListOpts, bounds aisec.CollectOptions) ([]ModelSecurityGroupResponse, error) {
	return internal.CollectPages(ctx, bounds, func(ctx context.Context, offset, limit int) (aisec.ListPage[ModelSecurityGroupResponse], error) {
		opts.Limit = limit
		opts.Skip = offset
		response, err := c.List(ctx, opts)
		if err != nil {
			return aisec.ListPage[ModelSecurityGroupResponse]{}, err
		}
		return aisec.ListPage[ModelSecurityGroupResponse]{Items: response.Items, Total: response.Metadata.TotalItems}, nil
	})
}

// ListAll collects offset pages with caller-selected bounds and the server total.
func (c *SecurityRulesClient) ListAll(ctx context.Context, opts RuleListOpts, bounds aisec.CollectOptions) ([]ModelSecurityRuleResponse, error) {
	return internal.CollectPages(ctx, bounds, func(ctx context.Context, offset, limit int) (aisec.ListPage[ModelSecurityRuleResponse], error) {
		opts.Limit = limit
		opts.Skip = offset
		response, err := c.List(ctx, opts)
		if err != nil {
			return aisec.ListPage[ModelSecurityRuleResponse]{}, err
		}
		return aisec.ListPage[ModelSecurityRuleResponse]{Items: response.Items, Total: response.Metadata.TotalItems}, nil
	})
}

// ListAll collects offset pages with caller-selected bounds and the server total.
func (c *ModelsClient) ListAll(ctx context.Context, opts ModelListOpts, bounds aisec.CollectOptions) ([]schema.ModelResponse, error) {
	return internal.CollectPages(ctx, bounds, func(ctx context.Context, offset, limit int) (aisec.ListPage[schema.ModelResponse], error) {
		opts.Limit = limit
		opts.Skip = offset
		response, err := c.List(ctx, opts)
		if err != nil {
			return aisec.ListPage[schema.ModelResponse]{}, err
		}
		return aisec.ListPage[schema.ModelResponse]{Items: response.Models, Total: toInt(response.Pagination.TotalItems)}, nil
	})
}

// ListAllVersions collects offset pages with caller-selected bounds and the server total.
func (c *ModelsClient) ListAllVersions(ctx context.Context, id string, opts ModelVersionListOpts, bounds aisec.CollectOptions) ([]schema.ModelVersionResponse, error) {
	return internal.CollectPages(ctx, bounds, func(ctx context.Context, offset, limit int) (aisec.ListPage[schema.ModelVersionResponse], error) {
		opts.Limit = limit
		opts.Skip = offset
		response, err := c.ListVersions(ctx, id, opts)
		if err != nil {
			return aisec.ListPage[schema.ModelVersionResponse]{}, err
		}
		return aisec.ListPage[schema.ModelVersionResponse]{Items: response.ModelVersions, Total: toInt(response.Pagination.TotalItems)}, nil
	})
}

// ListAllFiles collects offset pages with caller-selected bounds and the server total.
func (c *ModelVersionsClient) ListAllFiles(ctx context.Context, id string, opts PageOpts, bounds aisec.CollectOptions) ([]schema.FileResponse, error) {
	return internal.CollectPages(ctx, bounds, func(ctx context.Context, offset, limit int) (aisec.ListPage[schema.FileResponse], error) {
		opts.Limit = limit
		opts.Skip = offset
		response, err := c.ListFiles(ctx, id, opts)
		if err != nil {
			return aisec.ListPage[schema.FileResponse]{}, err
		}
		return aisec.ListPage[schema.FileResponse]{Items: response.Files, Total: toInt(response.Pagination.TotalItems)}, nil
	})
}

// ListAll collects offset pages with caller-selected bounds and the server total.
func (c *CustomRulesClient) ListAll(ctx context.Context, opts CustomRuleListOpts, bounds aisec.CollectOptions) ([]schema.CustomRuleListItem, error) {
	return internal.CollectPages(ctx, bounds, func(ctx context.Context, offset, limit int) (aisec.ListPage[schema.CustomRuleListItem], error) {
		opts.Limit = limit
		opts.Skip = offset
		response, err := c.List(ctx, opts)
		if err != nil {
			return aisec.ListPage[schema.CustomRuleListItem]{}, err
		}
		return aisec.ListPage[schema.CustomRuleListItem]{Items: response.CustomRules, Total: toInt(response.Pagination.TotalItems)}, nil
	})
}
func toInt(value aisec.Optional[int64]) *int {
	raw, ok := value.Get()
	if !ok {
		return nil
	}
	result := int(raw)
	return &result
}

// ListAllVersions walks custom-rule snapshot versions using opaque cursors, never item offsets.
func (c *CustomRulesClient) ListAllVersions(ctx context.Context, opts SnapshotListOpts, bounds aisec.CollectOptions) ([]schema.SnapshotVersion, error) {
	limit := bounds.Limit
	if limit == 0 {
		limit = 50
	}
	maximum := 10000
	if bounds.Max != nil {
		maximum = *bounds.Max
	}
	if limit < 1 || maximum < 0 {
		return nil, aisec.NewAISecSDKError("invalid snapshot listing bounds", aisec.UserRequestPayloadError)
	}
	items := []schema.SnapshotVersion{}
	seen := map[string]bool{}
	opts.Limit = limit
	for page := 0; page < 10000; page++ {
		if seen[opts.NextToken] {
			return nil, aisec.NewAISecSDKError("snapshot listing returned a repeated cursor", aisec.AISecSDKInternalError)
		}
		seen[opts.NextToken] = true
		response, err := c.ListVersions(ctx, opts)
		if err != nil {
			return nil, err
		}
		count := len(response.Versions)
		if maximum > 0 && len(items)+count > maximum {
			count = maximum - len(items)
		}
		items = append(items, response.Versions[:count]...)
		if maximum > 0 && len(items) >= maximum {
			return items, nil
		}
		token, ok := response.Pagination.NextToken.Get()
		if !ok || token == "" {
			return items, nil
		}
		if len(response.Versions) == 0 {
			return nil, aisec.NewAISecSDKError("snapshot listing returned an empty non-final page", aisec.AISecSDKInternalError)
		}
		opts.NextToken = token
	}
	return nil, aisec.NewAISecSDKError("snapshot listing exceeded its page bound", aisec.AISecSDKInternalError)
}
