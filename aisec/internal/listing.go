package internal

import (
	"context"
	"github.com/cdot65/prisma-airs-go/aisec"
)

// CollectPages follows bounded, monotonic offsets and stops before fetching beyond the caller's record cap.
func CollectPages[T any](ctx context.Context, opts aisec.CollectOptions, fetch func(context.Context, int, int) (aisec.ListPage[T], error)) ([]T, error) {
	limit := opts.Limit
	if limit == 0 {
		limit = 50
	}
	maximum := 10000
	if opts.Max != nil {
		maximum = *opts.Max
	}
	if limit < 1 || maximum < 0 {
		return nil, aisec.NewAISecSDKError("invalid all-page listing bounds", aisec.UserRequestPayloadError)
	}
	result := []T{}
	offset := 0
	for page := 0; page < 10000; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p, err := fetch(ctx, offset, limit)
		if err != nil {
			return nil, err
		}
		count := len(p.Items)
		if maximum > 0 && len(result)+count > maximum {
			count = maximum - len(result)
		}
		result = append(result, p.Items[:count]...)
		if maximum > 0 && len(result) >= maximum {
			return result, nil
		}
		if p.Done || (p.Next == nil && len(p.Items) == 0) {
			return result, nil
		}
		next := offset + len(p.Items)
		if p.Next != nil {
			if *p.Next <= offset {
				return nil, aisec.NewAISecSDKError("listing returned a repeated or regressing cursor", aisec.AISecSDKInternalError)
			}
			next = *p.Next
		} else if p.Total != nil {
			if next >= *p.Total {
				return result, nil
			}
		} else if len(p.Items) < limit {
			return result, nil
		}
		if len(p.Items) == 0 {
			return nil, aisec.NewAISecSDKError("listing returned an empty non-final page", aisec.AISecSDKInternalError)
		}
		offset = next
	}
	return nil, aisec.NewAISecSDKError("listing exceeded its page bound", aisec.AISecSDKInternalError)
}
