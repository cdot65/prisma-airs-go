package aisec

import "context"

// Paginate visits native cursor pages until Next is absent or yield returns false.
// Fetch must honor its context. Repeated cursors and more than 10,000 pages are errors.
func Paginate[T any, C comparable](ctx context.Context, fetch func(context.Context, C) (CursorPage[T, C], error), initial C, yield func(T) bool) error {
	seen := map[C]bool{}
	cursor := initial
	for page := 0; page < 10000; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if seen[cursor] {
			return NewAISecSDKError("pagination returned a repeated cursor", AISecSDKInternalError)
		}
		seen[cursor] = true
		result, err := fetch(ctx, cursor)
		if err != nil {
			return err
		}
		for _, item := range result.Items {
			if !yield(item) {
				return nil
			}
		}
		if result.Next == nil {
			return nil
		}
		cursor = *result.Next
	}
	return NewAISecSDKError("pagination exceeded its page bound", AISecSDKInternalError)
}

// CollectAll collects native cursor pages up to Max (nil:10,000; pointer to zero:unlimited).
// The page fetcher chooses page size; CollectOptions.Limit is not used by this cursor helper.
func CollectAll[T any, C comparable](ctx context.Context, fetch func(context.Context, C) (CursorPage[T, C], error), initial C, opts CollectOptions) ([]T, error) {
	maximum := 10000
	if opts.Max != nil {
		maximum = *opts.Max
	}
	if maximum < 0 {
		return nil, NewAISecSDKError("maximum must be nonnegative", UserRequestPayloadError)
	}
	items := []T{}
	err := Paginate(ctx, fetch, initial, func(item T) bool { items = append(items, item); return maximum == 0 || len(items) < maximum })
	if err != nil {
		return nil, err
	}
	return items, nil
}
