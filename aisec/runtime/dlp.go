package runtime

import (
	"context"
	"fmt"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	"github.com/cdot65/prisma-airs-go/aisec/internal/typedhttp"
	parity "github.com/cdot65/prisma-airs-go/aisec/parity/schema"
	"net/http"
	"net/url"
)

// DLPClient groups DLP management resources under their separate endpoint, sharing management OAuth.
type DLPClient struct {
	DataFilteringProfiles *DataFilteringProfilesClient
	DataPatterns          *DataPatternsClient
	DataProfiles          *DataProfilesClient
	Dictionaries          *DictionariesClient
}

// DLPListOptions supports zero-based Spring pages and repeated sort criteria.
type DLPListOptions struct {
	Page     *int
	Size     *int
	Sort     []string
	Keywords *bool
}

// DLPListAllOptions bounds collection; Max defaults to 10,000 records; an explicit zero collects all pages, capped at 10,000 pages.
type DLPListAllOptions struct {
	Size     int
	Sort     []string
	Keywords *bool
	Max      *int
}

func dlpQuery(opts DLPListOptions) (url.Values, error) {
	q := url.Values{}
	if opts.Page != nil {
		if *opts.Page < 0 {
			return nil, dlpInvalid("page must be nonnegative")
		}
		q.Set("page", fmt.Sprint(*opts.Page))
	}
	if opts.Size != nil {
		if *opts.Size < 1 {
			return nil, dlpInvalid("size must be positive")
		}
		q.Set("size", fmt.Sprint(*opts.Size))
	}
	for _, s := range opts.Sort {
		q.Add("sort", s)
	}
	if opts.Keywords != nil {
		q.Set("keywords", fmt.Sprint(*opts.Keywords))
	}
	return q, nil
}

// DataFilteringProfilesClient manages the corresponding DLP resource through its published TypeScript contract.
type DataFilteringProfilesClient struct{ cfg *internal.OAuthServiceConfig }

// List calls GET /v2/api/data-filtering-profiles; deletes archive server-side where supported.
func (c *DataFilteringProfilesClient) List(ctx context.Context, opts DLPListOptions) (*parity.PageDataFilteringProfileResponse, error) {
	query, err := dlpQuery(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.PageDataFilteringProfileResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RuntimeV2ApiDataFilteringProfilesPath, Query: query}, SafeErrors: true, ResponseSchema: "PageDataFilteringProfileResponseSchema"})
}

// Get calls GET /v2/api/data-filtering-profiles/{resourceId}; deletes archive server-side where supported.
func (c *DataFilteringProfilesClient) Get(ctx context.Context, resourceId string) (*parity.DataFilteringProfileResponse, error) {
	if resourceId == "" {
		return nil, dlpInvalid("resource ID is required")
	}
	return typedhttp.Do[parity.DataFilteringProfileResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RuntimeV2ApiDataFilteringProfilesPath + "/" + seg(resourceId) + ""}, SafeErrors: true, ResponseSchema: "DataFilteringProfileResponseSchema"})
}

// Replace calls PUT /v2/api/data-filtering-profiles/{resourceId}; deletes archive server-side where supported.
func (c *DataFilteringProfilesClient) Replace(ctx context.Context, resourceId string, body parity.DataFilteringProfileRequest) (*parity.DataFilteringProfileResponse, error) {
	if resourceId == "" {
		return nil, dlpInvalid("resource ID is required")
	}
	return typedhttp.Do[parity.DataFilteringProfileResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.RuntimeV2ApiDataFilteringProfilesPath + "/" + seg(resourceId) + "", Body: body}, SafeErrors: true, RequestSchema: "DataFilteringProfileRequestSchema", ResponseSchema: "DataFilteringProfileResponseSchema"})
}

// ListAll follows server pagination with a maximum and a bounded page count.
func (c *DataFilteringProfilesClient) ListAll(ctx context.Context, opts DLPListAllOptions) ([]parity.PageDataFilteringProfileResponseContentItem, error) {
	return collectDLP(ctx, opts, func(ctx context.Context, page DLPListOptions) (dlpPage[parity.PageDataFilteringProfileResponseContentItem], error) {
		response, err := c.List(ctx, page)
		if err != nil {
			return dlpPage[parity.PageDataFilteringProfileResponseContentItem]{}, err
		}
		return dlpPage[parity.PageDataFilteringProfileResponseContentItem]{response.Content, response.Last, response.TotalPages}, nil
	})
}

// DataPatternsClient manages the corresponding DLP resource through its published TypeScript contract.
type DataPatternsClient struct{ cfg *internal.OAuthServiceConfig }

// List calls GET /v2/api/data-patterns; deletes archive server-side where supported.
func (c *DataPatternsClient) List(ctx context.Context, opts DLPListOptions) (*parity.PageDataPatternResponse, error) {
	query, err := dlpQuery(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.PageDataPatternResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RuntimeV2ApiDataPatternsPath, Query: query}, SafeErrors: true, ResponseSchema: "PageDataPatternResponseSchema"})
}

// Create calls POST /v2/api/data-patterns; deletes archive server-side where supported.
func (c *DataPatternsClient) Create(ctx context.Context, body parity.DataPatternRequest) (*parity.DataPatternResponse, error) {
	return typedhttp.Do[parity.DataPatternResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.RuntimeV2ApiDataPatternsPath, Body: body}, SafeErrors: true, RequestSchema: "DataPatternRequestSchema", ResponseSchema: "DataPatternResponseSchema"})
}

// Get calls GET /v2/api/data-patterns/{resourceId}; deletes archive server-side where supported.
func (c *DataPatternsClient) Get(ctx context.Context, resourceId string) (*parity.DataPatternResponse, error) {
	if resourceId == "" {
		return nil, dlpInvalid("resource ID is required")
	}
	return typedhttp.Do[parity.DataPatternResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RuntimeV2ApiDataPatternsPath + "/" + seg(resourceId) + ""}, SafeErrors: true, ResponseSchema: "DataPatternResponseSchema"})
}

// Replace calls PUT /v2/api/data-patterns/{resourceId}; deletes archive server-side where supported.
func (c *DataPatternsClient) Replace(ctx context.Context, resourceId string, body parity.DataPatternRequest) (*parity.DataPatternResponse, error) {
	if resourceId == "" {
		return nil, dlpInvalid("resource ID is required")
	}
	return typedhttp.Do[parity.DataPatternResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.RuntimeV2ApiDataPatternsPath + "/" + seg(resourceId) + "", Body: body}, SafeErrors: true, RequestSchema: "DataPatternRequestSchema", ResponseSchema: "DataPatternResponseSchema"})
}

// Patch calls PATCH /v2/api/data-patterns/{resourceId}; deletes archive server-side where supported.
func (c *DataPatternsClient) Patch(ctx context.Context, resourceId string, body parity.DataPatternPatchRequest) (*parity.DataPatternResponse, error) {
	if resourceId == "" {
		return nil, dlpInvalid("resource ID is required")
	}
	return typedhttp.Do[parity.DataPatternResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodPatch, Path: aisec.RuntimeV2ApiDataPatternsPath + "/" + seg(resourceId) + "", Body: body}, SafeErrors: true, RequestSchema: "DataPatternPatchRequestSchema", ResponseSchema: "DataPatternResponseSchema", ContentType: "application/merge-patch+json"})
}

// Delete calls DELETE /v2/api/data-patterns/{resourceId}; deletes archive server-side where supported.
func (c *DataPatternsClient) Delete(ctx context.Context, resourceId string) error {
	if resourceId == "" {
		return dlpInvalid("resource ID is required")
	}
	_, err := typedhttp.Do[any](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodDelete, Path: aisec.RuntimeV2ApiDataPatternsPath + "/" + seg(resourceId) + "", ResponsePolicy: internal.AllowEmptyJSON}, SafeErrors: true})
	return err
}

// ListAll follows server pagination with a maximum and a bounded page count.
func (c *DataPatternsClient) ListAll(ctx context.Context, opts DLPListAllOptions) ([]parity.PageDataPatternResponseContentItem, error) {
	return collectDLP(ctx, opts, func(ctx context.Context, page DLPListOptions) (dlpPage[parity.PageDataPatternResponseContentItem], error) {
		response, err := c.List(ctx, page)
		if err != nil {
			return dlpPage[parity.PageDataPatternResponseContentItem]{}, err
		}
		return dlpPage[parity.PageDataPatternResponseContentItem]{response.Content, response.Last, response.TotalPages}, nil
	})
}

// DataProfilesClient manages the corresponding DLP resource through its published TypeScript contract.
type DataProfilesClient struct{ cfg *internal.OAuthServiceConfig }

// List calls GET /v2/api/data-profiles; deletes archive server-side where supported.
func (c *DataProfilesClient) List(ctx context.Context, opts DLPListOptions) (*parity.PageDataProfileResponse, error) {
	query, err := dlpQuery(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.PageDataProfileResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RuntimeV2ApiDataProfilesPath, Query: query}, SafeErrors: true, ResponseSchema: "PageDataProfileResponseSchema"})
}

// Create calls POST /v2/api/data-profiles; deletes archive server-side where supported.
func (c *DataProfilesClient) Create(ctx context.Context, body parity.AdvancedDataProfileRequest) (*parity.DataProfileResponse, error) {
	return typedhttp.Do[parity.DataProfileResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.RuntimeV2ApiDataProfilesPath, Body: body}, SafeErrors: true, RequestSchema: "AdvancedDataProfileRequestSchema", ResponseSchema: "DataProfileResponseSchema"})
}

// Get calls GET /v2/api/data-profiles/{resourceId}; deletes archive server-side where supported.
func (c *DataProfilesClient) Get(ctx context.Context, resourceId string) (*parity.DataProfileResponse, error) {
	if resourceId == "" {
		return nil, dlpInvalid("resource ID is required")
	}
	return typedhttp.Do[parity.DataProfileResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RuntimeV2ApiDataProfilesPath + "/" + seg(resourceId) + ""}, SafeErrors: true, ResponseSchema: "DataProfileResponseSchema"})
}

// Replace calls PUT /v2/api/data-profiles/{resourceId}; deletes archive server-side where supported.
func (c *DataProfilesClient) Replace(ctx context.Context, resourceId string, body parity.AdvancedDataProfileRequest) (*parity.DataProfileResponse, error) {
	if resourceId == "" {
		return nil, dlpInvalid("resource ID is required")
	}
	return typedhttp.Do[parity.DataProfileResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.RuntimeV2ApiDataProfilesPath + "/" + seg(resourceId) + "", Body: body}, SafeErrors: true, RequestSchema: "AdvancedDataProfileRequestSchema", ResponseSchema: "DataProfileResponseSchema"})
}

// Patch calls PATCH /v2/api/data-profiles/{resourceId}; deletes archive server-side where supported.
func (c *DataProfilesClient) Patch(ctx context.Context, resourceId string, body parity.DataProfilePatchRequest) (*parity.DataProfileResponse, error) {
	if resourceId == "" {
		return nil, dlpInvalid("resource ID is required")
	}
	return typedhttp.Do[parity.DataProfileResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodPatch, Path: aisec.RuntimeV2ApiDataProfilesPath + "/" + seg(resourceId) + "", Body: body}, SafeErrors: true, RequestSchema: "DataProfilePatchRequestSchema", ResponseSchema: "DataProfileResponseSchema", ContentType: "application/merge-patch+json"})
}

// ListAll follows server pagination with a maximum and a bounded page count.
func (c *DataProfilesClient) ListAll(ctx context.Context, opts DLPListAllOptions) ([]parity.PageDataProfileResponseContentItem, error) {
	return collectDLP(ctx, opts, func(ctx context.Context, page DLPListOptions) (dlpPage[parity.PageDataProfileResponseContentItem], error) {
		response, err := c.List(ctx, page)
		if err != nil {
			return dlpPage[parity.PageDataProfileResponseContentItem]{}, err
		}
		return dlpPage[parity.PageDataProfileResponseContentItem]{response.Content, response.Last, response.TotalPages}, nil
	})
}

// DictionariesClient manages the corresponding DLP resource through its published TypeScript contract.
type DictionariesClient struct{ cfg *internal.OAuthServiceConfig }

// List calls GET /v2/api/dictionaries; deletes archive server-side where supported.
func (c *DictionariesClient) List(ctx context.Context, opts DLPListOptions) (*parity.PageDictionaryResponse, error) {
	query, err := dlpQuery(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.PageDictionaryResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RuntimeV2ApiDictionariesPath, Query: query}, SafeErrors: true, ResponseSchema: "PageDictionaryResponseSchema"})
}

// Patch calls PATCH /v2/api/dictionaries/{resourceId}; deletes archive server-side where supported.
func (c *DictionariesClient) Patch(ctx context.Context, resourceId string, body parity.DictionaryPatchRequest) (*parity.DictionaryResponse, error) {
	if resourceId == "" {
		return nil, dlpInvalid("resource ID is required")
	}
	return typedhttp.Do[parity.DictionaryResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodPatch, Path: aisec.RuntimeV2ApiDictionariesPath + "/" + seg(resourceId) + "", Body: body}, SafeErrors: true, RequestSchema: "DictionaryPatchRequestSchema", ResponseSchema: "DictionaryResponseSchema", ContentType: "application/merge-patch+json"})
}

// Delete calls DELETE /v2/api/dictionaries/{resourceId}; deletes archive server-side where supported.
func (c *DictionariesClient) Delete(ctx context.Context, resourceId string) error {
	if resourceId == "" {
		return dlpInvalid("resource ID is required")
	}
	_, err := typedhttp.Do[any](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: http.MethodDelete, Path: aisec.RuntimeV2ApiDictionariesPath + "/" + seg(resourceId) + "", ResponsePolicy: internal.AllowEmptyJSON}, SafeErrors: true})
	return err
}

// ListAll follows server pagination with a maximum and a bounded page count.
func (c *DictionariesClient) ListAll(ctx context.Context, opts DLPListAllOptions) ([]parity.PageDictionaryResponseContentItem, error) {
	return collectDLP(ctx, opts, func(ctx context.Context, page DLPListOptions) (dlpPage[parity.PageDictionaryResponseContentItem], error) {
		response, err := c.List(ctx, page)
		if err != nil {
			return dlpPage[parity.PageDictionaryResponseContentItem]{}, err
		}
		return dlpPage[parity.PageDictionaryResponseContentItem]{response.Content, response.Last, response.TotalPages}, nil
	})
}

type dlpPage[T any] struct {
	items      []T
	last       *bool
	totalPages *float64
}

func collectDLP[T any](ctx context.Context, opts DLPListAllOptions, fetch func(context.Context, DLPListOptions) (dlpPage[T], error)) ([]T, error) {
	maximum := 10000
	if opts.Max != nil {
		maximum = *opts.Max
	}
	size := opts.Size
	if size == 0 {
		size = 50
	}
	if maximum < 0 || size < 1 {
		return nil, dlpInvalid("invalid DLP collection bounds")
	}
	items := []T{}
	for page := 0; page < 10000; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p, err := fetch(ctx, DLPListOptions{Page: &page, Size: &size, Sort: opts.Sort, Keywords: opts.Keywords})
		if err != nil {
			return nil, err
		}
		count := len(p.items)
		if maximum > 0 && len(items)+count > maximum {
			count = maximum - len(items)
		}
		items = append(items, p.items[:count]...)
		if maximum > 0 && len(items) >= maximum {
			return items, nil
		}
		final := false
		if p.last != nil {
			final = *p.last
		} else if p.totalPages != nil {
			final = float64(page+1) >= *p.totalPages
		} else {
			final = len(p.items) < size
		}
		if final {
			return items, nil
		}
		if len(p.items) == 0 {
			return nil, aisec.NewAISecSDKError("DLP listing returned an empty non-final page", aisec.AISecSDKInternalError)
		}
	}
	return nil, aisec.NewAISecSDKError("DLP pagination exceeded its page bound", aisec.AISecSDKInternalError)
}
