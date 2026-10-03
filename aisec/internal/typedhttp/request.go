// Package typedhttp applies recovered TypeScript request/response contracts to the shared OAuth pipeline.
package typedhttp

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	"github.com/cdot65/prisma-airs-go/aisec/parity/schema"
)

// Options adds endpoint-specific shape validation and content type to a management request.
type Options struct {
	internal.MgmtRequestOptions
	RequestSchema, ResponseSchema, ContentType string
	SafeErrors                                 bool
}

// Do validates before authentication and decodes the original wire response without losing unknown fields.
func Do[T any](ctx context.Context, cfg *internal.OAuthServiceConfig, opts Options) (*T, error) {
	var body []byte
	if opts.Body != nil {
		if opts.RequestSchema != "" {
			if err := schema.Validate(opts.RequestSchema, opts.Body); err != nil {
				return nil, aisec.WrapError("invalid request", aisec.UserRequestPayloadError, err)
			}
		}
		var err error
		body, err = json.Marshal(opts.Body)
		if err != nil {
			return nil, aisec.WrapError("invalid request encoding", aisec.UserRequestPayloadError, err)
		}
	}
	raw, err := internal.DoMgmtRaw(ctx, cfg, internal.RawMgmtRequestOptions{Method: opts.Method, Path: opts.Path, Params: opts.Params, Query: opts.Query, Body: body, ContentType: opts.ContentType})
	if err != nil {
		if opts.SafeErrors {
			var e *aisec.AISecSDKError
			wrapped := aisec.WrapError("management request failed", aisec.ClientSideError, err)
			if errors.As(err, &e) {
				wrapped.StatusCode = e.StatusCode
				wrapped.ErrorType = e.ErrorType
			}
			return nil, wrapped
		}
		return nil, err
	}
	if opts.ResponseSchema != "" && len(raw.Body) > 0 {
		if err := schema.ValidateJSON(opts.ResponseSchema, raw.Body); err != nil {
			return nil, aisec.WrapError("response does not match the pinned contract", aisec.AISecSDKInternalError, err)
		}
	}
	response, err := internal.DecodeMgmtResponse[T](raw, opts.ResponsePolicy)
	if err != nil {
		return nil, err
	}
	return &response.Data, nil
}
