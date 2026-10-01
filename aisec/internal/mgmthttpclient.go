package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/cdot65/prisma-airs-go/aisec"
)

// MgmtRequestOptions for an OAuth-authenticated HTTP request.
type MgmtRequestOptions struct {
	Method string
	Path   string
	Body   any
	Params map[string]string
	// Query preserves repeated query parameters and overrides Params keys.
	Query url.Values
	// ResponsePolicy defaults to RequireJSON. Exceptions belong at the endpoint.
	ResponsePolicy ResponsePolicy
}

// RawMgmtRequestOptions describes an OAuth-authenticated request whose body or
// response is not plain JSON (multipart uploads, file downloads).
type RawMgmtRequestOptions struct {
	Method string
	Path   string
	Params map[string]string
	Query  url.Values
	// Body is sent verbatim. When nil, no body is sent.
	Body []byte
	// ContentType defaults to application/json.
	ContentType string
}

// RawResponse is a fully-read successful (2xx) HTTP response.
type RawResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

func (c *OAuthServiceConfig) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return DefaultHTTPClient()
}

func buildURL(baseURL, path string, params map[string]string) (*url.URL, error) {
	u, err := url.Parse(baseURL + path)
	if err != nil {
		return nil, aisec.WrapError(fmt.Sprintf("invalid URL: %s%s", baseURL, path), aisec.AISecSDKInternalError, err)
	}
	if params != nil {
		q := u.Query()
		for k, v := range params {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
	}
	return u, nil
}

// DoMgmtRaw performs an OAuth-authenticated HTTP request with retry and returns
// the raw response body. It is the single place the OAuth request pipeline —
// token injection, bounded 401/403 refresh, retry/backoff, error mapping —
// lives; DoMgmtRequest and the binary red team endpoints are built on it.
func DoMgmtRaw(ctx context.Context, svcCfg *OAuthServiceConfig, opts RawMgmtRequestOptions) (*RawResponse, error) {
	u, err := buildURL(svcCfg.BaseURL, opts.Path, opts.Params)
	if err != nil {
		return nil, err
	}
	if opts.Query != nil {
		q := u.Query()
		for key, values := range opts.Query {
			q.Del(key)
			for _, value := range values {
				q.Add(key, value)
			}
		}
		u.RawQuery = q.Encode()
	}
	contentType := opts.ContentType
	if contentType == "" {
		contentType = "application/json"
	}

	resp, err := ExecuteWithRetry(RetryOptions{
		Ctx:                ctx,
		MaxRetries:         svcCfg.NumRetries,
		OnRetryableFailure: NewAuthRefreshHandler(svcCfg.OAuth),
		Execute: func(attempt int) (*http.Response, error) {
			token, err := svcCfg.OAuth.GetTokenContext(ctx)
			if err != nil {
				return nil, err
			}

			var bodyReader io.Reader
			if opts.Body != nil {
				bodyReader = bytes.NewReader(opts.Body)
			}

			req, err := http.NewRequestWithContext(ctx, opts.Method, u.String(), bodyReader)
			if err != nil {
				return nil, err
			}

			req.Header.Set("Content-Type", contentType)
			req.Header.Set("User-Agent", aisec.UserAgent)
			req.Header.Set(aisec.HeaderAuthToken, aisec.Bearer+token)

			return svcCfg.client().Do(req)
		},
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, aisec.WrapError("failed to read response body", aisec.AISecSDKInternalError, err)
	}
	return &RawResponse{Status: resp.StatusCode, Header: resp.Header, Body: respBody}, nil
}

// DoMgmtRequest performs an OAuth-authenticated JSON request with retry.
func DoMgmtRequest[T any](ctx context.Context, svcCfg *OAuthServiceConfig, opts MgmtRequestOptions) (*Response[T], error) {
	var bodyBytes []byte
	if opts.Body != nil {
		var err error
		bodyBytes, err = json.Marshal(opts.Body)
		if err != nil {
			return nil, aisec.WrapError("failed to marshal request body", aisec.AISecSDKInternalError, err)
		}
	}

	raw, err := DoMgmtRaw(ctx, svcCfg, RawMgmtRequestOptions{
		Method: opts.Method,
		Path:   opts.Path,
		Params: opts.Params,
		Query:  opts.Query,
		Body:   bodyBytes,
	})
	if err != nil {
		return nil, err
	}

	return DecodeMgmtResponse[T](raw, opts.ResponsePolicy)
}
