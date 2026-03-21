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

// RequestOptions for a scan API HTTP request.
type RequestOptions struct {
	Method string
	Path   string
	Body   any
	Params map[string]string
}

// Response wraps a typed HTTP response.
type Response[T any] struct {
	Status int
	Data   T
}

// DoRequest performs an HTTP request to the scan API with retry logic.
func DoRequest[T any](ctx context.Context, cfg *aisec.Config, opts RequestOptions) (*Response[T], error) {
	baseURL := cfg.Endpoint()

	u, err := url.Parse(baseURL + opts.Path)
	if err != nil {
		return nil, aisec.WrapError(fmt.Sprintf("invalid URL: %s%s", baseURL, opts.Path), aisec.AISecSDKInternalError, err)
	}

	if opts.Params != nil {
		q := u.Query()
		for k, v := range opts.Params {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
	}

	var bodyBytes []byte
	if opts.Body != nil {
		bodyBytes, err = json.Marshal(opts.Body)
		if err != nil {
			return nil, aisec.WrapError("failed to marshal request body", aisec.AISecSDKInternalError, err)
		}
	}

	resp, err := ExecuteWithRetry(RetryOptions{
		MaxRetries: cfg.NumRetries(),
		Execute: func(attempt int) (*http.Response, error) {
			var bodyReader io.Reader
			if bodyBytes != nil {
				bodyReader = bytes.NewReader(bodyBytes)
			}

			req, err := http.NewRequestWithContext(ctx, opts.Method, u.String(), bodyReader)
			if err != nil {
				return nil, err
			}

			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", aisec.UserAgent)

			if cfg.APIToken() != "" {
				req.Header.Set(aisec.HeaderAuthToken, aisec.Bearer+cfg.APIToken())
			}
			if cfg.APIKey() != "" {
				req.Header.Set(aisec.HeaderAPIKey, cfg.APIKey())
				if bodyBytes != nil {
					req.Header.Set(aisec.PayloadHash, aisec.GeneratePayloadHash(string(bodyBytes), cfg.APIKey()))
				}
			}

			return http.DefaultClient.Do(req)
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

	var data T
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &data); err != nil {
			return nil, aisec.WrapError("failed to parse response JSON", aisec.AISecSDKInternalError, err)
		}
	}

	return &Response[T]{Status: resp.StatusCode, Data: data}, nil
}
