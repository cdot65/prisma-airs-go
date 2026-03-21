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
}

// DoMgmtRequest performs an OAuth-authenticated HTTP request with retry.
func DoMgmtRequest[T any](ctx context.Context, svcCfg *OAuthServiceConfig, opts MgmtRequestOptions) (*Response[T], error) {
	baseURL := svcCfg.BaseURL

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
		MaxRetries: svcCfg.NumRetries,
		Execute: func(attempt int) (*http.Response, error) {
			token, err := svcCfg.OAuth.GetToken()
			if err != nil {
				return nil, err
			}

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
			req.Header.Set(aisec.HeaderAuthToken, aisec.Bearer+token)

			return http.DefaultClient.Do(req)
		},
		OnRetryableFailure: func(resp *http.Response, attempt int) (bool, error) {
			if resp.StatusCode == 401 || resp.StatusCode == 403 {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				svcCfg.OAuth.ClearToken()
				return true, nil // retry without consuming budget
			}
			return false, nil
		},
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

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
