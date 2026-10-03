package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	parity "github.com/cdot65/prisma-airs-go/aisec/parity/schema"
)

// InferenceOpts configures a caller-selected runtime endpoint and key, separate from SCM OAuth.
// Retries default to zero because replay can repeat billable generation.
type InferenceOpts struct {
	Endpoint, APIKey string
	Timeout          time.Duration
	NumRetries       int
	MaxEventBytes    int
	HTTPClient       *http.Client
}

// InferenceRequestOptions controls cancellation through context, deadline, retries and allowed routing headers.
type InferenceRequestOptions struct {
	Timeout    time.Duration
	NumRetries *int
	Headers    http.Header
}

// InferenceClient provides the TypeScript SDK's runtime inference and HTTP resource surface.
type InferenceClient struct {
	baseURL                   string
	authenticate              func(http.Header)
	client                    *http.Client
	timeout                   time.Duration
	numRetries, maxEventBytes int
}

// NewInferenceClient uses explicit options or PANW_AI_GW_INFERENCE_ENDPOINT/API_KEY only.
func NewInferenceClient(opts InferenceOpts) (*InferenceClient, error) {
	endpoint := opts.Endpoint
	if endpoint == "" {
		endpoint = os.Getenv(aisec.EnvGatewayInferenceEndpoint)
	}
	key := opts.APIKey
	if key == "" {
		key = os.Getenv(aisec.EnvGatewayInferenceAPIKey)
	}
	if endpoint == "" || key == "" {
		return nil, aisec.NewAISecSDKError("runtime inference requires its own endpoint and API key", aisec.MissingVariableError)
	}
	if err := validatePublicEndpoint(endpoint); err != nil {
		return nil, err
	}
	if strings.TrimSpace(key) == "" || strings.ContainsAny(key, "\r\n") {
		return nil, invalidInput("runtime key must be a nonempty header value")
	}
	if opts.Timeout < 0 || opts.NumRetries < 0 || opts.NumRetries > 5 || opts.MaxEventBytes < 0 {
		return nil, invalidInput("invalid inference timeout, retries or event limit")
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = time.Minute
	}
	limit := opts.MaxEventBytes
	if limit == 0 {
		limit = 1 << 20
	}
	client := internal.DefaultHTTPClient()
	if opts.HTTPClient != nil {
		client = opts.HTTPClient
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return fmt.Errorf("runtime redirects are disabled") }
	return &InferenceClient{baseURL: strings.TrimRight(endpoint, "/"), authenticate: func(h http.Header) { h.Set("x-portkey-api-key", key) }, client: &copyClient, timeout: timeout, numRetries: opts.NumRetries, maxEventBytes: limit}, nil
}
func validatePublicEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return invalidInput("endpoint must be an absolute URL without credentials, query or fragment")
	}
	loopback := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return invalidInput("endpoint requires HTTPS, except HTTP on loopback")
	}
	return nil
}
func inferenceHeaders(h http.Header) error {
	for key, values := range h {
		lower := strings.ToLower(key)
		if lower == "x-portkey-api-key" || (!(strings.HasPrefix(lower, "x-portkey-") || lower == "openai-beta")) {
			return invalidInput("only runtime routing headers and OpenAI-Beta can be supplied")
		}
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n") {
				return invalidInput("invalid routing header value")
			}
		}
	}
	return nil
}
func (c *InferenceClient) open(ctx context.Context, method, path string, query url.Values, body []byte, contentType string, opts InferenceRequestOptions) (*http.Response, context.CancelFunc, error) {
	if err := inferenceHeaders(opts.Headers); err != nil {
		return nil, nil, err
	}
	timeout := c.timeout
	if opts.Timeout != 0 {
		if opts.Timeout < 0 {
			return nil, nil, invalidInput("timeout must be positive")
		}
		timeout = opts.Timeout
	}
	retries := c.numRetries
	if opts.NumRetries != nil {
		retries = *opts.NumRetries
	}
	if retries < 0 || retries > 5 {
		return nil, nil, invalidInput("retries must be between zero and five")
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	u, err := url.Parse(c.baseURL + path)
	if err != nil {
		cancel()
		return nil, nil, invalidInput("invalid runtime path")
	}
	u.RawQuery = query.Encode()
	response, err := internal.ExecuteWithRetry(internal.RetryOptions{Ctx: callCtx, MaxRetries: retries, Execute: func(int) (*http.Response, error) {
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(callCtx, method, u.String(), reader)
		if err != nil {
			return nil, err
		}
		req.Header = opts.Headers.Clone()
		if req.Header == nil {
			req.Header = http.Header{}
		}
		req.Header.Set("User-Agent", aisec.UserAgent)
		req.Header.Set("Accept", "application/json")
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		c.authenticate(req.Header)
		return c.client.Do(req)
	}})
	if err != nil {
		cancel()
		return nil, nil, err
	}
	return response, cancel, nil
}
func inferenceJSON[T any](ctx context.Context, c *InferenceClient, method, path string, query url.Values, body any, requestSchema, responseSchema string, opts InferenceRequestOptions) (*T, error) {
	var encoded []byte
	if body != nil {
		if requestSchema != "" {
			if err := parity.Validate(requestSchema, body); err != nil {
				return nil, aisec.WrapError("invalid inference request", aisec.UserRequestPayloadError, err)
			}
		}
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			return nil, aisec.WrapError("invalid inference JSON", aisec.UserRequestPayloadError, err)
		}
	}
	response, cancel, err := c.open(ctx, method, path, query, encoded, "application/json", opts)
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, aisec.WrapError("failed to read runtime response", aisec.ClientSideError, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		if responseSchema != "" {
			return nil, aisec.NewAISecSDKError("expected runtime JSON response", aisec.AISecSDKInternalError)
		}
		return nil, nil
	}
	if responseSchema != "" {
		if err := parity.ValidateJSON(responseSchema, data); err != nil {
			return nil, aisec.WrapError("invalid inference response", aisec.AISecSDKInternalError, err)
		}
	}

	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, aisec.WrapError("invalid runtime JSON response", aisec.AISecSDKInternalError, err)
	}
	return &result, nil
}

// RuntimeFile supplies binary multipart content without base64 or JSON-string input.
type RuntimeFile struct {
	Filename, ContentType string
	Data                  []byte
}
