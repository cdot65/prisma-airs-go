package gateway

import (
	"context"
	"github.com/cdot65/prisma-airs-go/aisec"
	"net/http"
	"strings"
	"time"

	"github.com/cdot65/prisma-airs-go/aisec/internal"
	parity "github.com/cdot65/prisma-airs-go/aisec/parity/schema"
)

// ModelPricingOpts selects an unauthenticated public catalog. No default endpoint or credential fallback is used.
type ModelPricingOpts struct {
	Endpoint   string
	Timeout    time.Duration
	NumRetries int
	HTTPClient *http.Client
}

// ModelPricingClient reads upstream catalog prices, rather than effective tenant billing or SCM cost telemetry.
type ModelPricingClient struct{ transport *InferenceClient }

// NewModelPricingClient creates a standalone, unauthenticated catalog client with redirects disabled.
func NewModelPricingClient(opts ModelPricingOpts) (*ModelPricingClient, error) {
	if err := validatePublicEndpoint(opts.Endpoint); err != nil {
		return nil, err
	}
	if opts.Timeout < 0 || opts.NumRetries < 0 || opts.NumRetries > 5 {
		return nil, invalidInput("invalid pricing deadline or retries")
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = time.Minute
	}
	client := internal.DefaultHTTPClient()
	if opts.HTTPClient != nil {
		client = opts.HTTPClient
	}
	clone := *client
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return invalidInput("pricing redirects are disabled") }
	return &ModelPricingClient{transport: &InferenceClient{baseURL: strings.TrimRight(opts.Endpoint, "/"), authenticate: func(http.Header) {}, client: &clone, timeout: timeout, numRetries: opts.NumRetries}}, nil
}

// Get reads provider/model rates and unevaluated expressions without altering currencies or formulas.
func (c *ModelPricingClient) Get(ctx context.Context, provider, model string) (*parity.GatewayModelPricingConfig, error) {
	if err := validateResourceID(provider); err != nil {
		return nil, err
	}
	if err := validateResourceID(model); err != nil {
		return nil, err
	}
	return inferenceJSON[parity.GatewayModelPricingConfig](ctx, c.transport, "GET", aisec.GatewayModelConfigsPricingPath+"/"+seg(provider)+"/"+seg(model), nil, nil, "", "GatewayModelPricingConfigSchema", InferenceRequestOptions{})
}
