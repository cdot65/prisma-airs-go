package agentguard

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
)

// Client exposes all operations in the AgentGuard public preview contracts.
type Client struct {
	Scans          *ScansClient
	Statistics     *StatisticsClient
	Instances      *InstancesClient
	Rules          *RulesClient
	RuleInstances  *RuleInstancesClient
	SkillOverrides *SkillOverridesClient
}

// NewClient creates an AgentGuard client sharing one OAuth token across planes.
func NewClient(opts Opts) (*Client, error) {
	dataEndpoint := internal.ResolveEndpoint(opts.DataEndpoint, aisec.EnvAgentGuardDataEndpoint, "")
	mgmtEndpoint := internal.ResolveEndpoint(opts.MgmtEndpoint, aisec.EnvAgentGuardMgmtEndpoint, "")
	for _, endpoint := range []struct{ name, value string }{{aisec.EnvAgentGuardDataEndpoint, dataEndpoint}, {aisec.EnvAgentGuardMgmtEndpoint, mgmtEndpoint}} {
		if endpoint.value == "" {
			return nil, aisec.NewAISecSDKError("AgentGuard endpoint is required (option or "+endpoint.name+")", aisec.MissingVariableError)
		}
		parsed, err := url.Parse(endpoint.value)
		if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.User != nil || parsed.ForceQuery || parsed.RawQuery != "" || strings.Contains(endpoint.value, "#") {
			return nil, aisec.NewAISecSDKError("invalid AgentGuard endpoint: "+endpoint.name, aisec.UserRequestPayloadError)
		}
	}
	mgmtCfg, err := internal.ResolveOAuthConfig(internal.ResolveOAuthConfigOpts{
		ClientID: opts.ClientID, ClientSecret: opts.ClientSecret, TsgID: opts.TsgID,
		BaseURL: mgmtEndpoint, TokenEndpoint: opts.TokenEndpoint, NumRetries: opts.NumRetries,
		PrimaryEnvPrefix: "PANW_AGENT_GUARD", FallbackEnvPrefix: "PANW_MGMT", HTTPClient: opts.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	// AgentGuard's SCM routing requires the tenant header on both API planes.
	// Keep it on service configs so OAuth token requests never receive it.
	mgmtCfg.Headers = http.Header{aisec.HeaderTsgID: {mgmtCfg.TsgID}}
	dataCfg := &internal.OAuthServiceConfig{BaseURL: dataEndpoint, OAuth: mgmtCfg.OAuth, NumRetries: mgmtCfg.NumRetries, TsgID: mgmtCfg.TsgID, HTTPClient: mgmtCfg.HTTPClient, Headers: mgmtCfg.Headers}
	return &Client{
		Scans: &ScansClient{dataCfg}, Statistics: &StatisticsClient{dataCfg},
		Instances: &InstancesClient{mgmtCfg}, Rules: &RulesClient{mgmtCfg},
		RuleInstances: &RuleInstancesClient{mgmtCfg}, SkillOverrides: &SkillOverridesClient{mgmtCfg},
	}, nil
}

func request[T any](ctx context.Context, cfg *internal.OAuthServiceConfig, method, path string, query url.Values, body any) (*T, error) {
	resp, err := internal.DoMgmtRequest[T](ctx, cfg, internal.MgmtRequestOptions{Method: method, Path: path, Query: query, Body: body})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func validUUIDs(ids ...string) error {
	for _, id := range ids {
		if !aisec.IsValidUUID(id) {
			return aisec.NewAISecSDKError("invalid AgentGuard UUID: "+id, aisec.UserRequestPayloadError)
		}
	}
	return nil
}

func validTenant(id string) error {
	if strings.TrimSpace(id) == "" {
		return aisec.NewAISecSDKError("tenant ID is required", aisec.UserRequestPayloadError)
	}
	return nil
}

// ScansClient provides scan lifecycle, findings, attack chains, and CSV export.
type ScansClient struct{ cfg *internal.OAuthServiceConfig }

// StatisticsClient provides scan and rule summary statistics.
type StatisticsClient struct{ cfg *internal.OAuthServiceConfig }

// InstancesClient manages tenant instances via the management plane.
type InstancesClient struct{ cfg *internal.OAuthServiceConfig }

// RulesClient lists the skill security rule catalog.
type RulesClient struct{ cfg *internal.OAuthServiceConfig }

// RuleInstancesClient lists and atomically updates rule configuration.
type RuleInstancesClient struct{ cfg *internal.OAuthServiceConfig }

// SkillOverridesClient manages trusted skill overrides.
type SkillOverridesClient struct{ cfg *internal.OAuthServiceConfig }

// ExportCSV calls GET /v1/scans/csv and returns the transport's raw body.
func (c *ScansClient) ExportCSV(ctx context.Context, opts ScanFilter) (*CSVExport, error) {
	raw, err := internal.DoMgmtRaw(ctx, c.cfg, internal.RawMgmtRequestOptions{Method: http.MethodGet, Path: aisec.AgentGuardScanCSVPath, Query: scanQuery(opts)})
	if err != nil {
		return nil, err
	}
	return &CSVExport{Body: raw.Body, Header: raw.Header}, nil
}
