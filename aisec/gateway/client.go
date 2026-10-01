package gateway

import (
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	"net/http"
)

// Opts configures management CRUD access with SCM OAuth. Workspaces must already exist.
type Opts struct {
	ClientID, ClientSecret, TsgID, DataEndpoint, AdminEndpoint, TokenEndpoint string
	NumRetries                                                                int
	HTTPClient                                                                *http.Client
}

// Client exposes Gateway CRUD and explicit lifecycle operations.
type Client struct {
	Guardrails        *GuardrailsClient
	OrgGuardrails     *OrgGuardrailsClient
	Configs           *ConfigsClient
	Integrations      *IntegrationsClient
	Providers         *ProvidersClient
	MCPIntegrations   *MCPIntegrationsClient
	MCPServers        *MCPServersClient
	APIKeys           *APIKeysClient
	UsageLimits       *UsageLimitsClient
	RateLimits        *RateLimitsClient
	SecretReferences  *SecretReferencesClient
	Deployments       *DeploymentsClient
	dataCfg, adminCfg *internal.OAuthServiceConfig
}

// GuardrailsClient manages Guardrails resources.
type GuardrailsClient struct{ cfg *internal.OAuthServiceConfig }

// OrgGuardrailsClient manages OrgGuardrails resources.
type OrgGuardrailsClient struct{ cfg *internal.OAuthServiceConfig }

// ConfigsClient manages Configs resources.
type ConfigsClient struct{ cfg *internal.OAuthServiceConfig }

// IntegrationsClient manages Integrations resources.
type IntegrationsClient struct{ cfg *internal.OAuthServiceConfig }

// ProvidersClient manages Providers resources.
type ProvidersClient struct{ cfg *internal.OAuthServiceConfig }

// MCPIntegrationsClient manages MCPIntegrations resources.
type MCPIntegrationsClient struct{ cfg *internal.OAuthServiceConfig }

// MCPServersClient manages MCPServers resources.
type MCPServersClient struct{ cfg *internal.OAuthServiceConfig }

// APIKeysClient manages APIKeys resources.
type APIKeysClient struct{ cfg *internal.OAuthServiceConfig }

// UsageLimitsClient manages UsageLimits resources.
type UsageLimitsClient struct{ cfg *internal.OAuthServiceConfig }

// RateLimitsClient manages RateLimits resources.
type RateLimitsClient struct{ cfg *internal.OAuthServiceConfig }

// SecretReferencesClient manages SecretReferences resources.
type SecretReferencesClient struct{ cfg *internal.OAuthServiceConfig }

// DeploymentsClient manages Deployments resources.
type DeploymentsClient struct{ cfg *internal.OAuthServiceConfig }

// NewClient creates a Gateway management client using options, PANW_AI_GW or PANW_MGMT credentials.
func NewClient(opts Opts) (*Client, error) {
	data, err := internal.ResolveOAuthConfig(internal.ResolveOAuthConfigOpts{ClientID: opts.ClientID, ClientSecret: opts.ClientSecret, TsgID: opts.TsgID, BaseURL: internal.ResolveEndpoint(opts.DataEndpoint, aisec.EnvGatewayDataEndpoint, aisec.DefaultGatewayDataEndpoint), TokenEndpoint: opts.TokenEndpoint, NumRetries: opts.NumRetries, HTTPClient: opts.HTTPClient, PrimaryEnvPrefix: "PANW_AI_GW", FallbackEnvPrefix: "PANW_MGMT"})
	if err != nil {
		return nil, err
	}
	data.Headers = http.Header{}
	data.Headers.Set(aisec.HeaderTsgID, data.TsgID)
	admin := *data
	admin.BaseURL = internal.ResolveEndpoint(opts.AdminEndpoint, aisec.EnvGatewayAdminEndpoint, aisec.DefaultGatewayAdminEndpoint)
	c := &Client{dataCfg: data, adminCfg: &admin}
	c.Guardrails = &GuardrailsClient{cfg: data}
	c.OrgGuardrails = &OrgGuardrailsClient{cfg: &admin}
	c.Configs = &ConfigsClient{cfg: data}
	c.Integrations = &IntegrationsClient{cfg: &admin}
	c.Providers = &ProvidersClient{cfg: data}
	c.MCPIntegrations = &MCPIntegrationsClient{cfg: &admin}
	c.MCPServers = &MCPServersClient{cfg: data}
	c.APIKeys = &APIKeysClient{cfg: data}
	c.UsageLimits = &UsageLimitsClient{cfg: data}
	c.RateLimits = &RateLimitsClient{cfg: data}
	c.SecretReferences = &SecretReferencesClient{cfg: &admin}
	c.Deployments = &DeploymentsClient{cfg: &admin}
	return c, nil
}
func seg(value string) string { return internal.PathSeg(value) }
