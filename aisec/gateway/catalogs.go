package gateway

import (
	"context"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	"github.com/cdot65/prisma-airs-go/aisec/internal/typedhttp"
	parity "github.com/cdot65/prisma-airs-go/aisec/parity/schema"
	"strings"
)

// GetCatalog returns available guardrail evaluators and parameter schemas, rather than configured instances.
func (c *GuardrailsClient) GetCatalog(ctx context.Context) (*parity.GatewayGuardrailCatalogResponse, error) {
	return typedhttp.Do[parity.GatewayGuardrailCatalogResponse](ctx, c.adminCfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.GatewayGuardrailCatalogPath, Params: map[string]string{"resource": "guardrails"}}, ResponseSchema: "GatewayGuardrailCatalogResponseSchema"})
}

// Catalog lists provider definitions accepted by integration creation.
func (c *IntegrationsClient) Catalog(ctx context.Context) (*parity.ListCatalogProvidersResponse, error) {
	return typedhttp.Do[parity.ListCatalogProvidersResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.GatewayProviderCatalogPath}, ResponseSchema: "ListCatalogProvidersResponseSchema"})
}

// ResolveProviderID accepts a UUID directly, or resolves a provider slug case-insensitively.
func (c *IntegrationsClient) ResolveProviderID(ctx context.Context, ref string) (string, error) {
	wanted := strings.TrimSpace(ref)
	if uuidPattern.MatchString(wanted) {
		return strings.ToLower(wanted), nil
	}
	if wanted == "" {
		return "", invalidInput("provider reference is required")
	}
	catalog, err := c.Catalog(ctx)
	if err != nil {
		return "", err
	}
	for _, provider := range catalog.Data {
		if strings.EqualFold(provider.Slug, wanted) {
			return provider.ID, nil
		}
	}
	return "", invalidInput("provider slug is absent from the catalog")
}
