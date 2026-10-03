package agentguard

import (
	"context"
	"net/http"

	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/agentguard/schema"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
)

// Create calls POST /v1/instances.
func (c *InstancesClient) Create(ctx context.Context, req schema.InstanceCreateModel) (*schema.InstanceResponseModel, error) {
	return request[schema.InstanceResponseModel](ctx, c.cfg, http.MethodPost, aisec.AgentGuardInstancesPath, nil, req)
}

// Get calls GET /v1/instances/{tenant_id}. Tenant IDs are strings, not UUIDs.
func (c *InstancesClient) Get(ctx context.Context, tenantID string) (*schema.Instance, error) {
	if err := validTenant(tenantID); err != nil {
		return nil, err
	}
	return request[schema.Instance](ctx, c.cfg, http.MethodGet, aisec.AgentGuardInstancesPath+"/"+internal.PathSeg(tenantID), nil, nil)
}

// Update calls PUT /v1/instances/{tenant_id}.
func (c *InstancesClient) Update(ctx context.Context, tenantID string, req schema.InstanceCreateModel) (*schema.InstanceResponseModel, error) {
	if err := validTenant(tenantID); err != nil {
		return nil, err
	}
	return request[schema.InstanceResponseModel](ctx, c.cfg, http.MethodPut, aisec.AgentGuardInstancesPath+"/"+internal.PathSeg(tenantID), nil, req)
}

// Delete calls DELETE /v1/instances/{tenant_id}, which returns a JSON receipt.
func (c *InstancesClient) Delete(ctx context.Context, tenantID string) (*schema.InstanceResponseModel, error) {
	if err := validTenant(tenantID); err != nil {
		return nil, err
	}
	return request[schema.InstanceResponseModel](ctx, c.cfg, http.MethodDelete, aisec.AgentGuardInstancesPath+"/"+internal.PathSeg(tenantID), nil, nil)
}

// List calls GET /v1/rules.
func (c *RulesClient) List(ctx context.Context, opts ListOpts) (*schema.ListSkillSecurityRulesResponse, error) {
	return request[schema.ListSkillSecurityRulesResponse](ctx, c.cfg, http.MethodGet, aisec.AgentGuardRulesPath, listQuery(opts), nil)
}

// List calls GET /v1/rule-instances.
func (c *RuleInstancesClient) List(ctx context.Context, opts ListOpts) (*schema.ListSkillSecurityRuleInstancesResponse, error) {
	return request[schema.ListSkillSecurityRuleInstancesResponse](ctx, c.cfg, http.MethodGet, aisec.AgentGuardRuleInstancesPath, listQuery(opts), nil)
}

// Update calls PUT /v1/rule-instances to atomically update rule states keyed by
// rule UUID in the tenant's singleton skill security group.
func (c *RuleInstancesClient) Update(ctx context.Context, req schema.SkillSecurityRuleInstancesUpdateRequest) (*schema.ListSkillSecurityRuleInstancesResponse, error) {
	return request[schema.ListSkillSecurityRuleInstancesResponse](ctx, c.cfg, http.MethodPut, aisec.AgentGuardRuleInstancesPath, nil, req)
}

// List calls GET /v1/skill-overrides.
func (c *SkillOverridesClient) List(ctx context.Context, opts SkillOverrideListOpts) (*schema.ListSkillOverridesResponse, error) {
	q := listQuery(opts.ListOpts)
	for key, value := range map[string]string{"skill_name": opts.SkillName, "fingerprint": opts.Fingerprint, "trusted_by": opts.TrustedBy, "q": opts.Q} {
		if value != "" {
			q.Set(key, value)
		}
	}
	return request[schema.ListSkillOverridesResponse](ctx, c.cfg, http.MethodGet, aisec.AgentGuardSkillOverridesPath, q, nil)
}

// Create calls POST /v1/skill-overrides to trust a skill fingerprint.
func (c *SkillOverridesClient) Create(ctx context.Context, req schema.SkillOverrideCreateRequest) (*schema.SkillOverrideResponse, error) {
	return request[schema.SkillOverrideResponse](ctx, c.cfg, http.MethodPost, aisec.AgentGuardSkillOverridesPath, nil, req)
}

// Delete calls DELETE /v1/skill-overrides/{override_uuid} (204, no body).
func (c *SkillOverridesClient) Delete(ctx context.Context, overrideUUID string) error {
	if err := validUUIDs(overrideUUID); err != nil {
		return err
	}
	_, err := internal.DoMgmtRequest[any](ctx, c.cfg, internal.MgmtRequestOptions{Method: http.MethodDelete, Path: aisec.AgentGuardSkillOverridesPath + "/" + internal.PathSeg(overrideUUID), ResponsePolicy: internal.AllowEmptyJSON})
	return err
}
