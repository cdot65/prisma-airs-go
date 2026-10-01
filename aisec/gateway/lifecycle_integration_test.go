//go:build integration

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cdot65/prisma-airs-go/aisec/gateway/schema"
	"testing"
	"time"
)

func liveValue[T any](t *testing.T, value any) T {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return contractValue[T](t, b)
}
func receiptID(t *testing.T, value any) string {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		ID   string `json:"id"`
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if v.ID != "" {
		return v.ID
	}
	if v.Data.ID != "" {
		return v.Data.ID
	}
	t.Fatal("creation receipt has no ID")
	return ""
}
func cleanupResource(t *testing.T, remove func(context.Context) error) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := remove(ctx); err != nil {
			t.Errorf("disposable resource cleanup failed: %v", err)
		}
	})
}
func TestIntegration_GatewayBasicLifecycles(t *testing.T) {
	c, workspace := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	name := fmt.Sprintf("sdk-crud-%d", time.Now().UnixNano())
	updated := name + "-updated"
	org := c.dataCfg.TsgID
	t.Run("configs", func(t *testing.T) {
		created, err := c.Configs.Create(ctx, liveValue[schema.ConfigsCreateRequest](t, map[string]any{"name": name, "workspace_id": workspace, "config": map[string]any{"provider": "openai", "retry": map[string]any{"attempts": 1}}}))
		if err != nil {
			t.Fatal(err)
		}
		id := receiptID(t, created)
		cleanupResource(t, func(ctx context.Context) error { _, err := c.Configs.Delete(ctx, id); return err })
		if _, err := c.Configs.Get(ctx, id); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Configs.Update(ctx, id, liveValue[schema.ConfigsUpdateRequest](t, map[string]any{"name": updated, "config": map[string]any{"provider": "openai", "retry": map[string]any{"attempts": 0}}})); err != nil {
			t.Fatal(err)
		}
		read, err := c.Configs.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if read.Name == nil || *read.Name != updated || read.Config == nil {
			t.Fatal("config update/read mismatch")
		}
		if _, err := c.Configs.ListVersions(ctx, id); err != nil {
			t.Fatal(err)
		}
	})
	guard := func(t *testing.T, orgScope bool) {
		body := map[string]any{"name": name, "workspace_id": workspace, "checks": []any{map[string]any{"id": "default.isAllLowerCase"}}, "actions": map[string]any{"deny": false, "async": false, "on_success": map[string]any{"feedback": map[string]any{"value": 5, "weight": 1, "metadata": ""}}, "on_fail": map[string]any{"feedback": map[string]any{"value": -5, "weight": 1, "metadata": ""}}}}
		if orgScope {
			delete(body, "workspace_id")
			body["organisation_id"] = org
		}
		req := liveValue[schema.CreateGuardrailRequest](t, body)
		var created *schema.CreateGuardrailResponse
		var err error
		if orgScope {
			created, err = c.OrgGuardrails.Create(ctx, req)
		} else {
			created, err = c.Guardrails.Create(ctx, req)
		}
		if err != nil {
			t.Fatal(err)
		}
		id := receiptID(t, created)
		cleanupResource(t, func(ctx context.Context) error {
			if orgScope {
				return c.OrgGuardrails.Delete(ctx, id)
			}
			return c.Guardrails.Delete(ctx, id)
		})
		update := liveValue[schema.UpdateGuardrailRequest](t, map[string]any{"name": updated})
		if orgScope {
			if _, err := c.OrgGuardrails.Get(ctx, id); err != nil {
				t.Fatal(err)
			}
			if _, err := c.OrgGuardrails.Update(ctx, id, update); err != nil {
				t.Fatal(err)
			}
		} else {
			if _, err := c.Guardrails.Get(ctx, id); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Guardrails.Update(ctx, id, update); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Run("workspace_guardrails", func(t *testing.T) { guard(t, false) })
	t.Run("org_guardrails", func(t *testing.T) { guard(t, true) })
	t.Run("service_api_keys", func(t *testing.T) {
		created, err := c.APIKeys.Create(ctx, APIKeyService, liveValue[schema.CreateAPIKeyObject](t, map[string]any{"name": name, "organisation_id": org, "workspace_id": workspace, "type": "service", "scopes": []string{"completions.write"}}))
		if err != nil {
			t.Fatal(err)
		}
		id := receiptID(t, created)
		cleanupResource(t, func(ctx context.Context) error { _, err := c.APIKeys.DeleteForKind(ctx, APIKeyService, id); return err })
		if created.Key == nil || *created.Key == "" {
			t.Fatal("creation omitted one-time key")
		}
		if _, err := c.APIKeys.GetForKind(ctx, APIKeyService, id); err != nil {
			t.Fatal(err)
		}
		if _, err := c.APIKeys.UpdateForKind(ctx, APIKeyService, id, liveValue[schema.UpdateAPIKeyObject](t, map[string]any{"name": updated})); err != nil {
			t.Fatal(err)
		}
		rotated, err := c.APIKeys.RotateForKind(ctx, APIKeyService, id, liveValue[schema.RotateAPIKeyRequest](t, map[string]any{}))
		if err != nil {
			t.Fatal(err)
		}
		if rotated.Key == nil || *rotated.Key == "" {
			t.Fatal("rotation omitted one-time key")
		}
	})
	t.Run("usage_limits", func(t *testing.T) {
		created, err := c.UsageLimits.Create(ctx, liveValue[schema.CreateUsageLimitsPolicyRequest](t, map[string]any{"name": name, "workspace_id": workspace, "type": "tokens", "credit_limit": 100000, "conditions": []any{map[string]any{"key": "metadata.sdk_verification", "value": name}}, "group_by": []any{map[string]any{"key": "metadata.sdk_verification"}}}))
		if err != nil {
			t.Fatal(err)
		}
		id := receiptID(t, created)
		cleanupResource(t, func(ctx context.Context) error { _, err := c.UsageLimits.Delete(ctx, id); return err })
		if _, err := c.UsageLimits.Get(ctx, id, schema.UsageLimitsGetOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.UsageLimits.Update(ctx, id, liveValue[schema.UpdateUsageLimitsPolicyRequest](t, map[string]any{"name": updated, "alert_threshold": 0})); err != nil {
			t.Fatal(err)
		}
		if _, err := c.UsageLimits.ListEntities(ctx, id, schema.UsageLimitsListEntitiesOptions{}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("rate_limits", func(t *testing.T) {
		created, err := c.RateLimits.Create(ctx, liveValue[schema.CreateRateLimitsPolicyRequest](t, map[string]any{"name": name, "workspace_id": workspace, "type": "requests", "unit": "rpm", "value": 100, "conditions": []any{map[string]any{"key": "metadata.sdk_verification", "value": name}}, "group_by": []any{map[string]any{"key": "metadata.sdk_verification"}}}))
		if err != nil {
			t.Fatal(err)
		}
		id := receiptID(t, created)
		cleanupResource(t, func(ctx context.Context) error { _, err := c.RateLimits.Delete(ctx, id); return err })
		if _, err := c.RateLimits.Get(ctx, id, schema.RateLimitsGetOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.RateLimits.Update(ctx, id, liveValue[schema.UpdateRateLimitsPolicyRequest](t, map[string]any{"name": updated, "value": 0})); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("deployments", func(t *testing.T) {
		created, err := c.Deployments.Create(ctx, liveValue[schema.CreateDeploymentRequest](t, map[string]any{"name": name, "organisation_id": org, "type": "non_production", "is_default": false}))
		if err != nil {
			t.Fatal(err)
		}
		id := receiptID(t, created)
		cleanupResource(t, func(ctx context.Context) error { _, err := c.Deployments.Delete(ctx, id); return err })
		if created.ClientAuth == nil || *created.ClientAuth == "" {
			t.Fatal("deployment creation omitted one-time client auth")
		}
		if _, err := c.Deployments.Get(ctx, id); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Deployments.Update(ctx, id, liveValue[schema.UpdateDeploymentRequest](t, map[string]any{"name": updated, "is_default": false})); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("secret_references", func(t *testing.T) {
		created, err := c.SecretReferences.Create(ctx, liveValue[schema.CreateSecretReferenceRequest](t, map[string]any{"name": name, "organisation_id": org, "manager_type": "aws_sm", "secret_path": "sdk-verification-unbound", "auth_config": map[string]any{"aws_auth_type": "serviceRole", "aws_region": "us-east-1"}, "allow_all_workspaces": false, "allowed_workspaces": []string{workspace}}))
		if err != nil {
			t.Fatal(err)
		}
		id := receiptID(t, created)
		cleanupResource(t, func(ctx context.Context) error { _, err := c.SecretReferences.Delete(ctx, id); return err })
		if _, err := c.SecretReferences.Get(ctx, id); err != nil {
			t.Fatal(err)
		}
		if _, err := c.SecretReferences.Update(ctx, id, liveValue[schema.UpdateSecretReferenceRequest](t, map[string]any{"description": "updated", "allow_all_workspaces": false})); err != nil {
			t.Fatal(err)
		}
	})
}
