//go:build integration

package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
)

func TestIntegration_RuntimeSpecRouteProbes(t *testing.T) {
	c := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, path := range []string{"/v1/mgmt/profiles", "/v1/mgmt/topics", "/v1/mgmt/apikeys"} {
		r, err := internal.DoMgmtRaw(ctx, c.Profiles.svcCfg, internal.RawMgmtRequestOptions{Method: http.MethodGet, Path: path, Params: map[string]string{"limit": "1"}})
		if err != nil {
			var sdk *aisec.AISecSDKError
			if !errors.As(err, &sdk) {
				t.Fatal(err)
			}
			t.Logf("spec route GET %s: status=%d error=%s", path, sdk.StatusCode, sdk.Message)
		} else {
			t.Logf("spec route GET %s: status=%d Content-Type=%q", path, r.Status, r.Header.Get("Content-Type"))
		}
	}
	// Use a fresh random UUID that cannot address an existing key. Both probes
	// must fail; their status/messages distinguish route and resource failures.
	id := "ba130084-25db-4164-a77a-1ed866a4a529"
	for _, path := range []string{"/v1/mgmt/apikey/" + id + "/regenerate", "/v1/mgmt/apikey/regenerate/" + id} {
		_, err := internal.DoMgmtRaw(ctx, c.ApiKeys.svcCfg, internal.RawMgmtRequestOptions{Method: http.MethodPost, Path: path, Body: []byte(`{"rotation_time_interval":1,"rotation_time_unit":"day"}`)})
		if err == nil {
			t.Fatalf("unexpected success regenerating nonexistent key via %s", path)
		}
		var sdk *aisec.AISecSDKError
		if !errors.As(err, &sdk) {
			t.Fatal(err)
		}
		t.Logf("nonexistent-key POST %s: status=%d error=%s", path, sdk.StatusCode, sdk.Message)
	}
}

func TestIntegration_Topics_ForceDelete(t *testing.T) {
	c := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	created, err := c.Topics.Create(ctx, CreateTopicRequest{TopicName: fmt.Sprintf("go-sdk-force-probe-%d", time.Now().UnixNano()), Description: "SDK disposable force-delete probe", Examples: []string{"temporary test example"}})
	if err != nil {
		t.Fatal(err)
	}
	if created.TopicID == "" {
		t.Fatal("create omitted topic ID")
	}
	deleted := false
	t.Cleanup(func() {
		if deleted {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := c.Topics.Delete(cleanup, created.TopicID); err != nil {
			t.Errorf("cleanup %s: %v", created.TopicID, err)
		}
	})
	if _, err := c.Topics.ForceDelete(ctx, created.TopicID, "sdk-integration-test"); err != nil {
		t.Fatal(err)
	}
	deleted = true
	list, err := c.Topics.List(ctx, ListOpts{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	for _, topic := range list.Items {
		if topic.TopicID == created.TopicID {
			t.Error("force-deleted disposable topic remains in list")
		}
	}
}

func TestIntegration_ApiKeys_RegenerateDisposable(t *testing.T) {
	c := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	profiles, err := c.DeploymentProfiles.List(ctx, ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	var authCode string
	for _, p := range profiles.Items {
		if p.AuthCode != "" {
			authCode = p.AuthCode
			break
		}
	}
	if authCode == "" {
		t.Fatal("no deployment profile auth code available for disposable-key verification")
	}
	name := fmt.Sprintf("sdk-key-%d", time.Now().UnixNano())
	keys, err := c.ApiKeys.List(ctx, ListOpts{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	createdBy := "sdk-integration-test@example.com"
	if len(keys.Items) > 0 && keys.Items[0].CreatedBy != "" {
		createdBy = keys.Items[0].CreatedBy
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		apps, err := c.CustomerApps.List(cleanup, ListOpts{Limit: 1000})
		if err != nil {
			t.Errorf("list customer apps for cleanup: %v", err)
			return
		}
		for _, app := range apps.Items {
			if app.AppName == name {
				if _, err := c.CustomerApps.Delete(cleanup, name, createdBy); err != nil {
					t.Errorf("delete disposable customer app %s: %v", name, err)
				}
			}
		}
	})
	created, err := c.ApiKeys.Create(ctx, CreateApiKeyRequest{ApiKeyName: name, AuthCode: authCode, CustApp: name, CreatedBy: createdBy, CustEnv: "dev", CustCloudProvider: "aws", RotationTimeInterval: 1, RotationTimeUnit: "days"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := c.ApiKeys.Delete(cleanup, name, "sdk-integration-test"); err != nil {
			t.Errorf("delete disposable API key %s: %v", name, err)
		}
	})
	if created.ApiKeyID == "" {
		t.Fatal("key creation omitted API key ID")
	}
	rotated, err := c.ApiKeys.Regenerate(ctx, created.ApiKeyID, RegenerateKeyRequest{UpdatedBy: "sdk-integration-test", RotationTimeInterval: 1, RotationTimeUnit: "days"})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.ApiKeyID == "" {
		t.Error("regeneration omitted the replacement API key ID")
	}
	t.Log("Disposable key creation and regeneration succeeded; credentials were not logged")
}

func TestIntegration_Profiles_OrdinaryDelete(t *testing.T) {
	c := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	created, err := c.Profiles.Create(ctx, CreateProfileRequest{ProfileName: fmt.Sprintf("sdk-delete-%d", time.Now().UnixNano()), Policy: &ProfilePolicy{AiSecurityProfiles: []AiSecurityProfileConfig{{ModelType: "default", ModelConfiguration: &ModelConfiguration{Latency: &LatencyConfig{InlineTimeoutAction: ProfileActionBlock, MaxInlineLatency: 5}, ModelProtection: []ModelProtectionConfig{{Name: "prompt-injection", Action: ProfileActionBlock}}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if created.ProfileID == "" {
		t.Fatal("missing profile ID")
	}
	deleted := false
	t.Cleanup(func() {
		if deleted {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := c.Profiles.ForceDelete(cleanup, created.ProfileID, "sdk-integration-test"); err != nil && !errors.Is(err, aisec.ErrNotFound) {
			t.Errorf("force cleanup %s: %v", created.ProfileID, err)
		}
	})
	if _, err := c.Profiles.Delete(ctx, created.ProfileID); err != nil {
		t.Fatal(err)
	}
	deleted = true
}

func TestIntegration_RuntimeNewQueryOptions(t *testing.T) {
	c := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	latest := false
	if _, err := c.Profiles.ListWithOptions(ctx, ProfileListOpts{ListOpts: ListOpts{Limit: 5}, Latest: &latest}); err != nil {
		t.Fatal(err)
	}
	unactivated := false
	if _, err := c.DeploymentProfiles.ListWithOptions(ctx, DeploymentProfileListOpts{Unactivated: &unactivated}); err != nil {
		t.Fatal(err)
	}
}
