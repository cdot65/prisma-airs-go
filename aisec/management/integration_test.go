//go:build integration

package management

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cdot65/prisma-airs-go/aisec/internal/testutil"
)

func newIntegrationClient(t *testing.T) *Client {
	t.Helper()
	testutil.LoadProjectEnv(t)
	testutil.RequireEnv(t, "PANW_MGMT_CLIENT_ID", "PANW_MGMT_CLIENT_SECRET", "PANW_MGMT_TSG_ID")

	client, err := NewClient(Opts{})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestIntegration_Profiles_List(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.Profiles.List(ctx, ListOpts{Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Profiles: %d items", len(resp.Items))
}

func TestIntegration_Topics_List(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.Topics.List(ctx, ListOpts{Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Topics: %d items", len(resp.Items))
}

func TestIntegration_ApiKeys_List(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.ApiKeys.List(ctx, ListOpts{Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ApiKeys: %d items", len(resp.Items))
}

func TestIntegration_ScanLogs_List(t *testing.T) {
	// ScanLogs endpoint consistently times out (>2min). Skip until API is stable.
	t.Skip("ScanLogs API endpoint unresponsive — times out even at 2min")
}

func TestIntegration_Topics_CRUD(t *testing.T) {
	client := newIntegrationClient(t)
	topicName := fmt.Sprintf("test-topic-%d", time.Now().UnixNano())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// 1. Create topic
	created, err := client.Topics.Create(ctx, CreateTopicRequest{
		TopicName:   topicName,
		Description: "test topic for integration testing",
		Examples:    []string{"example1", "example2"},
	})
	if err != nil {
		t.Fatalf("Topics.Create failed: %v", err)
	}
	t.Logf("Created topic: id=%s name=%s", created.TopicID, created.TopicName)

	if created.TopicID == "" {
		t.Fatal("expected non-empty TopicID after create")
	}

	// Cleanup: always delete even on failure
	t.Cleanup(func() {
		delCtx, delCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer delCancel()
		resp, err := client.Topics.Delete(delCtx, created.TopicID)
		if err != nil {
			t.Logf("WARNING: cleanup delete topic %s failed: %v", created.TopicID, err)
		} else {
			t.Logf("Cleanup: deleted topic %s: %s", created.TopicID, resp.Message)
		}
	})

	// 2. List topics, verify new topic appears
	listResp, err := client.Topics.List(ctx, ListOpts{Limit: 100})
	if err != nil {
		t.Fatalf("Topics.List failed: %v", err)
	}
	found := false
	for _, topic := range listResp.Items {
		if topic.TopicID == created.TopicID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("created topic %s not found in list of %d topics", created.TopicID, len(listResp.Items))
	} else {
		t.Logf("Verified topic %s appears in list (%d total)", created.TopicID, len(listResp.Items))
	}

	// 3. Update topic description (topic_name is required by the API)
	updated, err := client.Topics.Update(ctx, created.TopicID, UpdateTopicRequest{
		TopicName:   topicName,
		Description: "updated description for integration test",
	})
	if err != nil {
		t.Fatalf("Topics.Update failed: %v", err)
	}
	t.Logf("Updated topic: id=%s description=%s", updated.TopicID, updated.Description)
	if updated.Description != "updated description for integration test" {
		t.Errorf("description mismatch after update: got %q", updated.Description)
	}

	// 4. Delete handled by t.Cleanup above
}

func TestIntegration_Profiles_ReadOnly(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// List profiles
	resp, err := client.Profiles.List(ctx, ListOpts{Limit: 10})
	if err != nil {
		t.Fatalf("Profiles.List failed: %v", err)
	}
	t.Logf("Profiles: %d items", len(resp.Items))

	if len(resp.Items) == 0 {
		t.Log("No profiles found, skipping GetByName")
		return
	}

	// Get first profile by name
	first := resp.Items[0]
	t.Logf("First profile: id=%s name=%s active=%v", first.ProfileID, first.ProfileName, first.Active)

	if first.ProfileName != "" {
		profile, err := client.Profiles.GetByName(ctx, first.ProfileName)
		if err != nil {
			t.Fatalf("Profiles.GetByName(%s) failed: %v", first.ProfileName, err)
		}
		t.Logf("GetByName result: id=%s name=%s revision=%d", profile.ProfileID, profile.ProfileName, profile.Revision)
	}
}

func TestIntegration_DlpProfiles_Read(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.DlpProfiles.List(ctx, ListOpts{Limit: 10})
	if err != nil {
		t.Fatalf("DlpProfiles.List failed: %v", err)
	}
	t.Logf("DlpProfiles: %d items", len(resp.Items))

	if len(resp.Items) == 0 {
		t.Log("No DLP profiles found, skipping Get")
		return
	}

	first := resp.Items[0]
	t.Logf("First DLP profile: id=%s name=%s", first.ID, first.Name)

	if first.ID != "" {
		profile, err := client.DlpProfiles.Get(ctx, first.ID)
		if err != nil {
			t.Fatalf("DlpProfiles.Get(%s) failed: %v", first.ID, err)
		}
		t.Logf("DlpProfiles.Get result: id=%s name=%s", profile.ID, profile.Name)
	}
}

func TestIntegration_DeploymentProfiles_Read(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.DeploymentProfiles.List(ctx, ListOpts{Limit: 10})
	if err != nil {
		t.Fatalf("DeploymentProfiles.List failed: %v", err)
	}
	t.Logf("DeploymentProfiles: %d items", len(resp.Items))

	if len(resp.Items) == 0 {
		t.Log("No deployment profiles found, skipping Get")
		return
	}

	first := resp.Items[0]
	t.Logf("First deployment profile: dpName=%s status=%s authCode=%s",
		first.DpName, first.Status, first.AuthCode)
}

func TestIntegration_OAuth_GetToken(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Requires a valid Apigee client_id for a customer app
	clientID := os.Getenv("PANW_MGMT_OAUTH_APP_CLIENT_ID")
	if clientID == "" {
		t.Skip("PANW_MGMT_OAUTH_APP_CLIENT_ID not set")
	}

	// Look up an existing customer app to use
	apps, err := client.CustomerApps.List(ctx, ListOpts{Limit: 1})
	if err != nil {
		t.Fatalf("CustomerApps.List: %v", err)
	}
	if len(apps.Items) == 0 {
		t.Skip("no customer apps found, cannot test OAuth.GetToken")
	}
	appName := apps.Items[0].AppName
	t.Logf("Using customer app: %s", appName)

	token, err := client.OAuth.GetToken(ctx, OAuthTokenRequest{
		ClientID:    clientID,
		CustomerApp: appName,
	})
	if err != nil {
		t.Fatalf("OAuth.GetToken failed: %v", err)
	}

	if token.AccessToken == "" {
		t.Error("expected non-empty AccessToken")
	}
	if token.TokenType == "" {
		t.Error("expected non-empty TokenType")
	}

	t.Logf("OAuth token: type=%s expiresIn=%s tokenLen=%d",
		token.TokenType, token.ExpiresIn, len(token.AccessToken))
}

func TestIntegration_Profiles_CRUD(t *testing.T) {
	client := newIntegrationClient(t)
	profileName := fmt.Sprintf("go-sdk-inttest-%d", time.Now().UnixNano())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// 1. Create
	created, err := client.Profiles.Create(ctx, CreateProfileRequest{
		ProfileName: profileName,
		Policy: &ProfilePolicy{
			AiSecurityProfiles: []AiSecurityProfileConfig{
				{
					ModelType: "default",
					ModelConfiguration: &ModelConfiguration{
						MaskDataInStorage: false,
						Latency: &LatencyConfig{
							InlineTimeoutAction: ProfileActionBlock,
							MaxInlineLatency:    5,
						},
						ModelProtection: []ModelProtectionConfig{
							{Name: "prompt-injection", Action: ProfileActionBlock},
						},
						AgentProtection: []AgentProtectionConfig{
							{Name: "agent-security", Action: ProfileActionAlert},
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Logf("Created: id=%s name=%s revision=%d", created.ProfileID, created.ProfileName, created.Revision)

	if created.ProfileID == "" {
		t.Fatal("expected non-empty ProfileID")
	}
	if created.ProfileName != profileName {
		t.Errorf("ProfileName = %q, want %q", created.ProfileName, profileName)
	}
	if created.Revision != 1 {
		t.Errorf("Revision = %d, want 1", created.Revision)
	}

	// Cleanup
	t.Cleanup(func() {
		delCtx, delCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer delCancel()
		_, err := client.Profiles.ForceDelete(delCtx, created.ProfileID, "integration-test")
		if err != nil {
			t.Logf("WARNING: cleanup ForceDelete %s: %v", created.ProfileID, err)
		} else {
			t.Logf("Cleanup: force-deleted %s", created.ProfileID)
		}
	})

	// 2. List — verify profile appears
	listResp, err := client.Profiles.List(ctx, ListOpts{Limit: 1000})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, p := range listResp.Items {
		if p.ProfileID == created.ProfileID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("created profile %s not in list (%d items)", created.ProfileID, len(listResp.Items))
	}
	t.Logf("List: %d profiles, created profile found=%v", len(listResp.Items), found)

	// 3. GetByID
	byID, err := client.Profiles.GetByID(ctx, created.ProfileID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if byID.ProfileID != created.ProfileID {
		t.Errorf("GetByID ProfileID = %q, want %q", byID.ProfileID, created.ProfileID)
	}
	if byID.ProfileName != profileName {
		t.Errorf("GetByID ProfileName = %q, want %q", byID.ProfileName, profileName)
	}
	t.Logf("GetByID: id=%s name=%s revision=%d", byID.ProfileID, byID.ProfileName, byID.Revision)

	// 4. GetByName
	byName, err := client.Profiles.GetByName(ctx, profileName)
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	if byName.ProfileName != profileName {
		t.Errorf("GetByName ProfileName = %q, want %q", byName.ProfileName, profileName)
	}
	t.Logf("GetByName: id=%s revision=%d", byName.ProfileID, byName.Revision)

	// 5. Update — add contextual-grounding, increase latency
	updated, err := client.Profiles.Update(ctx, created.ProfileID, UpdateProfileRequest{
		ProfileName: profileName,
		Policy: &ProfilePolicy{
			AiSecurityProfiles: []AiSecurityProfileConfig{
				{
					ModelType: "default",
					ModelConfiguration: &ModelConfiguration{
						MaskDataInStorage: false,
						Latency: &LatencyConfig{
							InlineTimeoutAction: ProfileActionBlock,
							MaxInlineLatency:    10,
						},
						ModelProtection: []ModelProtectionConfig{
							{Name: "prompt-injection", Action: ProfileActionBlock},
							{Name: "contextual-grounding", Action: ProfileActionBlock},
						},
						AgentProtection: []AgentProtectionConfig{
							{Name: "agent-security", Action: ProfileActionBlock},
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Revision != 2 {
		t.Errorf("Updated Revision = %d, want 2", updated.Revision)
	}
	t.Logf("Updated: id=%s revision=%d", updated.ProfileID, updated.Revision)

	// 6. GetByName after update — should return highest revision
	latest, err := client.Profiles.GetByName(ctx, profileName)
	if err != nil {
		t.Fatalf("GetByName after update: %v", err)
	}
	if latest.Revision < 2 {
		t.Errorf("GetByName revision = %d, want >= 2", latest.Revision)
	}
	t.Logf("GetByName after update: id=%s revision=%d", latest.ProfileID, latest.Revision)

	// 7. Delete (cleanup runs via t.Cleanup)
}

func TestIntegration_Profiles_GetByID(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// List to find an existing profile
	resp, err := client.Profiles.List(ctx, ListOpts{Limit: 5})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(resp.Items) == 0 {
		t.Skip("no profiles found")
	}

	target := resp.Items[0]
	t.Logf("Target: id=%s name=%s", target.ProfileID, target.ProfileName)

	profile, err := client.Profiles.GetByID(ctx, target.ProfileID)
	if err != nil {
		t.Fatalf("GetByID(%s): %v", target.ProfileID, err)
	}
	if profile.ProfileID != target.ProfileID {
		t.Errorf("ProfileID = %q, want %q", profile.ProfileID, target.ProfileID)
	}
	if profile.ProfileName != target.ProfileName {
		t.Errorf("ProfileName = %q, want %q", profile.ProfileName, target.ProfileName)
	}
	t.Logf("GetByID: id=%s name=%s revision=%d", profile.ProfileID, profile.ProfileName, profile.Revision)
}

func TestIntegration_Profiles_GetByID_NotFound(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := client.Profiles.GetByID(ctx, "00000000-0000-0000-0000-000000000000")
	if err == nil {
		t.Fatal("expected error for nonexistent profile ID")
	}
	t.Logf("Expected error: %v", err)
}
