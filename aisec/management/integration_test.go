//go:build integration

package management

import (
	"context"
	"fmt"
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

	// 3. Update topic description
	updated, err := client.Topics.Update(ctx, created.TopicID, UpdateTopicRequest{
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

	token, err := client.OAuth.GetToken(ctx)
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
