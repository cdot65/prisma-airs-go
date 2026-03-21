package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestMgmtServer creates a mock server that handles both OAuth token + API calls.
func newTestMgmtServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *httptest.Server) {
	t.Helper()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	}))

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			t.Errorf("missing Bearer auth: %q", auth)
			w.WriteHeader(401)
			return
		}
		handler(w, r)
	}))

	return tokenServer, apiServer
}

func newTestClient(t *testing.T, tokenURL, apiURL string) *Client {
	t.Helper()
	client, err := NewClient(Opts{
		ClientID:      "test-id",
		ClientSecret:  "test-secret",
		TsgID:         "123",
		APIEndpoint:   apiURL,
		TokenEndpoint: tokenURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestProfiles_Create(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(SecurityProfile{ProfileID: "p-1", ProfileName: "test"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	p, err := client.Profiles.Create(context.Background(), CreateProfileRequest{ProfileName: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if p.ProfileID != "p-1" {
		t.Errorf("ProfileID = %q", p.ProfileID)
	}
}

func TestProfiles_List(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(SecurityProfileListResponse{
			Items:      []SecurityProfile{{ProfileID: "p-1"}},
			TotalCount: 1,
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	resp, err := client.Profiles.List(context.Background(), ListOpts{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 1 {
		t.Errorf("items = %d", len(resp.Items))
	}
}

func TestProfiles_Update(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(SecurityProfile{ProfileID: "p-1", ProfileName: "updated"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	p, err := client.Profiles.Update(context.Background(), "p-1", UpdateProfileRequest{ProfileName: "updated"})
	if err != nil {
		t.Fatal(err)
	}
	if p.ProfileName != "updated" {
		t.Errorf("ProfileName = %q", p.ProfileName)
	}
}

func TestProfiles_Delete(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(DeleteProfileResponse{Message: "deleted"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	resp, err := client.Profiles.Delete(context.Background(), "p-1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Message != "deleted" {
		t.Errorf("Message = %q", resp.Message)
	}
}

func TestTopics_CRUD(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(CustomTopic{TopicID: "t-1", TopicName: "test"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)

	topic, err := client.Topics.Create(context.Background(), CreateTopicRequest{TopicName: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if topic.TopicID != "t-1" {
		t.Errorf("TopicID = %q", topic.TopicID)
	}
}

func TestApiKeys_Create(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ApiKey{ApiKeyID: "k-1", ApiKeyName: "test-key"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	key, err := client.ApiKeys.Create(context.Background(), CreateApiKeyRequest{ApiKeyName: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	if key.ApiKeyID != "k-1" {
		t.Errorf("ApiKeyID = %q", key.ApiKeyID)
	}
}

func TestCustomerApps_CRUD(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(CustomerApp{AppID: "a-1", AppName: "test-app"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)

	app, err := client.CustomerApps.Create(context.Background(), CreateAppRequest{AppName: "test-app"})
	if err != nil {
		t.Fatal(err)
	}
	if app.AppID != "a-1" {
		t.Errorf("AppID = %q", app.AppID)
	}

	got, err := client.CustomerApps.Get(context.Background(), "a-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.AppID != "a-1" {
		t.Errorf("AppID = %q", got.AppID)
	}
}

func TestDlpProfiles_List(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(DlpProfileListResponse{
			Items: []DlpProfile{{ProfileID: "dlp-1"}}, TotalCount: 1,
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	resp, err := client.DlpProfiles.List(context.Background(), ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 1 {
		t.Errorf("items = %d", len(resp.Items))
	}
}

func TestDeploymentProfiles_List(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(DeploymentProfileListResponse{
			Items: []DeploymentProfile{{ProfileID: "dp-1"}}, TotalCount: 1,
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	resp, err := client.DeploymentProfiles.List(context.Background(), ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 1 {
		t.Errorf("items = %d", len(resp.Items))
	}
}

func TestScanLogs_List(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ScanLogListResponse{
			Items: []ScanLog{{LogID: "log-1"}}, TotalCount: 1,
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	resp, err := client.ScanLogs.List(context.Background(), ScanLogListOpts{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 1 {
		t.Errorf("items = %d", len(resp.Items))
	}
}

func TestOAuth_GetToken(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(OAuthToken{AccessToken: "mgmt-token", ExpiresIn: 3600})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	token, err := client.OAuth.GetToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != "mgmt-token" {
		t.Errorf("AccessToken = %q", token.AccessToken)
	}
}

func TestNewClient_MissingCredentials(t *testing.T) {
	_, err := NewClient(Opts{})
	if err == nil {
		t.Fatal("expected error for missing credentials")
	}
}

func TestSubClients_AllPresent(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "t", "expires_in": 3600})
	}))
	defer tokenSrv.Close()

	client := newTestClient(t, tokenSrv.URL, "https://api.example.com")

	if client.Profiles == nil {
		t.Error("Profiles is nil")
	}
	if client.Topics == nil {
		t.Error("Topics is nil")
	}
	if client.ApiKeys == nil {
		t.Error("ApiKeys is nil")
	}
	if client.CustomerApps == nil {
		t.Error("CustomerApps is nil")
	}
	if client.DlpProfiles == nil {
		t.Error("DlpProfiles is nil")
	}
	if client.DeploymentProfiles == nil {
		t.Error("DeploymentProfiles is nil")
	}
	if client.ScanLogs == nil {
		t.Error("ScanLogs is nil")
	}
	if client.OAuth == nil {
		t.Error("OAuth is nil")
	}
}

func TestProfiles_GetByName(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method = %s", r.Method)
		}
		if r.URL.Query().Get("profile_name") != "my-profile" {
			t.Errorf("profile_name = %q", r.URL.Query().Get("profile_name"))
		}
		_ = json.NewEncoder(w).Encode(SecurityProfile{ProfileID: "p-1", ProfileName: "my-profile"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	p, err := client.Profiles.GetByName(context.Background(), "my-profile")
	if err != nil {
		t.Fatal(err)
	}
	if p.ProfileName != "my-profile" {
		t.Errorf("ProfileName = %q", p.ProfileName)
	}
}

func TestTopics_List(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(CustomTopicListResponse{
			Items: []CustomTopic{{TopicID: "t-1", TopicName: "test"}}, TotalCount: 1,
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	resp, err := client.Topics.List(context.Background(), ListOpts{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 1 {
		t.Errorf("items = %d", len(resp.Items))
	}
}

func TestTopics_Update(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(CustomTopic{TopicID: "t-1", TopicName: "updated"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	topic, err := client.Topics.Update(context.Background(), "t-1", UpdateTopicRequest{TopicName: "updated"})
	if err != nil {
		t.Fatal(err)
	}
	if topic.TopicName != "updated" {
		t.Errorf("TopicName = %q", topic.TopicName)
	}
}

func TestTopics_Delete(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(DeleteTopicResponse{Message: "deleted"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	resp, err := client.Topics.Delete(context.Background(), "t-1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Message != "deleted" {
		t.Errorf("Message = %q", resp.Message)
	}
}

func TestTopics_ForceDelete(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(DeleteTopicResponse{Message: "force deleted"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	resp, err := client.Topics.ForceDelete(context.Background(), "t-1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Message != "force deleted" {
		t.Errorf("Message = %q", resp.Message)
	}
}

func TestApiKeys_List(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(ApiKeyListResponse{
			Items: []ApiKey{{ApiKeyID: "k-1"}}, TotalCount: 1,
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	resp, err := client.ApiKeys.List(context.Background(), ListOpts{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 1 {
		t.Errorf("items = %d", len(resp.Items))
	}
}

func TestApiKeys_Delete(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("method = %s", r.Method)
		}
		if r.URL.Query().Get("api_key_name") != "my-key" {
			t.Errorf("api_key_name = %q", r.URL.Query().Get("api_key_name"))
		}
		if r.URL.Query().Get("updated_by") != "admin" {
			t.Errorf("updated_by = %q", r.URL.Query().Get("updated_by"))
		}
		_ = json.NewEncoder(w).Encode(ApiKeyDeleteResponse{Message: "deleted"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	resp, err := client.ApiKeys.Delete(context.Background(), "my-key", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Message != "deleted" {
		t.Errorf("Message = %q", resp.Message)
	}
}

func TestApiKeys_Regenerate(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(ApiKey{ApiKeyID: "k-new", ApiKeyName: "regen"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	key, err := client.ApiKeys.Regenerate(context.Background(), "k-1", RegenerateKeyRequest{UpdatedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if key.ApiKeyID != "k-new" {
		t.Errorf("ApiKeyID = %q", key.ApiKeyID)
	}
}

func TestCustomerApps_List(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(CustomerAppListResponse{
			Items: []CustomerApp{{AppID: "a-1"}}, TotalCount: 1,
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	resp, err := client.CustomerApps.List(context.Background(), ListOpts{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 1 {
		t.Errorf("items = %d", len(resp.Items))
	}
}

func TestCustomerApps_Update(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(CustomerApp{AppID: "a-1", AppName: "updated"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	app, err := client.CustomerApps.Update(context.Background(), "a-1", UpdateAppRequest{AppName: "updated"})
	if err != nil {
		t.Fatal(err)
	}
	if app.AppName != "updated" {
		t.Errorf("AppName = %q", app.AppName)
	}
}

func TestCustomerApps_Delete(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(DeleteAppResponse{Message: "deleted"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	resp, err := client.CustomerApps.Delete(context.Background(), "a-1")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Message != "deleted" {
		t.Errorf("Message = %q", resp.Message)
	}
}

func TestDlpProfiles_Get(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(DlpProfile{ProfileID: "dlp-1", ProfileName: "test-dlp"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	p, err := client.DlpProfiles.Get(context.Background(), "dlp-1")
	if err != nil {
		t.Fatal(err)
	}
	if p.ProfileID != "dlp-1" {
		t.Errorf("ProfileID = %q", p.ProfileID)
	}
}

func TestDeploymentProfiles_Get(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(DeploymentProfile{ProfileID: "dp-1", ProfileName: "test-dp"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	p, err := client.DeploymentProfiles.Get(context.Background(), "dp-1")
	if err != nil {
		t.Fatal(err)
	}
	if p.ProfileID != "dp-1" {
		t.Errorf("ProfileID = %q", p.ProfileID)
	}
}

func TestScanLogs_Get(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(ScanLog{LogID: "log-1"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	log, err := client.ScanLogs.Get(context.Background(), "log-1")
	if err != nil {
		t.Fatal(err)
	}
	if log.LogID != "log-1" {
		t.Errorf("LogID = %q", log.LogID)
	}
}

func TestOAuth_InvalidateToken(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(InvalidateTokenResponse{Message: "invalidated"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	resp, err := client.OAuth.InvalidateToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Message != "invalidated" {
		t.Errorf("Message = %q", resp.Message)
	}
}
