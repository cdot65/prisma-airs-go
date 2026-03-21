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
		json.NewEncoder(w).Encode(map[string]any{
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
		json.NewEncoder(w).Encode(SecurityProfile{ProfileID: "p-1", ProfileName: "test"})
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
		json.NewEncoder(w).Encode(SecurityProfileListResponse{
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
		json.NewEncoder(w).Encode(SecurityProfile{ProfileID: "p-1", ProfileName: "updated"})
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
		json.NewEncoder(w).Encode(DeleteProfileResponse{Message: "deleted"})
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
		json.NewEncoder(w).Encode(CustomTopic{TopicID: "t-1", TopicName: "test"})
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
		json.NewEncoder(w).Encode(ApiKey{ApiKeyID: "k-1", ApiKeyName: "test-key"})
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
		json.NewEncoder(w).Encode(CustomerApp{AppID: "a-1", AppName: "test-app"})
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
		json.NewEncoder(w).Encode(DlpProfileListResponse{
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
		json.NewEncoder(w).Encode(DeploymentProfileListResponse{
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
		json.NewEncoder(w).Encode(ScanLogListResponse{
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
		json.NewEncoder(w).Encode(OAuthToken{AccessToken: "mgmt-token", ExpiresIn: 3600})
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
		json.NewEncoder(w).Encode(map[string]any{"access_token": "t", "expires_in": 3600})
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
