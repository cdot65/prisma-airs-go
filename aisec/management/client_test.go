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
			Items: []SecurityProfile{{ProfileID: "p-1"}},
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

func TestProfiles_ForceDelete(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("method = %s, want DELETE", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/profile/p-1/force") {
			t.Errorf("path = %q, want /profile/p-1/force", r.URL.Path)
		}
		if r.URL.Query().Get("updated_by") != "admin@example.com" {
			t.Errorf("updated_by = %q", r.URL.Query().Get("updated_by"))
		}
		_ = json.NewEncoder(w).Encode(DeleteProfileResponse{Message: "force deleted"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	resp, err := client.Profiles.ForceDelete(context.Background(), "p-1", "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Message != "force deleted" {
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

	got, err := client.CustomerApps.Get(context.Background(), "test-app")
	if err != nil {
		t.Fatal(err)
	}
	if got.AppID != "a-1" {
		t.Errorf("AppID = %q", got.AppID)
	}
}

func TestCustomerApps_Get_QueryParam(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Query().Get("app_name") != "my-app" {
			t.Errorf("app_name = %q, want my-app", r.URL.Query().Get("app_name"))
		}
		// Verify no path param — path should end at /customerapp
		if strings.Contains(r.URL.Path, "/customerapp/") {
			t.Errorf("path = %q, should not have path param", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(CustomerApp{AppID: "a-1", AppName: "my-app"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	app, err := client.CustomerApps.Get(context.Background(), "my-app")
	if err != nil {
		t.Fatal(err)
	}
	if app.AppName != "my-app" {
		t.Errorf("AppName = %q", app.AppName)
	}
}

func TestCustomerApps_Update_QueryParam(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("method = %s, want PUT", r.Method)
		}
		if r.URL.Query().Get("customer_app_id") != "app-123" {
			t.Errorf("customer_app_id = %q, want app-123", r.URL.Query().Get("customer_app_id"))
		}
		_ = json.NewEncoder(w).Encode(CustomerApp{AppID: "app-123", AppName: "updated"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	app, err := client.CustomerApps.Update(context.Background(), "app-123", UpdateAppRequest{AppName: "updated"})
	if err != nil {
		t.Fatal(err)
	}
	if app.AppName != "updated" {
		t.Errorf("AppName = %q", app.AppName)
	}
}

func TestCustomerApps_Delete_QueryParams(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("method = %s, want DELETE", r.Method)
		}
		if r.URL.Query().Get("app_name") != "my-app" {
			t.Errorf("app_name = %q, want my-app", r.URL.Query().Get("app_name"))
		}
		if r.URL.Query().Get("updated_by") != "admin@example.com" {
			t.Errorf("updated_by = %q, want admin@example.com", r.URL.Query().Get("updated_by"))
		}
		_ = json.NewEncoder(w).Encode(DeleteAppResponse{Message: "deleted"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	resp, err := client.CustomerApps.Delete(context.Background(), "my-app", "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Message != "deleted" {
		t.Errorf("Message = %q", resp.Message)
	}
}

func TestDlpProfiles_List(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(DlpProfileListResponse{
			Items: []DlpProfile{{ID: "dlp-1"}},
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
			Items: []DeploymentProfile{{DpName: "dp-1"}},
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
		if r.Method != "POST" {
			t.Errorf("method = %s, want POST", r.Method)
		}
		q := r.URL.Query()
		if q.Get("time_interval") != "24" {
			t.Errorf("time_interval = %q", q.Get("time_interval"))
		}
		if q.Get("time_unit") != "hour" {
			t.Errorf("time_unit = %q", q.Get("time_unit"))
		}
		if q.Get("pageNumber") != "1" {
			t.Errorf("pageNumber = %q", q.Get("pageNumber"))
		}
		if q.Get("pageSize") != "10" {
			t.Errorf("pageSize = %q", q.Get("pageSize"))
		}
		if q.Get("filter") != "all" {
			t.Errorf("filter = %q", q.Get("filter"))
		}
		_ = json.NewEncoder(w).Encode(ScanLogListResponse{
			ScanResultForDashboard: &ScanResultForDashboard{
				ScanResultEntries: []ScanLog{{ScanID: "scan-1", Verdict: "benign"}},
			},
			TotalPages: 1,
			PageNumber: 1,
			PageSize:   10,
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	resp, err := client.ScanLogs.List(context.Background(), ScanLogListOpts{
		TimeInterval: 24,
		TimeUnit:     "hour",
		PageNumber:   1,
		PageSize:     10,
		Filter:       "all",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.ScanResultForDashboard == nil {
		t.Fatal("ScanResultForDashboard is nil")
	}
	if len(resp.ScanResultForDashboard.ScanResultEntries) != 1 {
		t.Errorf("entries = %d", len(resp.ScanResultForDashboard.ScanResultEntries))
	}
	if resp.ScanResultForDashboard.ScanResultEntries[0].ScanID != "scan-1" {
		t.Errorf("ScanID = %q", resp.ScanResultForDashboard.ScanResultEntries[0].ScanID)
	}
}

func TestScanLogs_List_WithPageToken(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s, want POST", r.Method)
		}
		var body PageTokenRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.PageToken != "next-page-token" {
			t.Errorf("page_token = %q, want next-page-token", body.PageToken)
		}
		_ = json.NewEncoder(w).Encode(ScanLogListResponse{
			ScanResultForDashboard: &ScanResultForDashboard{},
			TotalPages:             2,
			PageNumber:             2,
			PageSize:               10,
		})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	resp, err := client.ScanLogs.List(context.Background(), ScanLogListOpts{
		TimeInterval: 24,
		TimeUnit:     "hour",
		PageNumber:   2,
		PageSize:     10,
		Filter:       "all",
		PageToken:    "next-page-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.PageNumber != 2 {
		t.Errorf("PageNumber = %d", resp.PageNumber)
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
			Items: []CustomTopic{{TopicID: "t-1", TopicName: "test"}},
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
		if !strings.Contains(r.URL.Path, "/topic/t-1/force") {
			t.Errorf("path = %q, want /topic/t-1/force", r.URL.Path)
		}
		if r.URL.Query().Get("updated_by") != "admin@example.com" {
			t.Errorf("updated_by = %q", r.URL.Query().Get("updated_by"))
		}
		_ = json.NewEncoder(w).Encode(DeleteTopicResponse{Message: "force deleted"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	resp, err := client.Topics.ForceDelete(context.Background(), "t-1", "admin@example.com")
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
			Items: []ApiKey{{ApiKeyID: "k-1"}},
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
			Items: []CustomerApp{{AppID: "a-1"}},
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

func TestDlpProfiles_Get(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(DlpProfile{ID: "dlp-1", Name: "test-dlp"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	p, err := client.DlpProfiles.Get(context.Background(), "dlp-1")
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "dlp-1" {
		t.Errorf("ID = %q", p.ID)
	}
}

func TestDeploymentProfiles_Get(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(DeploymentProfile{DpName: "dp-1", AuthCode: "test-dp"})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	p, err := client.DeploymentProfiles.Get(context.Background(), "dp-1")
	if err != nil {
		t.Fatal(err)
	}
	if p.DpName != "dp-1" {
		t.Errorf("DpName = %q", p.DpName)
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

func TestApiKey_JSONRoundTrip(t *testing.T) {
	key := ApiKey{
		ApiKeyID:             "key-123",
		ApiKeyLast8:          "abcd1234",
		ApiKeyName:           "test-key",
		AuthCode:             "auth-code",
		CspID:                "csp-1",
		TsgID:                "tsg-1",
		Expiration:           "2025-12-31T00:00:00Z",
		Revoked:              true,
		RevokeReason:         "compromised",
		CustApp:              "my-app",
		CustEnv:              "production",
		CustAIAgentFramework: "langchain",
		CustCloudProvider:    "aws",
		CreatedBy:            "user@example.com",
		UpdatedBy:            "admin@example.com",
		LastModifiedTS:       "2025-06-01T00:00:00Z",
		RotationTimeInterval: 90,
		RotationTimeUnit:     "day",
		DpName:               "dp-1",
		Status:               "active",
		ApiKey:               "secret-key-value",
		LicExpiration:        "2026-12-31T00:00:00Z",
		AvgTextRecords:       1000,
		CreationTS:           "2025-01-01T00:00:00Z",
		CustomerAppID:        "app-456",
	}

	data, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}

	var decoded ApiKey
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.ApiKeyID != key.ApiKeyID {
		t.Errorf("ApiKeyID = %q", decoded.ApiKeyID)
	}
	if decoded.ApiKeyLast8 != key.ApiKeyLast8 {
		t.Errorf("ApiKeyLast8 = %q", decoded.ApiKeyLast8)
	}
	if decoded.Revoked != key.Revoked {
		t.Errorf("Revoked = %v", decoded.Revoked)
	}
	if decoded.RotationTimeInterval != key.RotationTimeInterval {
		t.Errorf("RotationTimeInterval = %d", decoded.RotationTimeInterval)
	}
	if decoded.CustomerAppID != key.CustomerAppID {
		t.Errorf("CustomerAppID = %q", decoded.CustomerAppID)
	}
}

func TestScanLog_JSONRoundTrip(t *testing.T) {
	log := ScanLog{
		CspID:             "csp-1",
		TsgID:             "tsg-1",
		ScanID:            "scan-abc",
		ScanSubReqID:      1,
		TransactionID:     "tx-123",
		ApiKeyName:        "key-1",
		ProfileID:         "prof-1",
		ProfileName:       "default",
		AppName:           "my-app",
		ModelName:         "gpt-4",
		User:              "user@example.com",
		Environment:       "production",
		CloudProvider:     "aws",
		AgentFramework:    "langchain",
		Tokens:            500,
		TextRecords:       1,
		ReportID:          "rpt-1",
		ReceivedTS:        "2025-06-01T00:00:00Z",
		CompletedTS:       "2025-06-01T00:00:01Z",
		Status:            "completed",
		Verdict:           "benign",
		Action:            "allow",
		IsPrompt:          true,
		IsResponse:        false,
		PIFinalVerdict:    "benign",
		UFFinalVerdict:    "benign",
		DLPFinalVerdict:   "benign",
		DBSFinalVerdict:   "benign",
		TCFinalVerdict:    "benign",
		MCFinalVerdict:    "benign",
		AgentFinalVerdict: "benign",
		CGFinalVerdict:    "benign",
		TGFinalVerdict:    "benign",
		PromptVerdict:     "benign",
		ResponseVerdict:   "benign",
		ContentMasked:     false,
		UserIP:            "192.168.1.1",
	}

	data, err := json.Marshal(log)
	if err != nil {
		t.Fatal(err)
	}

	var decoded ScanLog
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.ScanID != log.ScanID {
		t.Errorf("ScanID = %q", decoded.ScanID)
	}
	if decoded.Verdict != log.Verdict {
		t.Errorf("Verdict = %q", decoded.Verdict)
	}
	if decoded.Tokens != log.Tokens {
		t.Errorf("Tokens = %d", decoded.Tokens)
	}
	if decoded.IsPrompt != log.IsPrompt {
		t.Errorf("IsPrompt = %v", decoded.IsPrompt)
	}
	if decoded.PIFinalVerdict != log.PIFinalVerdict {
		t.Errorf("PIFinalVerdict = %q", decoded.PIFinalVerdict)
	}
	if decoded.UserIP != log.UserIP {
		t.Errorf("UserIP = %q", decoded.UserIP)
	}
}
