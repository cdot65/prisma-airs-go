package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/cdot65/prisma-airs-go/aisec"
	parity "github.com/cdot65/prisma-airs-go/aisec/parity/schema"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
)

func runtimeParityClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_, _ = io.WriteString(w, `{"access_token":"token","expires_in":3600}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Error("OAuth missing")
		}
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	c, err := NewClient(Opts{ClientID: "id", ClientSecret: "secret", TsgID: "123", APIEndpoint: server.URL, DLPEndpoint: server.URL, TokenEndpoint: server.URL + "/token"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestTokenScopedListsUseUnqualifiedRoutes(t *testing.T) {
	for _, path := range []string{"profiles", "topics", "apikeys", "customerapps"} {
		t.Run(path, func(t *testing.T) {
			c := runtimeParityClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/mgmt/"+path || r.URL.Query().Get("offset") != "0" || r.URL.Query().Get("limit") != "100" {
					t.Errorf("unexpected %s", r.URL)
				}
				_, _ = io.WriteString(w, `{"items":[],"next_offset":0}`)
			})
			ctx := context.Background()
			var err error
			switch path {
			case "profiles":
				_, err = c.Profiles.ListForToken(ctx, ProfileListOpts{})
			case "topics":
				_, err = c.Topics.ListForToken(ctx, ListOpts{})
			case "apikeys":
				_, err = c.ApiKeys.ListForToken(ctx, ListOpts{})
			case "customerapps":
				_, err = c.CustomerApps.ListForToken(ctx, ListOpts{})
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestDLPCollectionHonorsFinalPageAndRecordCap(t *testing.T) {
	var calls int
	c := runtimeParityClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Tsg-Id") != "" {
			t.Error("DLP received dashboard tenant header")
		}
		if r.URL.Query().Get("size") != "2" || !reflect.DeepEqual(r.URL.Query()["sort"], []string{"name,asc", "id,desc"}) {
			t.Errorf("DLP query: %s", r.URL)
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		calls++
		if page == 0 {
			_, _ = io.WriteString(w, `{"content":[{"name":"a"},{"name":"b"}],"last":false,"totalPages":2}`)
		} else {
			_, _ = io.WriteString(w, `{"content":[{"name":"c"},{"name":"d"}],"last":true,"totalPages":2}`)
		}
	})
	maximum := 3
	items, err := c.DLP.DataPatterns.ListAll(context.Background(), DLPListAllOptions{Size: 2, Max: &maximum, Sort: []string{"name,asc", "id,desc"}})
	if err != nil || len(items) != 3 || calls != 2 {
		t.Fatalf("items=%v calls=%d err=%v", items, calls, err)
	}
}
func TestDLPEmptyNonfinalPageIsInternalError(t *testing.T) {
	c := runtimeParityClient(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{"content":[],"last":false}`) })
	_, err := c.DLP.DataPatterns.ListAll(context.Background(), DLPListAllOptions{})
	var sdk *aisec.AISecSDKError
	if !errors.As(err, &sdk) || sdk.ErrorType != aisec.AISecSDKInternalError {
		t.Fatal(err)
	}
}
func TestDictionaryMultipartAndHTTPStatus(t *testing.T) {
	var mode string
	c := runtimeParityClient(t, func(w http.ResponseWriter, r *http.Request) {
		if mode == "missing" {
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"message":"confidential keyword"}`)
			return
		}
		if mode == "replace" {
			w.WriteHeader(204)
			return
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"json", "file"} {
			file, h, err := r.FormFile(name)
			if err != nil {
				t.Error(err)
				return
			}
			b, _ := io.ReadAll(file)
			_ = file.Close()
			if name == "json" {
				var fields map[string]any
				_ = json.Unmarshal(b, &fields)
				if h.Filename != "metadata.json" || h.Header.Get("Content-Type") != "application/json" || fields["name"] != "test" {
					t.Error("invalid metadata part")
				}
			} else if h.Filename != "keywords.txt" || string(b) != "one\ntwo" {
				t.Error("invalid keyword file")
			}
		}
		_, _ = io.WriteString(w, `{"id":"dict"}`)
	})
	input := DictionaryUpload{Metadata: parity.DictionaryRequest{Category: "Confidential", Name: "test", OriginalFileName: "keywords.txt", RegionName: "us"}, File: []byte("one\ntwo")}
	if _, err := c.DLP.Dictionaries.Create(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	mode = "replace"
	if value, err := c.DLP.Dictionaries.Replace(context.Background(), "dict", input); err != nil || value != nil {
		t.Fatalf("204=%v %v", value, err)
	}
	mode = "missing"
	_, err := c.DLP.Dictionaries.Get(context.Background(), "dict", DictionaryGetOptions{})
	var sdk *aisec.AISecSDKError
	if !errors.As(err, &sdk) || sdk.StatusCode != 404 || !errors.Is(err, aisec.ErrNotFound) || sdk.Message == "confidential keyword" {
		t.Fatalf("status=%v", err)
	}
}
func TestDLPExplicitNullUsesMergePatch(t *testing.T) {
	c := runtimeParityClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PATCH" || r.Header.Get("Content-Type") != "application/merge-patch+json" {
			t.Error("wrong patch transport")
		}
		var fields map[string]json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&fields)
		if string(fields["description"]) != "null" {
			t.Error("explicit null lost")
		}
		_, _ = io.WriteString(w, `{}`)
	})
	var body parity.DataPatternPatchRequest
	if err := json.Unmarshal([]byte(`{"name":"test","type":"custom","detection_config":{"technique":"regex"},"description":null}`), &body); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DLP.DataPatterns.Patch(context.Background(), "pattern", body); err != nil {
		t.Fatal(err)
	}
}
func TestDashboardParameterIdentityAndZeroSubrequest(t *testing.T) {
	p, err := dashboardTransactionParams(DashboardTransactionQuery{SessionID: "s", AppID: "a", AppName: "name", ScanID: "scan", ScanSubReqID: 0})
	if err != nil || p["app_id"] != "a" || p["app_name"] != "name" || p["scan_sub_req_id"] != "0" {
		t.Fatalf("transaction=%v %v", p, err)
	}
	app, err := dashboardAppParams(DashboardAppQuery{AppID: "a", AppName: "name"})
	if err != nil || app["appid"] != "a" || app["appname"] != "name" || app["time_interval"] != "30" {
		t.Fatalf("app=%v %v", app, err)
	}
	if _, err = dashboardOverviewParams(DashboardOverviewQuery{DashboardTimeRangeQuery: DashboardTimeRangeQuery{TimeInterval: 2, TimeUnit: "hour"}}); err == nil {
		t.Fatal("accepted unsupported window")
	}
}
func TestStandaloneOAuthCacheAndRefreshCallback(t *testing.T) {
	var tokens, callbacks atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokens.Add(1)
		_, _ = io.WriteString(w, `{"access_token":"token","expires_in":3600}`)
	}))
	defer server.Close()
	c, err := NewOAuthClient(OAuthClientOptions{ClientID: "id", ClientSecret: "secret", TsgID: "123", TokenEndpoint: server.URL, OnTokenRefresh: func(info TokenInfo) {
		if !info.HasToken || !info.IsValid {
			t.Error("bad callback snapshot")
		}
		callbacks.Add(1)
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsTokenExpired() {
		t.Fatal("empty cache not expired")
	}
	for i := 0; i < 2; i++ {
		if _, err = c.GetToken(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	c.ClearToken()
	if _, err = c.GetToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	if tokens.Load() != 2 || callbacks.Load() != 2 || !c.GetTokenInfo().IsValid {
		t.Fatal("cache/refresh parity failed")
	}
}
func TestContentFromJSONFileValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "content.json")
	if err := os.WriteFile(path, []byte(`{"prompt":"hello","code_response":"print(1)"}`), 0600); err != nil {
		t.Fatal(err)
	}
	content, err := ContentFromJSONFile(path)
	if err != nil || content.Prompt() != "hello" || content.CodeResponse() != "print(1)" {
		t.Fatalf("content=%v %v", content, err)
	}
}

func TestRuntimeListAllFullPageWithoutNextOffsetAdvances(t *testing.T) {
	calls := 0
	c := runtimeParityClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.URL.Query().Get("offset") {
		case "0":
			_, _ = io.WriteString(w, `{"ai_profiles":[{"profile_name":"a"},{"profile_name":"b"}]}`)
		case "2":
			_, _ = io.WriteString(w, `{"ai_profiles":[{"profile_name":"c"}]}`)
		default:
			t.Errorf("unexpected offset %s", r.URL)
		}
	})
	items, err := c.Profiles.ListAll(context.Background(), ProfileListOpts{}, aisec.CollectOptions{Limit: 2})
	if err != nil || len(items) != 3 || calls != 2 {
		t.Fatalf("items=%v calls=%d err=%v", items, calls, err)
	}
}
func TestContentFileRejectsUnknownAndTrailingFields(t *testing.T) {
	for _, body := range []string{`{"prompt":"hello","codePrompt":"print(1)"}`, `{"prompt":"hello"} {}`} {
		path := filepath.Join(t.TempDir(), "content.json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ContentFromJSONFile(path); err == nil {
			t.Fatal("content was silently dropped")
		}
	}
}

func TestDashboardUsesIndependentEndpointAndSharedOAuth(t *testing.T) {
	data, err := os.ReadFile("testdata/parity-dashboard.json")
	if err != nil {
		t.Fatal(err)
	}
	var tokenCalls atomic.Int32
	token := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCalls.Add(1)
		_, _ = io.WriteString(w, `{"access_token":"shared-token","expires_in":3600}`)
	}))
	defer token.Close()
	dashboard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer shared-token" || r.Header.Get("x-tsg-id") != "123" {
			t.Error("dashboard authentication mismatch")
		}
		q := r.URL.Query()
		switch r.URL.Path {
		case "/v1/mgmt/dashboard/v2/apps/application":
			if q.Get("appid") != "app" || q.Get("appname") != "name" || q.Has("app_id") {
				t.Error(q)
			}
			_, _ = w.Write(data)
		case "/v1/mgmt/dashboard/v2/sessions/sessiontransaction":
			if q.Get("app_id") != "app" || q.Get("app_name") != "name" || q.Get("scan_sub_req_id") != "0" || q.Has("appid") {
				t.Error(q)
			}
			_, _ = io.WriteString(w, `{"future_field":true}`)
		default:
			t.Error(r.URL)
		}
	}))
	defer dashboard.Close()
	management := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("dashboard reached management base") }))
	defer management.Close()
	c, err := NewClient(Opts{ClientID: "id", ClientSecret: "secret", TsgID: "123", APIEndpoint: management.URL, DashboardEndpoint: dashboard.URL, TokenEndpoint: token.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Dashboard.Application(context.Background(), DashboardAppQuery{AppID: "app", AppName: "name"}); err != nil {
		t.Fatal(err)
	}
	got, err := c.Dashboard.SessionTransactionRaw(context.Background(), DashboardTransactionQuery{AppID: "app", AppName: "name", SessionID: "session", ScanID: "scan"})
	if err != nil || got == nil || string(*got) != `{"future_field":true}` {
		t.Fatalf("raw=%v err=%v", got, err)
	}
	if tokenCalls.Load() != 1 {
		t.Fatal("dashboard did not share cached OAuth")
	}
}
