package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/cdot65/prisma-airs-go/aisec"
)

func contractError[T any](_ T, err error) error             { return err }
func contractResult[T any](value T, err error) (any, error) { return value, err }

func TestRuntimeScanner_AllPinnedOperations(t *testing.T) {
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	b, err := os.ReadFile("../../specs/contracts/runtime-data.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const id = "550e8400-e29b-41d4-a716-446655440000"
	content, err := NewContent(ContentOpts{Prompt: "test"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		method, path, response string
		call                   func(*Scanner) error
	}{
		{"POST", "/v1/scan/sync/request", `{"scan_id":"scan","report_id":"report","action":"allow","category":"benign"}`, func(s *Scanner) error { return contractError(s.SyncScan(ctx, AiProfile{ProfileName: "test"}, content)) }},
		{"POST", "/v1/scan/async/request", `{"scan_id":"scan","received":"accepted"}`, func(s *Scanner) error {
			return contractError(s.AsyncScan(ctx, []AsyncScanObject{{ReqID: 1, ScanReq: ScanRequest{AiProfile: AiProfile{ProfileName: "test"}, Contents: []ContentInner{{Prompt: "test"}}}}}))
		}},
		{"GET", "/v1/scan/results", `[]`, func(s *Scanner) error { return contractError(s.QueryByScanIDs(ctx, []string{id})) }},
		{"GET", "/v1/scan/reports", `[]`, func(s *Scanner) error { return contractError(s.QueryByReportIDs(ctx, []string{id})) }},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if _, ok := doc.Paths[tc.path][strings.ToLower(tc.method)]; !ok {
				t.Fatal("operation missing from pinned spec")
			}
			seen[tc.method+" "+tc.path] = true
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tc.method || r.URL.Path != tc.path {
					t.Errorf("unexpected %s %s", r.Method, r.URL)
				}
				if r.Header.Get("x-pan-token") == "" || (r.Method == "POST" && r.Header.Get("x-payload-hash") == "") {
					t.Error("scan authentication headers missing")
				}
				_, _ = w.Write([]byte(tc.response))
			}))
			t.Cleanup(server.Close)
			s := NewScanner(aisec.NewConfig(aisec.WithAPIKey("test-key"), aisec.WithEndpoint(server.URL)))
			if err := tc.call(s); err != nil {
				t.Fatal(err)
			}
		})
	}
	for path, item := range doc.Paths {
		for method := range item {
			switch method {
			case "get", "post":
				if !seen[strings.ToUpper(method)+" "+path] {
					t.Errorf("uncovered scan operation %s %s", method, path)
				}
			}
		}
	}
}

// Contracts come from the pinned OpenAPI document. TSG-qualified listing paths
// remain supported live aliases (both forms returned 200 on 2026-10-01).
func TestRuntimeManagement_AllPinnedOperations(t *testing.T) {
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	b, err := os.ReadFile("../../specs/contracts/runtime-mgmt.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	inactive := false
	revision := int32(0)
	topicRevision := int64(0)
	var fixtures map[string]managementFixture
	raw, err := os.ReadFile("testdata/management_contracts.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		method, template, path string
		call                   func(*Client) (any, error)
	}{
		{"POST", "/v1/mgmt/apikey", "/v1/mgmt/apikey", func(c *Client) (any, error) {
			return contractResult(c.ApiKeys.Create(ctx, CreateApiKeyRequest{ApiKeyName: "test", AuthCode: "auth", CustApp: "app", CreatedBy: "tester", RotationTimeInterval: 90, RotationTimeUnit: "day", CustEnv: "dev", CustCloudProvider: "aws", Revoked: false}))
		}},
		{"GET", "/v1/mgmt/apikeys", "/v1/mgmt/apikeys/tsg/123", func(c *Client) (any, error) { return contractResult(c.ApiKeys.List(ctx, ListOpts{Limit: 5})) }},
		{"DELETE", "/v1/mgmt/apikey/delete/{api_key_name}", "/v1/mgmt/apikey/delete/id%2Fpart", func(c *Client) (any, error) { return contractResult(c.ApiKeys.Delete(ctx, "id/part", "tester")) }},
		{"POST", "/v1/mgmt/apikey/regenerate/{api_key_id}", "/v1/mgmt/apikey/regenerate/id%2Fpart", func(c *Client) (any, error) {
			return contractResult(c.ApiKeys.Regenerate(ctx, "id/part", RegenerateKeyRequest{UpdatedBy: "tester", RotationTimeInterval: 90, RotationTimeUnit: "day"}))
		}},
		{"POST", "/v1/mgmt/profile", "/v1/mgmt/profile", func(c *Client) (any, error) {
			return contractResult(c.Profiles.Create(ctx, CreateProfileRequest{ProfileName: "test", Policy: &ProfilePolicy{}, Revision: &revision, Active: &inactive, CreatedBy: "tester"}))
		}},
		{"DELETE", "/v1/mgmt/profile/{profile_id}", "/v1/mgmt/profile/id%2Fpart", func(c *Client) (any, error) { return contractResult(c.Profiles.Delete(ctx, "id/part")) }},
		{"PUT", "/v1/mgmt/profile/uuid/{profile_id}", "/v1/mgmt/profile/uuid/id%2Fpart", func(c *Client) (any, error) {
			return contractResult(c.Profiles.Update(ctx, "id/part", UpdateProfileRequest{ProfileName: "updated", Policy: &ProfilePolicy{}, Revision: &revision, Active: &inactive, UpdatedBy: "tester"}))
		}},
		{"GET", "/v1/mgmt/profiles", "/v1/mgmt/profiles/tsg/123", func(c *Client) (any, error) { return contractResult(c.Profiles.List(ctx, ListOpts{Limit: 5})) }},
		{"DELETE", "/v1/mgmt/profile/{profile_id}/force", "/v1/mgmt/profile/id%2Fpart/force", func(c *Client) (any, error) { return contractResult(c.Profiles.ForceDelete(ctx, "id/part", "tester")) }},
		{"GET", "/v1/mgmt/dlpprofiles", "/v1/mgmt/dlpprofiles", func(c *Client) (any, error) { return contractResult(c.DlpProfiles.List(ctx, ListOpts{})) }},
		{"GET", "/v1/mgmt/deploymentprofiles", "/v1/mgmt/deploymentprofiles", func(c *Client) (any, error) { return contractResult(c.DeploymentProfiles.List(ctx, ListOpts{})) }},
		{"GET", "/v1/mgmt/customerapp", "/v1/mgmt/customerapp", func(c *Client) (any, error) { return contractResult(c.CustomerApps.Get(ctx, "test")) }},
		{"DELETE", "/v1/mgmt/customerapp", "/v1/mgmt/customerapp", func(c *Client) (any, error) { return contractResult(c.CustomerApps.Delete(ctx, "test", "tester")) }},
		{"PUT", "/v1/mgmt/customerapp", "/v1/mgmt/customerapp", func(c *Client) (any, error) {
			return contractResult(c.CustomerApps.Update(ctx, "test", UpdateAppRequest{AppName: "updated", ModelName: "model", CloudProvider: "aws", Environment: "dev", CustomerAppID: "test", TsgID: "123", Status: "active", CreatedBy: "creator", UpdatedBy: "tester", AiAgentFramework: "framework"}))
		}},
		{"GET", "/v1/mgmt/customerapps", "/v1/mgmt/customerapps", func(c *Client) (any, error) { return contractResult(c.CustomerApps.List(ctx, ListOpts{Limit: 5})) }},
		{"POST", "/v1/mgmt/topic", "/v1/mgmt/topic", func(c *Client) (any, error) {
			return contractResult(c.Topics.Create(ctx, CreateTopicRequest{TopicName: "test", Description: "description", Examples: []string{"example"}, Revision: &topicRevision, Active: &inactive, CreatedBy: "tester"}))
		}},
		{"DELETE", "/v1/mgmt/topic/{topic_id}", "/v1/mgmt/topic/id%2Fpart", func(c *Client) (any, error) { return contractResult(c.Topics.Delete(ctx, "id/part")) }},
		{"DELETE", "/v1/mgmt/topic/{topic_id}/force", "/v1/mgmt/topic/id%2Fpart/force", func(c *Client) (any, error) { return contractResult(c.Topics.ForceDelete(ctx, "id/part", "tester")) }},
		{"PUT", "/v1/mgmt/topic/uuid/{topic_id}", "/v1/mgmt/topic/uuid/id%2Fpart", func(c *Client) (any, error) {
			return contractResult(c.Topics.Update(ctx, "id/part", UpdateTopicRequest{TopicName: "updated", Description: "description", Examples: []string{"example"}, Revision: &topicRevision, Active: &inactive, UpdatedBy: "tester"}))
		}},
		{"GET", "/v1/mgmt/topics", "/v1/mgmt/topics/tsg/123", func(c *Client) (any, error) { return contractResult(c.Topics.List(ctx, ListOpts{Limit: 5})) }},
		{"POST", "/v1/mgmt/oauth/client_credential/accesstoken", "/v1/mgmt/oauth/client_credential/accesstoken", func(c *Client) (any, error) {
			return contractResult(c.OAuth.GetToken(ctx, OAuthTokenRequest{ClientID: "client", CustomerApp: "app"}))
		}},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.template, func(t *testing.T) {
			if _, ok := doc.Paths[tc.template][strings.ToLower(tc.method)]; !ok {
				t.Fatalf("operation missing from pinned spec: %s %s", tc.method, tc.template)
			}
			seen[tc.method+" "+tc.template] = true
			fixture, ok := fixtures[tc.method+" "+tc.template]
			if !ok {
				t.Fatal("missing independently specified payload fixture")
			}
			for _, mode := range []string{"success", "not_found", "malformed"} {
				t.Run(mode, func(t *testing.T) {
					token, api := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
						if r.Method != tc.method || r.URL.EscapedPath() != tc.path {
							t.Errorf("got %s %s; want %s %s", r.Method, r.URL, tc.method, tc.path)
						}
						wantQuery, err := url.ParseQuery(fixture.Query)
						if err != nil {
							t.Error(err)
						}
						if !reflect.DeepEqual(r.URL.Query(), wantQuery) {
							t.Errorf("query=%v; want %v", r.URL.Query(), wantQuery)
						}
						body, err := io.ReadAll(r.Body)
						if err != nil {
							t.Error(err)
						}
						if len(fixture.Request) == 0 {
							if len(body) != 0 {
								t.Errorf("unexpected body %s", body)
							}
						} else {
							assertContractJSON(t, body, fixture.Request)
						}
						switch mode {
						case "not_found":
							w.WriteHeader(http.StatusNotFound)
							_, _ = w.Write([]byte(`{"message":"missing"}`))
						case "malformed":
							_, _ = w.Write([]byte(`{"broken":`))
						default:
							_, _ = w.Write(fixture.Response)
						}
					})
					t.Cleanup(token.Close)
					t.Cleanup(api.Close)
					result, err := tc.call(newTestClient(t, token.URL, api.URL))
					if mode == "success" {
						if err != nil {
							t.Fatal(err)
						}
						encoded, err := json.Marshal(result)
						if err != nil {
							t.Fatal(err)
						}
						var fields map[string]json.RawMessage
						if err := json.Unmarshal(encoded, &fields); err != nil {
							t.Fatal(err)
						}
						for key, want := range fixture.Fields {
							assertContractJSON(t, fields[key], want)
						}
						return
					}
					if result != nil && !reflect.ValueOf(result).IsNil() {
						t.Fatalf("partial result on failure: %#v", result)
					}
					var sdkErr *aisec.AISecSDKError
					if !errors.As(err, &sdkErr) {
						t.Fatalf("error type=%T (%v)", err, err)
					}
					if mode == "not_found" {
						if sdkErr.StatusCode != 404 || !errors.Is(err, aisec.ErrNotFound) {
							t.Fatalf("HTTP error=%+v", sdkErr)
						}
					} else {
						var syntax *json.SyntaxError
						if sdkErr.StatusCode != 200 || !errors.As(err, &syntax) || errors.Is(err, aisec.ErrNotFound) {
							t.Fatalf("decode error=%+v", sdkErr)
						}
					}
				})
			}
		})
	}
	for path, item := range doc.Paths {
		for method := range item {
			switch method {
			case "get", "post", "put", "patch", "delete":
				if !seen[strings.ToUpper(method)+" "+path] {
					t.Errorf("uncovered operation %s %s", method, path)
				}
			}
		}
	}
}

// Payload literals are curated from the pinned schema and observed delete shapes.
type managementFixture struct {
	Query    string                     `json:"query"`
	Request  json.RawMessage            `json:"request"`
	Response json.RawMessage            `json:"response"`
	Fields   map[string]json.RawMessage `json:"fields"`
}

func assertContractJSON(t *testing.T, got, want []byte) {
	t.Helper()
	var actual, expected any
	if err := json.Unmarshal(got, &actual); err != nil {
		t.Fatalf("invalid actual JSON %q: %v", got, err)
	}
	if err := json.Unmarshal(want, &expected); err != nil {
		t.Fatalf("invalid expected JSON %q: %v", want, err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("JSON=%s; want %s", got, want)
	}
}
