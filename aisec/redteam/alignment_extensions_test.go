package redteam

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/redteam/schema"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
)

func extensionResult[T any](v T, err error) (any, error) { return v, err }
func extensionRequest[T any](t *testing.T, body []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

type extensionFixture struct {
	Query    string          `json:"query"`
	Request  json.RawMessage `json:"request"`
	Response json.RawMessage `json:"response"`
	Status   int             `json:"status"`
}

func extensionJSONEqual(t *testing.T, got, want []byte) {
	t.Helper()
	var a, b any
	if err := json.Unmarshal(got, &a); err != nil {
		t.Fatalf("JSON %s: %v", got, err)
	}
	if err := json.Unmarshal(want, &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("JSON=%s;want %s", got, want)
	}
}
func TestAdaptersAndNetworkBroker_Contracts(t *testing.T) {
	ctx := context.Background()
	inactive := false
	var fixtures map[string]extensionFixture
	b, err := os.ReadFile("testdata/extensions.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &fixtures); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, plane, method, path string
		call                      func(*Client, extensionFixture) (any, error)
	}{
		{"adapter_create", "mgmt", "POST", "/v1/adapters", func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Adapters.Create(ctx, extensionRequest[schema.CustomTargetAdapterCreateRequest](t, f.Request), AdapterWriteOpts{Validate: &inactive}))
		}},
		{"adapter_list", "mgmt", "GET", "/v1/adapters", func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Adapters.List(ctx, AdapterListOpts{ListOpts: ListOpts{Limit: 5, Skip: 2}, Search: "test", Status: "DRAFT", IncludeTargetCount: &inactive}))
		}},
		{"adapter_get", "mgmt", "GET", "/v1/adapters/id%2Fpart", func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Adapters.Get(ctx, "id/part"))
		}},
		{"adapter_update", "mgmt", "PUT", "/v1/adapters/id%2Fpart", func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Adapters.Update(ctx, "id/part", extensionRequest[schema.CustomTargetAdapterUpdateRequest](t, f.Request), AdapterWriteOpts{Validate: &inactive}))
		}},
		{"adapter_delete", "mgmt", "DELETE", "/v1/adapters/id%2Fpart", func(c *Client, f extensionFixture) (any, error) { return nil, c.Adapters.Delete(ctx, "id/part") }},
		{"adapter_config", "mgmt", "GET", "/v1/adapters/config", func(c *Client, f extensionFixture) (any, error) { return extensionResult(c.Adapters.GetConfig(ctx)) }},
		{"adapter_validate", "mgmt", "POST", "/v1/adapters/validate", func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Adapters.Validate(ctx, extensionRequest[schema.CustomTargetAdapterValidateRequest](t, f.Request)))
		}},
		{"broker_list", "broker", "GET", "/v1/channels", func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.NetworkBroker.List(ctx, ChannelListOpts{ListOpts: ListOpts{Limit: 5, Skip: 2}, Status: []schema.ChannelStatus{"OFFLINE", "ONLINE"}, Search: "test", IncludeAllIfEmpty: &inactive}))
		}},
		{"broker_create", "broker", "POST", "/v1/channels", func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.NetworkBroker.Create(ctx, extensionRequest[schema.CreateChannelRequest](t, f.Request)))
		}},
		{"broker_get", "broker", "GET", "/v1/channels/id%2Fpart", func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.NetworkBroker.Get(ctx, "id/part"))
		}},
		{"broker_update", "broker", "PATCH", "/v1/channels/id%2Fpart", func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.NetworkBroker.Update(ctx, "id/part", extensionRequest[schema.UpdateChannelRequest](t, f.Request)))
		}},
		{"broker_stats", "broker", "GET", "/v1/channels/stats", func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.NetworkBroker.GetStats(ctx))
		}},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := fixtures[tc.name]
			label := "redteam-mgmt"
			template := strings.ReplaceAll(tc.path, "id%2Fpart", "{adapter_uuid}")
			if tc.plane == "broker" {
				label = "redteam-broker"
				template = strings.ReplaceAll(tc.path, "id%2Fpart", "{channelId}")
			}
			raw, err := os.ReadFile("../../specs/contracts/" + label + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Paths map[string]map[string]json.RawMessage `json:"paths"`
			}
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			seen[label+" "+tc.method+" "+template] = true
			if _, ok := doc.Paths[template][strings.ToLower(tc.method)]; !ok {
				t.Fatalf("operation absent from pinned source: %s %s", tc.method, template)
			}
			for _, mode := range []string{"success", "not_found", "malformed"} {
				t.Run(mode, func(t *testing.T) {
					token := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
					}))
					t.Cleanup(token.Close)
					handler := func(plane string) http.HandlerFunc {
						return func(w http.ResponseWriter, r *http.Request) {
							if plane != tc.plane || r.Method != tc.method || r.URL.EscapedPath() != tc.path {
								t.Errorf("got %s %s %s;want %s %s %s", plane, r.Method, r.URL, tc.plane, tc.method, tc.path)
							}
							if r.Header.Get("Authorization") != "Bearer token" {
								t.Error("missing OAuth")
							}
							query, err := url.ParseQuery(f.Query)
							if err != nil {
								t.Error(err)
							}
							if !reflect.DeepEqual(query, r.URL.Query()) {
								t.Errorf("query=%v;want %v", r.URL.Query(), query)
							}
							body, err := io.ReadAll(r.Body)
							if err != nil {
								t.Error(err)
							}
							if len(f.Request) > 0 {
								extensionJSONEqual(t, body, f.Request)
							} else if len(body) > 0 {
								t.Errorf("unexpected body %s", body)
							}
							switch mode {
							case "not_found":
								w.WriteHeader(404)
								_, _ = w.Write([]byte(`{"message":"missing"}`))
							case "malformed":
								_, _ = w.Write([]byte(`{"broken":`))
							default:
								w.WriteHeader(f.Status)
								if f.Status != 204 {
									_, _ = w.Write(f.Response)
								}
							}
						}
					}
					data := httptest.NewServer(handler("data"))
					t.Cleanup(data.Close)
					mgmt := httptest.NewServer(handler("mgmt"))
					t.Cleanup(mgmt.Close)
					broker := httptest.NewServer(handler("broker"))
					t.Cleanup(broker.Close)
					c, err := NewClient(Opts{ClientID: "test", ClientSecret: "secret", TsgID: "123", TokenEndpoint: token.URL, DataEndpoint: data.URL, MgmtEndpoint: mgmt.URL, BrokerEndpoint: broker.URL})
					if err != nil {
						t.Fatal(err)
					}
					result, err := tc.call(c, f)
					if mode == "success" {
						if err != nil {
							t.Fatal(err)
						}
						if f.Status != 204 {
							b, err := json.Marshal(result)
							if err != nil {
								t.Fatal(err)
							}
							extensionJSONEqual(t, b, f.Response)
						}
						return
					}
					if result != nil && !reflect.ValueOf(result).IsNil() {
						t.Fatalf("partial result %v", result)
					}
					var sdkErr *aisec.AISecSDKError
					if !errors.As(err, &sdkErr) {
						t.Fatalf("error=%v", err)
					}
					if mode == "not_found" {
						if sdkErr.StatusCode != 404 || !errors.Is(err, aisec.ErrNotFound) {
							t.Fatalf("error=%+v", sdkErr)
						}
					} else {
						var syntax *json.SyntaxError
						if sdkErr.StatusCode != 200 || !errors.As(err, &syntax) {
							t.Fatalf("error=%+v", sdkErr)
						}
					}
				})
			}
		})
	}
	for _, label := range []string{"redteam-mgmt", "redteam-broker"} {
		raw, err := os.ReadFile("../../specs/contracts/" + label + ".json")
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Paths map[string]map[string]json.RawMessage `json:"paths"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		for path, item := range doc.Paths {
			if label == "redteam-mgmt" && !strings.HasPrefix(path, "/v1/adapters") {
				continue
			}
			for method := range item {
				switch method {
				case "get", "post", "put", "delete", "patch":
					if !seen[label+" "+strings.ToUpper(method)+" "+path] {
						t.Errorf("uncovered operation %s %s %s", label, method, path)
					}
				}
			}
		}
	}

}
