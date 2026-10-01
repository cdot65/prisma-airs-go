package gateway

import (
	"encoding/json"
	"errors"
	"github.com/cdot65/prisma-airs-go/aisec"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
)

type contractFixture struct {
	Request, Response, Options json.RawMessage
	Query                      string
	Status                     int
}
type contractCase struct {
	name, plane, method, template, path string
	call                                func(*testing.T, *Client, contractFixture) (any, error)
}

func contractResult[T any](v T, err error) (any, error) { return v, err }
func contractValue[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}
func jsonEqual(t *testing.T, got, want []byte) {
	t.Helper()
	var a, b any
	if err := json.Unmarshal(got, &a); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if err := json.Unmarshal(want, &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("JSON=%s; want %s", got, want)
	}
}
func runContracts(t *testing.T, cases []contractCase, fixtures map[string]contractFixture) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, ok := fixtures[tc.name]
			if !ok {
				t.Fatal("fixture missing")
			}
			for _, mode := range []string{"success", "not_found", "malformed", "wrong_type"} {
				t.Run(mode, func(t *testing.T) {
					if mode == "wrong_type" && string(f.Response) == "null" {
						t.Skip("source defines no response schema")
					}
					token := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.Header.Get(aisec.HeaderTsgID) != "" {
							t.Error("tenant header leaked into token request")
						}
						_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
					}))
					t.Cleanup(token.Close)
					handler := func(plane string) http.HandlerFunc {
						return func(w http.ResponseWriter, r *http.Request) {
							if plane != tc.plane || r.Method != tc.method || r.URL.EscapedPath() != tc.path {
								t.Errorf("got %s %s %s;want %s %s %s", plane, r.Method, r.URL, tc.plane, tc.method, tc.path)
							}
							if r.Header.Get("Authorization") != "Bearer token" || r.Header.Get(aisec.HeaderTsgID) != "tenant" {
								t.Error("OAuth/TSG missing")
							}
							q, err := url.ParseQuery(f.Query)
							if err != nil {
								t.Fatal(err)
							}
							if !reflect.DeepEqual(q, r.URL.Query()) {
								t.Errorf("query=%v;want %v", r.URL.Query(), q)
							}
							body, err := io.ReadAll(r.Body)
							if err != nil {
								t.Fatal(err)
							}
							if len(f.Request) > 0 {
								jsonEqual(t, body, f.Request)
							} else if len(body) > 0 {
								t.Error("unexpected request body")
							}
							switch mode {
							case "not_found":
								w.WriteHeader(404)
								_, _ = w.Write([]byte(`{"message":"missing"}`))
							case "malformed":
								_, _ = w.Write([]byte(`{"broken":`))
							case "wrong_type":
								_, _ = w.Write([]byte(`"wrong type"`))
							default:
								w.WriteHeader(f.Status)
								if f.Status != 204 && string(f.Response) != "null" {
									_, _ = w.Write(f.Response)
								}
							}
						}
					}
					data := httptest.NewServer(handler("data"))
					t.Cleanup(data.Close)
					admin := httptest.NewServer(handler("admin"))
					t.Cleanup(admin.Close)
					c, err := NewClient(Opts{ClientID: "id", ClientSecret: "secret", TsgID: "tenant", TokenEndpoint: token.URL, DataEndpoint: data.URL, AdminEndpoint: admin.URL, HTTPClient: data.Client()})
					if err != nil {
						t.Fatal(err)
					}
					result, err := tc.call(t, c, f)
					if mode == "success" {
						if err != nil {
							t.Fatal(err)
						}
						if f.Status != 204 && string(f.Response) != "null" {
							b, err := json.Marshal(result)
							if err != nil {
								t.Fatal(err)
							}
							jsonEqual(t, b, f.Response)
						}
						return
					}
					if result != nil && !reflect.ValueOf(result).IsNil() {
						t.Fatalf("partial result=%v", result)
					}
					var sdkErr *aisec.AISecSDKError
					if !errors.As(err, &sdkErr) {
						t.Fatalf("error=%v", err)
					}
					if mode == "not_found" {
						if sdkErr.StatusCode != 404 || !errors.Is(err, aisec.ErrNotFound) {
							t.Errorf("error=%+v", sdkErr)
						}
					} else if mode == "malformed" {
						var cause *json.SyntaxError
						if sdkErr.StatusCode != 200 || (!errors.As(err, &cause) && errors.Unwrap(err) == nil) {
							t.Errorf("error=%+v", sdkErr)
						}
					} else {
						var cause *json.UnmarshalTypeError
						if sdkErr.StatusCode != 200 || (!errors.As(err, &cause) && errors.Unwrap(err) == nil) {
							t.Errorf("error=%+v", sdkErr)
						}
					}
				})
			}
		})
	}
}
func verifyScope(t *testing.T, cases []contractCase) {
	t.Helper()
	var scope []struct{ Path, Verb string }
	b, err := os.ReadFile("../../specs/gateway_scope.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &scope); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		seen[tc.method+" "+tc.template] = true
	}
	for _, op := range scope {
		if !seen[op.Verb+" "+op.Path] {
			t.Errorf("uncovered %s %s", op.Verb, op.Path)
		}
	}
	if len(scope) != 88 || len(seen) != 88 {
		t.Errorf("scope=%d cases=%d;want88", len(scope), len(seen))
	}
	var source struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	b, err = os.ReadFile("../../specs/contracts/gateway.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &source); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		if _, ok := source.Paths[tc.template][strings.ToLower(tc.method)]; !ok {
			t.Errorf("source operation absent: %s %s", tc.method, tc.template)
		}
	}
	selectedTags := []string{"Configs", "Guardrails", "Org Guardrails", "Providers", "Integrations", "MCP Integrations", "MCP Servers", "API Keys", "Usage Limit Policies", "Rate Limit Policies", "Secret References", "Deployments"}
	sourceCount := 0
	for path, item := range source.Paths {
		for method, raw := range item {
			switch method {
			case "get", "post", "put", "delete", "patch":
			default:
				continue
			}
			var op struct {
				Tags []string `json:"tags"`
			}
			if err := json.Unmarshal(raw, &op); err != nil {
				t.Fatal(err)
			}
			selected := false
			for _, tag := range op.Tags {
				for _, root := range selectedTags {
					if tag == root || strings.HasPrefix(tag, root+" >") {
						selected = true
					}
				}
			}
			if selected {
				sourceCount++
				if !seen[strings.ToUpper(method)+" "+path] {
					t.Errorf("selected source operation lacks public contract: %s %s", method, path)
				}
			}
		}
	}
	if sourceCount != 88 {
		t.Errorf("selected source operations=%d;want88", sourceCount)
	}

}
