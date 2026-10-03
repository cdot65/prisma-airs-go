package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/cdot65/prisma-airs-go/aisec"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unicode"
)

func goMethodName(value string) string {
	parts := regexp.MustCompile(`([a-z0-9])([A-Z])`).ReplaceAllString(value, "${1}_${2}")
	out := ""
	for _, part := range strings.Split(parts, "_") {
		if part == "id" {
			out += "ID"
		} else if part == "url" {
			out += "URL"
		} else if len(part) > 0 {
			out += string(unicode.ToUpper(rune(part[0]))) + part[1:]
		}
	}
	return out
}
func TestTypeScriptRuntimeWireContracts(t *testing.T) {
	data, err := os.ReadFile("testdata/typescript-runtime.json")
	if err != nil {
		t.Fatal(err)
	}
	var source struct {
		Cases []map[string]json.RawMessage `json:"cases"`
	}
	if err := json.Unmarshal(data, &source); err != nil {
		t.Fatal(err)
	}
	for _, row := range source.Cases {
		var call struct {
			Member     string                        `json:"member"`
			Parameters []struct{ Name, Type string } `json:"parameters"`
		}
		_ = json.Unmarshal(row["call"], &call)
		t.Run(call.Member, func(t *testing.T) {
			var verb, path string
			_ = json.Unmarshal(row["method"], &verb)
			_ = json.Unmarshal(row["path"], &path)
			var query map[string][]string
			_ = json.Unmarshal(row["queryWire"], &query)
			var status int
			_ = json.Unmarshal(row["responseStatus"], &status)
			var isText bool
			_ = json.Unmarshal(row["responseIsText"], &isText)
			body := append(json.RawMessage(nil), row["body"]...)
			// The JS fixture's int64-minimum seed is rounded beyond Go int64. Use a representable seed;
			// this changes only synthetic test input, not the pinned fixture or API payload conversion.
			if len(body) > 0 {
				var b map[string]json.RawMessage
				if json.Unmarshal(body, &b) == nil {
					if _, ok := b["seed"]; ok {
						b["seed"] = json.RawMessage("0")
						body, _ = json.Marshal(b)
					}
				}
			}
			resourceID := "resource/id"
			if call.Member == "updateFeedback" {
				resourceID = "550e8400-e29b-41d4-a716-446655440000"
			}
			expectedPath := regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(path, url.PathEscape(resourceID))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != verb || r.URL.EscapedPath() != expectedPath {
					t.Errorf("route=%s %s want=%s %s", r.Method, r.URL.EscapedPath(), verb, expectedPath)
				}
				if r.Header.Get("x-portkey-api-key") != "runtime-key" || r.Header.Get("Authorization") != "" || r.Header.Get("X-Tsg-Id") != "" {
					t.Error("runtime leaked SCM auth or lost runtime key")
				}
				if !reflect.DeepEqual(r.URL.Query(), url.Values(query)) {
					t.Errorf("query=%v want=%v", r.URL.Query(), query)
				}
				if len(body) > 0 {
					var got, want any
					_ = json.NewDecoder(r.Body).Decode(&got)
					_ = json.Unmarshal(body, &want)
					if !reflect.DeepEqual(got, want) {
						t.Errorf("body differs from retained TypeScript fixture")
					}
				}
				w.WriteHeader(status)
				if isText {
					var text string
					_ = json.Unmarshal(row["responseBody"], &text)
					_, _ = w.Write([]byte(text))
				} else {
					reply := regexp.MustCompile(`("seed"\s*:\s*)-9223372036854776000`).ReplaceAll(row["responseBody"], []byte("${1}0"))
					_, _ = w.Write(reply)
				}
			}))
			defer server.Close()
			c, err := NewInferenceClient(InferenceOpts{Endpoint: server.URL, APIKey: "runtime-key"})
			if err != nil {
				t.Fatal(err)
			}
			method := reflect.ValueOf(c).MethodByName(goMethodName(call.Member))
			if !method.IsValid() {
				t.Fatalf("missing TypeScript method: %s", call.Member)
			}
			args := []reflect.Value{reflect.ValueOf(context.Background())}
			for _, p := range call.Parameters {
				if p.Name == "options" {
					args = append(args, reflect.ValueOf(InferenceRequestOptions{}))
					continue
				}
				typ := method.Type().In(len(args))
				if p.Type == "string" {
					args = append(args, reflect.ValueOf(resourceID))
					continue
				}
				value := reflect.New(typ)
				payload := body
				if p.Name == "opts" {
					payload = row["query"]
				}
				if len(payload) == 0 {
					payload = []byte(`{}`)
				}
				if err := json.Unmarshal(payload, value.Interface()); err != nil {
					t.Fatalf("fixture input: %v", err)
				}
				args = append(args, value.Elem())
			}
			outputs := method.Call(args)
			last := outputs[len(outputs)-1]
			if !last.IsNil() {
				var sdkErr *aisec.AISecSDKError
				if !errors.As(last.Interface().(error), &sdkErr) {
					t.Fatal(last.Interface())
				}
				t.Fatalf("contract call failed: %v cause=%v", last.Interface(), sdkErr.Err)
			}
		})
	}
}
