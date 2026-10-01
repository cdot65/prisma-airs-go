package redteam

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/cdot65/prisma-airs-go/aisec"
)

func TestCSVUpload_ResponseExpectations(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		wantError  bool
	}{
		{"text", "OK", false}, {"empty", "", false},
		{"JSON", `{"message":"uploaded"}`, false},
		{"malformed", `{"message":`, true},
		{"wrong type", `{"message":"partial","status":"bad"}`, true},
		{"null", `null`, true},
		{"HTML", `<html>Proxy error</html>`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token, api := newTestServers(t, func(w http.ResponseWriter, _ *http.Request) {
				// Even the text success may be mislabeled as JSON upstream.
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			})
			defer token.Close()
			defer api.Close()
			client := newTestClient(t, token.URL, api.URL, api.URL)
			result, err := client.CustomAttacks.UploadPromptsCsv(context.Background(), "set", strings.NewReader("prompt\nhello"), "p.csv")
			if (err != nil) != tc.wantError {
				t.Fatalf("result=%+v error=%v; wantError=%v", result, err, tc.wantError)
			}
			if tc.wantError {
				var sdkErr *aisec.AISecSDKError
				if result != nil || !errors.As(err, &sdkErr) {
					t.Fatalf("want nil result and SDK error; result=%+v error=%v", result, err)
				}
			} else if result == nil {
				t.Fatal("missing success result")
			}
			if tc.name == "JSON" && result.Message != "uploaded" {
				t.Errorf("message=%q", result.Message)
			}
		})
	}
}

func TestRedTeam_DeleteNoContentAndJSON(t *testing.T) {
	for _, method := range []string{"target", "prompt"} {
		for _, tc := range []struct {
			name, body string
			status     int
			wantError  bool
		}{
			{"no content", "", 204, false}, {"JSON", `{"message":"deleted"}`, 200, false},
			{"empty success", "", 200, false}, {"text", "OK", 200, true},
			{"malformed", `{"message":`, 200, true}, {"null", "null", 200, true},
		} {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				token, api := newTestServers(t, func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(tc.status)
					_, _ = w.Write([]byte(tc.body))
				})
				defer token.Close()
				defer api.Close()
				client := newTestClient(t, token.URL, api.URL, api.URL)
				var result *BaseResponse
				var err error
				if method == "target" {
					result, err = client.Targets.Delete(context.Background(), "t")
				} else {
					result, err = client.CustomAttacks.DeletePrompt(context.Background(), "s", "p")
				}
				if (err != nil) != tc.wantError {
					t.Fatalf("result=%+v error=%v; wantError=%v", result, err, tc.wantError)
				}
				if tc.wantError && result != nil {
					t.Fatalf("partial result=%+v", result)
				}
				if !tc.wantError && result == nil {
					t.Fatal("missing success result")
				}
				if tc.name == "JSON" && result.Message != "deleted" {
					t.Errorf("message=%q", result.Message)
				}
			})
		}
	}
}

func TestCategories_RequireJSONArray(t *testing.T) {
	for _, body := range []string{"", `null`, `{}`, `[`, `[]`} {
		t.Run(body, func(t *testing.T) {
			token, api := newTestServers(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) })
			defer token.Close()
			defer api.Close()
			result, err := newTestClient(t, token.URL, api.URL, api.URL).Scans.GetCategories(context.Background())
			if body == `[]` {
				if err != nil || result == nil {
					t.Fatalf("result=%+v error=%v", result, err)
				}
			} else if err == nil {
				t.Fatalf("body=%q silently succeeded: %+v", body, result)
			}
		})
	}
}
