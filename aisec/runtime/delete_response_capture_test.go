//go:build integration

package runtime

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/cdot65/prisma-airs-go/aisec/internal"
)

// This test uses only mock servers: verify that integration response capture
// preserves the real client behavior before relying on it for tenant evidence.
func TestDeleteResponseCapture_PreservesDecoding(t *testing.T) {
	for _, body := range []string{"deleted", `"deleted"`, `{"message":"deleted"}`} {
		t.Run(body, func(t *testing.T) {
			token, api := newTestMgmtServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			})
			defer token.Close()
			defer api.Close()
			var log string
			client, err := NewClient(Opts{
				ClientID: "id", ClientSecret: "secret", TsgID: "1", TokenEndpoint: token.URL, APIEndpoint: api.URL,
				HTTPClient: &http.Client{Transport: deleteResponseTransport{
					base: internal.DefaultHTTPClient().Transport,
					logf: func(format string, args ...any) { log = fmt.Sprintf(format, args...) },
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.Profiles.ForceDelete(context.Background(), "p", "me")
			if err != nil || result == nil {
				t.Fatalf("result=%+v error=%v", result, err)
			}
			if strings.HasPrefix(body, `"`) || strings.HasPrefix(body, `{`) {
				if result.Message != "deleted" {
					t.Errorf("message=%q", result.Message)
				}
			}
			if !strings.Contains(log, `Content-Type="application/json"`) || !strings.Contains(log, fmt.Sprintf("body_prefix=%q", body)) {
				t.Errorf("response capture=%q", log)
			}
		})
	}
}
