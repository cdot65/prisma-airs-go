package redteam

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/cdot65/prisma-airs-go/aisec"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetScanMetadataRoutingAnd422Fallback(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusUnprocessableEntity, http.StatusBadRequest} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			dataCalls, managementCalls := 0, 0
			token, data := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
				dataCalls++
				if r.Method != "GET" || r.URL.Path != "/v1/scan/scan-metadata" || r.URL.RawQuery != "" {
					t.Error(r.URL)
				}
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(map[string]any{"direct": true})
			})
			defer token.Close()
			defer data.Close()
			management := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				managementCalls++
				if r.Method != "GET" || r.URL.Path != "/v1/template/target-metadata" || r.Header.Get("Authorization") != "Bearer test-token" {
					t.Error(r.URL)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"fallback": true})
			}))
			defer management.Close()
			c := newTestClient(t, token.URL, data.URL, management.URL)
			result, err := c.GetScanMetadata(context.Background())
			switch status {
			case http.StatusOK:
				if err != nil || result["direct"] != true || managementCalls != 0 {
					t.Fatalf("result=%v err=%v fallback=%d", result, err, managementCalls)
				}
			case http.StatusUnprocessableEntity:
				if err != nil || result["fallback"] != true || managementCalls != 1 {
					t.Fatalf("result=%v err=%v fallback=%d", result, err, managementCalls)
				}
			default:
				var sdk *aisec.AISecSDKError
				if !errors.As(err, &sdk) || sdk.StatusCode != status || managementCalls != 0 {
					t.Fatalf("err=%v fallback=%d", err, managementCalls)
				}
			}
			if dataCalls != 1 {
				t.Fatal(dataCalls)
			}
		})
	}
}
