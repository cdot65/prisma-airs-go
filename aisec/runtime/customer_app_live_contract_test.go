package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/cdot65/prisma-airs-go/aisec"
)

func TestCustomerApps_UpdateCarriesExistingDeploymentAuthCode(t *testing.T) {
	token, api := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(CustomerAppListResponse{Items: []CustomerApp{{CustomerAppID: "owned-id", AppName: "owned", ApiKeysDPInfo: []APIKeyDPInfo{{AuthCode: "fixture-code"}}}}})
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["auth_code"] != "fixture-code" {
			t.Error("live customer-app update requires its deployment auth code")
		}
		_ = json.NewEncoder(w).Encode(CustomerApp{CustomerAppID: "owned-id", AppName: "owned", ModelName: "updated"})
	})
	defer token.Close()
	defer api.Close()
	client := newTestClient(t, token.URL, api.URL)
	if _, err := client.CustomerApps.Update(context.Background(), "owned-id", UpdateAppRequest{AppName: "owned", ModelName: "updated"}); err != nil {
		t.Fatal(err)
	}
}

func TestCustomerApps_UpdateAuthCodeLookupFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		apps   []CustomerApp
		status int
		want   aisec.ErrorType
	}{
		{"missing app", nil, 200, aisec.ClientSideError},
		{"missing deployment", []CustomerApp{{CustomerAppID: "owned-id"}}, 200, aisec.MissingVariableError},
		{"ambiguous deployment", []CustomerApp{{CustomerAppID: "owned-id", ApiKeysDPInfo: []APIKeyDPInfo{{AuthCode: "secret-a"}, {AuthCode: "secret-b"}}}}, 200, aisec.UserRequestPayloadError},
		{"list failure", nil, 500, aisec.ServerSideError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token, api := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Error("lookup failure must prevent PUT")
				}
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(CustomerAppListResponse{Items: tc.apps})
			})
			defer token.Close()
			defer api.Close()
			client := newTestClient(t, token.URL, api.URL)
			_, err := client.CustomerApps.Update(context.Background(), "owned-id", UpdateAppRequest{AppName: "owned"})
			var sdk *aisec.AISecSDKError
			if !errors.As(err, &sdk) || sdk.ErrorType != tc.want {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.name == "missing app" && !errors.Is(err, aisec.ErrNotFound) {
				t.Error("missing app must have the typed not-found contract")
			}
			if strings.Contains(err.Error(), "secret-a") || strings.Contains(err.Error(), "secret-b") {
				t.Error("lookup diagnostic leaked auth codes")
			}
		})
	}
}

func TestCustomerApps_UpdateAuthCodeLookupUsesCursor(t *testing.T) {
	token, api := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			page := CustomerAppListResponse{Items: []CustomerApp{{CustomerAppID: "other"}}, NextOffset: 7}
			if r.URL.Query().Get("offset") == "7" {
				page = CustomerAppListResponse{Items: []CustomerApp{{CustomerAppID: "owned-id", ApiKeysDPInfo: []APIKeyDPInfo{{AuthCode: "fixture-code"}, {AuthCode: "fixture-code"}}}}}
			}
			_ = json.NewEncoder(w).Encode(page)
			return
		}
		_ = json.NewEncoder(w).Encode(CustomerApp{CustomerAppID: "owned-id"})
	})
	defer token.Close()
	defer api.Close()
	client := newTestClient(t, token.URL, api.URL)
	if _, err := client.CustomerApps.Update(context.Background(), "owned-id", UpdateAppRequest{AppName: "owned"}); err != nil {
		t.Fatal(err)
	}
}
