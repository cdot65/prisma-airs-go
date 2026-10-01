package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestNewClientTLSInjectionAndSharedToken(t *testing.T) {
	var tokens atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			tokens.Add(1)
			if r.Header.Get("X-Tsg-Id") != "" {
				t.Error("tenant header sent to token endpoint")
			}
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer token" || r.Header.Get("X-Tsg-Id") != "tenant" {
			t.Error("missing auth headers")
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	c, err := NewClient(Opts{ClientID: "id", ClientSecret: "secret", TsgID: "tenant", DataEndpoint: server.URL + "/data", AdminEndpoint: server.URL + "/admin", TokenEndpoint: server.URL + "/token", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Configs.Get(context.Background(), "id"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Integrations.Get(context.Background(), "id"); err != nil {
		t.Fatal(err)
	}
	if tokens.Load() != 1 {
		t.Fatal("planes did not share OAuth token cache")
	}
	if c.Configs == nil || c.Guardrails == nil || c.OrgGuardrails == nil || c.Providers == nil || c.Integrations == nil || c.MCPIntegrations == nil || c.MCPServers == nil || c.APIKeys == nil || c.UsageLimits == nil || c.RateLimits == nil || c.SecretReferences == nil || c.Deployments == nil {
		t.Fatal("missing sub-client")
	}
}
func TestNewClientCredentialAndEndpointPrecedence(t *testing.T) {
	t.Setenv("PANW_MGMT_CLIENT_ID", "fallback")
	t.Setenv("PANW_MGMT_CLIENT_SECRET", "fallback")
	t.Setenv("PANW_MGMT_TSG_ID", "fallback")
	t.Setenv("PANW_AI_GW_CLIENT_ID", "primary")
	t.Setenv("PANW_AI_GW_CLIENT_SECRET", "primary")
	t.Setenv("PANW_AI_GW_TSG_ID", "primary")
	t.Setenv("PANW_AI_GW_DATA_ENDPOINT", "https://env-data.example/")
	t.Setenv("PANW_AI_GW_ADMIN_ENDPOINT", "https://env-admin.example/")
	c, err := NewClient(Opts{})
	if err != nil {
		t.Fatal(err)
	}
	if c.dataCfg.TsgID != "primary" || c.dataCfg.BaseURL != "https://env-data.example" || c.adminCfg.BaseURL != "https://env-admin.example" {
		t.Fatal("primary env not selected")
	}
	c, err = NewClient(Opts{ClientID: "explicit", ClientSecret: "explicit", TsgID: "explicit", DataEndpoint: "https://explicit-data.example/", AdminEndpoint: "https://explicit-admin.example/"})
	if err != nil {
		t.Fatal(err)
	}
	if c.dataCfg.TsgID != "explicit" || c.dataCfg.BaseURL != "https://explicit-data.example" || c.adminCfg.BaseURL != "https://explicit-admin.example" {
		t.Fatal("options did not override env")
	}
}
