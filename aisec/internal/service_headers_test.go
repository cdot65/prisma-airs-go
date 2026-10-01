package internal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOAuthServiceHeadersStayOnAPIRequests(t *testing.T) {
	token := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Tsg-Id") != "" {
			t.Error("tenant header leaked onto token request")
		}
		_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
	}))
	defer token.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Tsg-Id") != "tenant" || r.Header.Get("Authorization") != "Bearer token" {
			t.Error("service headers or bearer missing")
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer api.Close()
	cfg := &OAuthServiceConfig{BaseURL: api.URL, OAuth: NewOAuthClient(OAuthClientOpts{ClientID: "a", ClientSecret: "b", TsgID: "tenant", TokenEndpoint: token.URL}), Headers: http.Header{"X-Tsg-Id": []string{"tenant"}, "Authorization": []string{"untrusted"}}}
	if _, err := DoMgmtRequest[map[string]any](context.Background(), cfg, MgmtRequestOptions{Method: http.MethodGet, Path: "/x"}); err != nil {
		t.Fatal(err)
	}
}
