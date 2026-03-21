package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdot65/prisma-airs-go/aisec"
)

func TestHTTPRequest_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-pan-token") != "test-key" {
			t.Error("missing API key header")
		}
		if r.Header.Get("x-payload-hash") == "" {
			t.Error("missing payload hash header")
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("missing content-type")
		}
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(map[string]string{"result": "ok"})
	}))
	defer server.Close()

	cfg := aisec.NewConfig(aisec.WithAPIKey("test-key"), aisec.WithEndpoint(server.URL))
	var result map[string]string
	resp, err := DoRequest[map[string]string](context.Background(), cfg, RequestOptions{
		Method: http.MethodPost,
		Path:   "/v1/scan/sync/request",
		Body:   map[string]string{"prompt": "hello"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result = resp.Data
	if result["result"] != "ok" {
		t.Errorf("result = %v", result)
	}
}

func TestHTTPRequest_WithQueryParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("limit") != "10" {
			t.Errorf("limit = %q", r.URL.Query().Get("limit"))
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	cfg := aisec.NewConfig(aisec.WithAPIKey("k"), aisec.WithEndpoint(server.URL))
	_, err := DoRequest[map[string]any](context.Background(), cfg, RequestOptions{
		Method: http.MethodGet,
		Path:   "/v1/test",
		Params: map[string]string{"limit": "10"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHTTPRequest_BearerToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			t.Errorf("Authorization = %q", auth)
		}
		// Should NOT have API key header
		if r.Header.Get("x-pan-token") != "" {
			t.Error("should not have API key header when using bearer token")
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	cfg := aisec.NewConfig(aisec.WithAPIToken("test-token"), aisec.WithEndpoint(server.URL))
	_, err := DoRequest[map[string]any](context.Background(), cfg, RequestOptions{
		Method: http.MethodGet,
		Path:   "/test",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHTTPRequest_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	cfg := aisec.NewConfig(aisec.WithAPIKey("k"), aisec.WithEndpoint(server.URL))
	_, err := DoRequest[map[string]any](ctx, cfg, RequestOptions{
		Method: http.MethodGet,
		Path:   "/test",
	})
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}
