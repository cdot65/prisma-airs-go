package internal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestOAuthServer(t *testing.T, expiresIn int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("content-type = %s", r.Header.Get("Content-Type"))
		}
		auth := r.Header.Get("Authorization")
		if auth == "" {
			t.Error("missing Authorization header")
		}

		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token-123",
			"expires_in":   expiresIn,
			"token_type":   "Bearer",
		})
	}))
}

func TestOAuthClient_GetToken(t *testing.T) {
	server := newTestOAuthServer(t, 3600)
	defer server.Close()

	client := NewOAuthClient(OAuthClientOpts{
		ClientID:      "id",
		ClientSecret:  "secret",
		TsgID:         "123",
		TokenEndpoint: server.URL,
	})

	token, err := client.GetToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "test-token-123" {
		t.Errorf("token = %q", token)
	}
}

func TestOAuthClient_TokenCaching(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "cached-token",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	}))
	defer server.Close()

	client := NewOAuthClient(OAuthClientOpts{
		ClientID:      "id",
		ClientSecret:  "secret",
		TsgID:         "123",
		TokenEndpoint: server.URL,
	})

	// First call fetches
	_, _ = client.GetToken()
	// Second call should use cache
	token, _ := client.GetToken()
	if token != "cached-token" {
		t.Errorf("token = %q", token)
	}
	if calls.Load() != 1 {
		t.Errorf("fetch calls = %d, want 1", calls.Load())
	}
}

func TestOAuthClient_ClearToken(t *testing.T) {
	server := newTestOAuthServer(t, 3600)
	defer server.Close()

	client := NewOAuthClient(OAuthClientOpts{
		ClientID:      "id",
		ClientSecret:  "secret",
		TsgID:         "123",
		TokenEndpoint: server.URL,
	})

	_, _ = client.GetToken()
	info := client.GetTokenInfo()
	if !info.HasToken {
		t.Error("should have token after GetToken")
	}

	client.ClearToken()
	info = client.GetTokenInfo()
	if info.HasToken {
		t.Error("should not have token after ClearToken")
	}
}

func TestOAuthClient_TokenInfo(t *testing.T) {
	server := newTestOAuthServer(t, 3600)
	defer server.Close()

	client := NewOAuthClient(OAuthClientOpts{
		ClientID:      "id",
		ClientSecret:  "secret",
		TsgID:         "123",
		TokenEndpoint: server.URL,
	})

	// Before fetch
	info := client.GetTokenInfo()
	if info.HasToken {
		t.Error("should not have token initially")
	}
	if info.IsValid {
		t.Error("should not be valid without token")
	}
	if !info.IsExpired {
		t.Error("should be expired without token")
	}

	// After fetch
	_, _ = client.GetToken()
	info = client.GetTokenInfo()
	if !info.HasToken {
		t.Error("should have token")
	}
	if !info.IsValid {
		t.Error("should be valid")
	}
	if info.IsExpired {
		t.Error("should not be expired")
	}
	if info.ExpiresIn <= 0 {
		t.Errorf("ExpiresIn = %v", info.ExpiresIn)
	}
}

func TestOAuthClient_ConcurrentDeduplication(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(50 * time.Millisecond) // simulate latency
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "dedup-token",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	}))
	defer server.Close()

	client := NewOAuthClient(OAuthClientOpts{
		ClientID:      "id",
		ClientSecret:  "secret",
		TsgID:         "123",
		TokenEndpoint: server.URL,
	})

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := client.GetToken()
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if token != "dedup-token" {
				t.Errorf("token = %q", token)
			}
		}()
	}
	wg.Wait()

	if calls.Load() != 1 {
		t.Errorf("fetch calls = %d, want 1 (deduplication failed)", calls.Load())
	}
}

func TestOAuthClient_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_client",
			"error_description": "bad credentials",
		})
	}))
	defer server.Close()

	client := NewOAuthClient(OAuthClientOpts{
		ClientID:      "bad-id",
		ClientSecret:  "bad-secret",
		TsgID:         "123",
		TokenEndpoint: server.URL,
	})

	_, err := client.GetToken()
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestOAuthClient_IsTokenExpired(t *testing.T) {
	server := newTestOAuthServer(t, 1) // 1 second expiry
	defer server.Close()

	client := NewOAuthClient(OAuthClientOpts{
		ClientID:      "id",
		ClientSecret:  "secret",
		TsgID:         "123",
		TokenEndpoint: server.URL,
		TokenBufferMs: 100, // small buffer for test
	})

	if !client.IsTokenExpired() {
		t.Error("should be expired without token")
	}

	_, _ = client.GetToken()
	if client.IsTokenExpired() {
		t.Error("should not be expired right after fetch")
	}
}

func TestOAuthClient_DefaultTokenEndpoint(t *testing.T) {
	client := NewOAuthClient(OAuthClientOpts{
		ClientID:     "id",
		ClientSecret: "secret",
		TsgID:        "123",
	})
	if client.TokenEndpoint() != "https://auth.apps.paloaltonetworks.com/oauth2/access_token" {
		t.Errorf("endpoint = %q", client.TokenEndpoint())
	}
}
