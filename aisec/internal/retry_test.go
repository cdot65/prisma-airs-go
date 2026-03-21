package internal

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/cdot65/prisma-airs-go/aisec"
)

func TestBackoffDelay_Bounds(t *testing.T) {
	for attempt := 0; attempt < 5; attempt++ {
		maxDelay := (1 << attempt) * 1000
		for i := 0; i < 100; i++ {
			d := BackoffDelay(attempt)
			if d < 0 || d > maxDelay {
				t.Errorf("attempt %d: delay %d out of bounds [0, %d]", attempt, d, maxDelay)
			}
		}
	}
}

func TestIsRetryableStatus(t *testing.T) {
	retryable := []int{500, 502, 503, 504}
	for _, code := range retryable {
		if !IsRetryableStatus(code) {
			t.Errorf("expected %d to be retryable", code)
		}
	}
	nonRetryable := []int{200, 400, 401, 403, 404, 429, 501}
	for _, code := range nonRetryable {
		if IsRetryableStatus(code) {
			t.Errorf("expected %d to not be retryable", code)
		}
	}
}

func TestClassifyErrorType(t *testing.T) {
	if ClassifyErrorType(500) != aisec.ServerSideError {
		t.Error("500 should be ServerSideError")
	}
	if ClassifyErrorType(502) != aisec.ServerSideError {
		t.Error("502 should be ServerSideError")
	}
	if ClassifyErrorType(400) != aisec.ClientSideError {
		t.Error("400 should be ClientSideError")
	}
	if ClassifyErrorType(404) != aisec.ClientSideError {
		t.Error("404 should be ClientSideError")
	}
}

func TestExtractErrorMessage(t *testing.T) {
	tests := []struct {
		body   string
		status int
		want   string
	}{
		{`{"error_message":"bad request"}`, 400, "bad request"},
		{`{"message":"not found"}`, 404, "not found"},
		{`{"error":{"message":"server error"}}`, 500, "server error"},
		{`not json`, 500, "API error 500: not json"},
		{"", 500, "API error 500"},
	}
	for _, tt := range tests {
		got := ExtractErrorMessage(tt.body, tt.status)
		if got != tt.want {
			t.Errorf("ExtractErrorMessage(%q, %d) = %q, want %q", tt.body, tt.status, got, tt.want)
		}
	}
}

func TestExecuteWithRetry_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	resp, err := ExecuteWithRetry(RetryOptions{
		MaxRetries: 3,
		Execute: func(attempt int) (*http.Response, error) {
			return http.Get(server.URL)
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestExecuteWithRetry_RetriesOn500(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			w.WriteHeader(500)
			_, _ = w.Write([]byte(`{"message":"server error"}`))
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	resp, err := ExecuteWithRetry(RetryOptions{
		MaxRetries: 5,
		Execute: func(attempt int) (*http.Response, error) {
			return http.Get(server.URL)
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	if attempts.Load() != 3 {
		t.Errorf("attempts = %d, want 3", attempts.Load())
	}
}

func TestExecuteWithRetry_NonRetryable400(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"message":"bad request"}`))
	}))
	defer server.Close()

	_, err := ExecuteWithRetry(RetryOptions{
		MaxRetries: 3,
		Execute: func(attempt int) (*http.Response, error) {
			return http.Get(server.URL)
		},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	var sdkErr *aisec.AISecSDKError
	if !errors.As(err, &sdkErr) {
		t.Fatal("expected AISecSDKError")
	}
	if sdkErr.ErrorType != aisec.ClientSideError {
		t.Errorf("ErrorType = %v", sdkErr.ErrorType)
	}
}

func TestExecuteWithRetry_ExhaustsRetries(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"message":"always fails"}`))
	}))
	defer server.Close()

	_, err := ExecuteWithRetry(RetryOptions{
		MaxRetries: 2,
		Execute: func(attempt int) (*http.Response, error) {
			return http.Get(server.URL)
		},
	})
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	// 1 initial + 2 retries = 3 total
	if attempts.Load() != 3 {
		t.Errorf("attempts = %d, want 3", attempts.Load())
	}
}

func TestExecuteWithRetry_OnRetryableFailure(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"message":"unauthorized"}`))
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	_, err := ExecuteWithRetry(RetryOptions{
		MaxRetries: 3,
		Execute: func(attempt int) (*http.Response, error) {
			return http.Get(server.URL)
		},
		OnRetryableFailure: func(resp *http.Response, attempt int) (bool, error) {
			if resp.StatusCode == 401 {
				return true, nil // handled, retry without budget cost
			}
			return false, nil
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if attempts.Load() != 2 {
		t.Errorf("attempts = %d, want 2", attempts.Load())
	}
}
