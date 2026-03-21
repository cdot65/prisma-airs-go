package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"time"

	"github.com/cdot65/prisma-airs-go/aisec"
)

// BackoffDelay calculates exponential backoff with full jitter for the given attempt.
// Returns delay in milliseconds in [0, 2^attempt * 1000].
func BackoffDelay(attempt int) int {
	maxDelay := int(math.Pow(2, float64(attempt))) * 1000
	return rand.Intn(maxDelay + 1)
}

// IsRetryableStatus returns true if the HTTP status code should trigger a retry.
func IsRetryableStatus(status int) bool {
	for _, code := range aisec.HTTPForceRetryStatusCodes {
		if status == code {
			return true
		}
	}
	return false
}

// ClassifyErrorType classifies an HTTP status code as server-side or client-side.
func ClassifyErrorType(status int) aisec.ErrorType {
	if status >= 500 {
		return aisec.ServerSideError
	}
	return aisec.ClientSideError
}

// ExtractErrorMessage extracts a human-readable message from an API error response body.
func ExtractErrorMessage(body string, status int) string {
	if body == "" {
		return fmt.Sprintf("API error %d", status)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return fmt.Sprintf("API error %d: %s", status, body)
	}

	if msg, ok := parsed["error_message"].(string); ok && msg != "" {
		return msg
	}
	if msg, ok := parsed["message"].(string); ok && msg != "" {
		return msg
	}
	if errObj, ok := parsed["error"].(map[string]any); ok {
		if msg, ok := errObj["message"].(string); ok && msg != "" {
			return msg
		}
	}
	return fmt.Sprintf("API error %d", status)
}

// RetryOptions configures the retry behavior.
type RetryOptions struct {
	MaxRetries int
	Execute    func(attempt int) (*http.Response, error)
	// OnRetryableFailure handles special failures (e.g. 401 token refresh).
	// Return (true, nil) to retry without consuming retry budget.
	OnRetryableFailure func(resp *http.Response, attempt int) (bool, error)
}

// ExecuteWithRetry executes an HTTP request with exponential backoff retry.
func ExecuteWithRetry(opts RetryOptions) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt <= opts.MaxRetries; attempt++ {
		resp, err := opts.Execute(attempt)
		if err != nil {
			// If it's already an SDK error, propagate immediately
			if _, ok := err.(*aisec.AISecSDKError); ok {
				return nil, err
			}
			lastErr = err
			if attempt < opts.MaxRetries {
				time.Sleep(time.Duration(BackoffDelay(attempt)) * time.Millisecond)
				continue
			}
			msg := "Network error"
			if lastErr != nil {
				msg = lastErr.Error()
			}
			return nil, aisec.NewAISecSDKError(msg, aisec.ClientSideError)
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, nil
		}

		// Let caller handle special status codes (e.g. 401 token refresh)
		if opts.OnRetryableFailure != nil {
			handled, handleErr := opts.OnRetryableFailure(resp, attempt)
			if handleErr != nil {
				return nil, handleErr
			}
			if handled {
				attempt-- // don't count against retry budget
				continue
			}
		}

		if IsRetryableStatus(resp.StatusCode) && attempt < opts.MaxRetries {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			time.Sleep(time.Duration(BackoffDelay(attempt)) * time.Millisecond)
			continue
		}

		// Non-retryable or retries exhausted
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		errorMessage := ExtractErrorMessage(string(bodyBytes), resp.StatusCode)
		return nil, aisec.NewAISecSDKError(errorMessage, ClassifyErrorType(resp.StatusCode))
	}

	msg := "Max retries exceeded"
	if lastErr != nil {
		msg = lastErr.Error()
	}
	return nil, aisec.NewAISecSDKError(msg, aisec.ClientSideError)
}
