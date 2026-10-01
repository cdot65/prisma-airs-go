package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"strconv"
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

// maxRetryAfter caps how long a server-supplied Retry-After may delay a retry.
const maxRetryAfter = 30 * time.Second

// RetryAfterDelay parses a Retry-After header (delta-seconds or HTTP-date).
// It returns false when the header is absent or unparseable. The result is
// capped at 30 seconds so a hostile or misconfigured server cannot stall callers.
func RetryAfterDelay(h http.Header, now time.Time) (time.Duration, bool) {
	v := h.Get("Retry-After")
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0, false
		}
		return capRetryAfter(time.Duration(secs) * time.Second), true
	}
	if t, err := http.ParseTime(v); err == nil {
		d := t.Sub(now)
		if d < 0 {
			d = 0
		}
		return capRetryAfter(d), true
	}
	return 0, false
}

func capRetryAfter(d time.Duration) time.Duration {
	if d > maxRetryAfter {
		return maxRetryAfter
	}
	return d
}

// RetryOptions configures the retry behavior.
type RetryOptions struct {
	// Ctx, when set, aborts backoff sleeps as soon as it is cancelled.
	Ctx        context.Context
	MaxRetries int
	Execute    func(attempt int) (*http.Response, error)
	// OnRetryableFailure handles special failures (e.g. 401 token refresh).
	// Return (true, nil) to retry without consuming retry budget. Handlers that
	// do this MUST bound themselves (see NewAuthRefreshHandler) or a persistent
	// failure will loop forever.
	OnRetryableFailure func(resp *http.Response, attempt int) (bool, error)
}

// NewAuthRefreshHandler returns an OnRetryableFailure handler that, on the
// first 401/403 of a request, discards the cached OAuth token and requests a
// free retry. A second 401/403 on the same request is treated as a genuine
// authorization failure and falls through to normal error handling. Create one
// handler per request: it carries per-request state.
func NewAuthRefreshHandler(oauth *OAuthClient) func(*http.Response, int) (bool, error) {
	refreshed := false
	return func(resp *http.Response, _ int) (bool, error) {
		if (resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden) || refreshed {
			return false, nil
		}
		refreshed = true
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		oauth.ClearToken()
		return true, nil
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	if ctx == nil {
		time.Sleep(d)
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func ctxError(err error) error {
	return aisec.WrapError(err.Error(), aisec.ClientSideError, err)
}

// ExecuteWithRetry executes an HTTP request with exponential backoff retry.
func ExecuteWithRetry(opts RetryOptions) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt <= opts.MaxRetries; attempt++ {
		if opts.Ctx != nil {
			if err := opts.Ctx.Err(); err != nil {
				return nil, ctxError(err)
			}
		}

		resp, err := opts.Execute(attempt)
		if err != nil {
			// If it's already an SDK error, propagate immediately
			if _, ok := err.(*aisec.AISecSDKError); ok {
				return nil, err
			}
			// A cancelled or expired context will not recover; do not retry it.
			if opts.Ctx != nil && opts.Ctx.Err() != nil {
				return nil, ctxError(err)
			}
			lastErr = err
			if attempt < opts.MaxRetries {
				if sleepErr := sleepCtx(opts.Ctx, time.Duration(BackoffDelay(attempt))*time.Millisecond); sleepErr != nil {
					return nil, ctxError(sleepErr)
				}
				continue
			}
			msg := "Network error"
			if lastErr != nil {
				msg = lastErr.Error()
			}
			return nil, aisec.WrapError(msg, aisec.ClientSideError, lastErr)
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
			delay := time.Duration(BackoffDelay(attempt)) * time.Millisecond
			if d, ok := RetryAfterDelay(resp.Header, time.Now()); ok {
				delay = d
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if sleepErr := sleepCtx(opts.Ctx, delay); sleepErr != nil {
				return nil, ctxError(sleepErr)
			}
			continue
		}

		// Non-retryable or retries exhausted
		bodyBytes, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		errorMessage := ExtractErrorMessage(string(bodyBytes), resp.StatusCode)
		return nil, aisec.NewHTTPError(errorMessage, ClassifyErrorType(resp.StatusCode), resp.StatusCode)
	}

	msg := "Max retries exceeded"
	if lastErr != nil {
		msg = lastErr.Error()
	}
	return nil, aisec.NewAISecSDKError(msg, aisec.ClientSideError)
}
