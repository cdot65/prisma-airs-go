package internal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cdot65/prisma-airs-go/aisec"
)

const defaultTokenBufferMs = 30_000 // refresh 30s before expiry

// TokenInfo is a snapshot of the current token state (never exposes the actual token).
type TokenInfo struct {
	HasToken       bool
	IsValid        bool
	IsExpired      bool
	IsExpiringSoon bool
	ExpiresIn      time.Duration
	ExpiresAt      time.Time
}

// OAuthClientOpts are options for creating an OAuthClient.
type OAuthClientOpts struct {
	ClientID      string
	ClientSecret  string
	TsgID         string
	TokenEndpoint string
	TokenBufferMs int
	// HTTPClient is used for token requests. Defaults to DefaultHTTPClient().
	HTTPClient *http.Client
	// OnTokenRefresh runs outside the token lock after a successful refresh.
	OnTokenRefresh func(TokenInfo)
}

// OAuthClient manages OAuth2 client_credentials tokens with caching and proactive refresh.
type OAuthClient struct {
	clientID       string
	clientSecret   string
	tsgID          string
	tokenEndpoint  string
	tokenBuffer    time.Duration
	httpClient     *http.Client
	onTokenRefresh func(TokenInfo)

	mu          sync.Mutex
	accessToken string
	expiresAt   time.Time
	inflight    *tokenFetch // non-nil while a fetch is in progress
	waiters     int32       // callers currently parked on an in-flight fetch (observed by tests)
}

// tokenFetch is the outcome of one fetch. Each fetch gets its own value so a
// waiter can never read the result of a different, later fetch.
type tokenFetch struct {
	done  chan struct{} // closed when the fetch finishes
	token string
	err   error
}

// NewOAuthClient creates a new OAuth2 client.
func NewOAuthClient(opts OAuthClientOpts) *OAuthClient {
	endpoint := opts.TokenEndpoint
	if endpoint == "" {
		endpoint = aisec.DefaultTokenEndpoint
	}
	bufferMs := opts.TokenBufferMs
	if bufferMs <= 0 {
		bufferMs = defaultTokenBufferMs
	}

	hc := opts.HTTPClient
	if hc == nil {
		hc = DefaultHTTPClient()
	}

	return &OAuthClient{
		httpClient:     hc,
		onTokenRefresh: opts.OnTokenRefresh,
		clientID:       opts.ClientID,
		clientSecret:   opts.ClientSecret,
		tsgID:          opts.TsgID,
		tokenEndpoint:  endpoint,
		tokenBuffer:    time.Duration(bufferMs) * time.Millisecond,
	}
}

// GetToken returns a valid access token, fetching/refreshing as needed.
// It is GetTokenContext with context.Background().
func (c *OAuthClient) GetToken() (string, error) {
	return c.GetTokenContext(context.Background())
}

// tokenFetchTimeout bounds a token request when the caller's context has no deadline.
const tokenFetchTimeout = 30 * time.Second

// tokenFetchTimeoutOverride lets tests shorten the bound; zero means tokenFetchTimeout.
var tokenFetchTimeoutOverride time.Duration

func fetchTimeout() time.Duration {
	if tokenFetchTimeoutOverride > 0 {
		return tokenFetchTimeoutOverride
	}
	return tokenFetchTimeout
}

// GetTokenContext returns a valid access token, fetching/refreshing as needed.
// Concurrent calls are deduplicated — only one fetch happens at a time — and
// waiters receive the leader's error rather than a generic one. The caller's
// context cancels both the fetch and any wait for another goroutine's fetch.
func (c *OAuthClient) GetTokenContext(ctx context.Context) (string, error) {
	for {
		token, err, retry := c.getTokenOnce(ctx)
		if !retry {
			return token, err
		}
	}
}

// getTokenOnce makes one attempt. retry is true when this call waited on
// another goroutine's fetch that failed only because *that* goroutine's context
// ended; the caller's own context is still live, so it should fetch for itself.
func (c *OAuthClient) getTokenOnce(ctx context.Context) (token string, err error, retry bool) {
	c.mu.Lock()

	// Return cached token if valid
	if c.accessToken != "" && time.Now().Before(c.expiresAt.Add(-c.tokenBuffer)) {
		token = c.accessToken
		c.mu.Unlock()
		return token, nil, false
	}

	// If another goroutine is already fetching, wait for that fetch's result.
	if f := c.inflight; f != nil {
		atomic.AddInt32(&c.waiters, 1)
		c.mu.Unlock()
		defer atomic.AddInt32(&c.waiters, -1)
		select {
		case <-f.done:
		case <-ctx.Done():
			return "", aisec.WrapError("token wait cancelled: "+ctx.Err().Error(), aisec.OAuthError, ctx.Err()), false
		}
		if f.err != nil {
			if (errors.Is(f.err, context.Canceled) || errors.Is(f.err, context.DeadlineExceeded)) && ctx.Err() == nil {
				return "", nil, true
			}
			return "", f.err, false
		}
		return f.token, nil, false
	}

	// Start fetch. The deferred block runs even if fetchToken panics, so a
	// panic can never leave callers parked on a fetch that will not finish.
	f := &tokenFetch{done: make(chan struct{})}
	c.inflight = f
	c.mu.Unlock()

	f.err = aisec.NewAISecSDKError("token fetch aborted", aisec.OAuthError)
	defer func() {
		c.mu.Lock()
		c.inflight = nil
		close(f.done)
		c.mu.Unlock()
	}()

	f.token, f.err = c.fetchTokenWithRetry(ctx)
	return f.token, f.err, false
}

// tokenFetchAttempts bounds retries of transient token-endpoint failures.
const tokenFetchAttempts = 3

// fetchTokenWithRetry retries the token request on network errors, 429 and
// 5xx with the same jittered backoff the API requests use. Credential errors
// (400/401/403) are returned immediately.
func (c *OAuthClient) fetchTokenWithRetry(ctx context.Context) (string, error) {
	var lastErr error
	for attempt := 0; attempt < tokenFetchAttempts; attempt++ {
		token, err := c.fetchToken(ctx)
		if err == nil {
			return token, nil
		}
		lastErr = err
		var sdkErr *aisec.AISecSDKError
		transient := false
		if errors.As(err, &sdkErr) {
			// Transient: retryable HTTP statuses, or a transport-level failure
			// (*url.Error). Malformed URLs and unparseable bodies are not.
			var netErr *url.Error
			transient = IsRetryableStatus(sdkErr.StatusCode) ||
				(sdkErr.StatusCode == 0 && ctx.Err() == nil && errors.As(sdkErr.Err, &netErr))
		}
		if !transient || attempt == tokenFetchAttempts-1 || ctx.Err() != nil {
			break
		}
		if sleepErr := sleepCtx(ctx, time.Duration(BackoffDelay(attempt))*time.Millisecond); sleepErr != nil {
			break
		}
	}
	return "", lastErr
}

// ClearToken invalidates the cached token.
func (c *OAuthClient) ClearToken() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.accessToken = ""
	c.expiresAt = time.Time{}
}

// IsTokenExpired returns true if the token is expired or doesn't exist.
func (c *OAuthClient) IsTokenExpired() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.accessToken == "" || time.Now().After(c.expiresAt)
}

// IsTokenExpiringSoon returns true if the token is within the pre-expiry buffer.
func (c *OAuthClient) IsTokenExpiringSoon() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.accessToken == "" || time.Now().After(c.expiresAt.Add(-c.tokenBuffer))
}

// GetTokenInfo returns a snapshot of the current token state.
func (c *OAuthClient) GetTokenInfo() TokenInfo {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	hasToken := c.accessToken != ""
	isExpired := !hasToken || now.After(c.expiresAt)
	isExpiringSoon := !hasToken || now.After(c.expiresAt.Add(-c.tokenBuffer))

	var expiresIn time.Duration
	var expiresAt time.Time
	if hasToken {
		expiresIn = c.expiresAt.Sub(now)
		if expiresIn < 0 {
			expiresIn = 0
		}
		expiresAt = c.expiresAt
	}

	return TokenInfo{
		HasToken:       hasToken,
		IsValid:        hasToken && !isExpiringSoon,
		IsExpired:      isExpired,
		IsExpiringSoon: isExpiringSoon,
		ExpiresIn:      expiresIn,
		ExpiresAt:      expiresAt,
	}
}

// TokenEndpoint returns the configured token endpoint URL.
func (c *OAuthClient) TokenEndpoint() string {
	return c.tokenEndpoint
}

// ClientID returns the configured OAuth client ID.
func (c *OAuthClient) ClientID() string {
	return c.clientID
}

type oauthTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func (c *OAuthClient) fetchToken(ctx context.Context) (string, error) {
	parent := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, fetchTimeout())
		defer cancel()
	}

	credentials := base64.StdEncoding.EncodeToString(
		[]byte(c.clientID + ":" + c.clientSecret),
	)

	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {fmt.Sprintf("tsg_id:%s", c.tsgID)},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", aisec.WrapError("failed to create token request", aisec.OAuthError, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+credentials)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Our own fetch timeout is not the caller's context ending. Report it
		// without wrapping the context error so waiters with live contexts do
		// not mistake it for the leader being cancelled and re-fetch serially.
		if parent.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
			return "", aisec.NewAISecSDKError(fmt.Sprintf("token request timed out after %s", fetchTimeout()), aisec.OAuthError)
		}
		return "", aisec.WrapError(fmt.Sprintf("token request failed: %s", err.Error()), aisec.OAuthError, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		var errBody map[string]any
		msg := fmt.Sprintf("Token request failed with status %d", resp.StatusCode)
		if json.Unmarshal(body, &errBody) == nil {
			if desc, ok := errBody["error_description"].(string); ok {
				msg = desc
			} else if errStr, ok := errBody["error"].(string); ok {
				msg = errStr
			}
		}
		return "", aisec.NewHTTPError(msg, aisec.OAuthError, resp.StatusCode)
	}

	var tokenResp oauthTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", aisec.WrapError("failed to parse token response", aisec.OAuthError, err)
	}

	c.mu.Lock()
	c.accessToken = tokenResp.AccessToken
	c.expiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	c.mu.Unlock()
	if c.onTokenRefresh != nil {
		c.onTokenRefresh(c.GetTokenInfo())
	}

	return tokenResp.AccessToken, nil
}
