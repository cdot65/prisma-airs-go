package internal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
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
}

// OAuthClient manages OAuth2 client_credentials tokens with caching and proactive refresh.
type OAuthClient struct {
	clientID      string
	clientSecret  string
	tsgID         string
	tokenEndpoint string
	tokenBuffer time.Duration

	mu          sync.Mutex
	accessToken string
	expiresAt   time.Time
	fetching    bool
	fetchCh     chan struct{} // closed when fetch completes
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

	return &OAuthClient{
		clientID:      opts.ClientID,
		clientSecret:  opts.ClientSecret,
		tsgID:         opts.TsgID,
		tokenEndpoint: endpoint,
		tokenBuffer: time.Duration(bufferMs) * time.Millisecond,
	}
}

// GetToken returns a valid access token, fetching/refreshing as needed.
// Concurrent calls are deduplicated — only one fetch happens at a time.
func (c *OAuthClient) GetToken() (string, error) {
	c.mu.Lock()

	// Return cached token if valid
	if c.accessToken != "" && time.Now().Before(c.expiresAt.Add(-c.tokenBuffer)) {
		token := c.accessToken
		c.mu.Unlock()
		return token, nil
	}

	// If another goroutine is already fetching, wait for it
	if c.fetching {
		ch := c.fetchCh
		c.mu.Unlock()
		<-ch
		c.mu.Lock()
		token := c.accessToken
		c.mu.Unlock()
		if token == "" {
			return "", aisec.NewAISecSDKError("token fetch failed", aisec.OAuthError)
		}
		return token, nil
	}

	// Start fetch
	c.fetching = true
	c.fetchCh = make(chan struct{})
	c.mu.Unlock()

	token, err := c.fetchToken()

	c.mu.Lock()
	c.fetching = false
	close(c.fetchCh)
	c.mu.Unlock()

	return token, err
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

type oauthTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func (c *OAuthClient) fetchToken() (string, error) {
	credentials := base64.StdEncoding.EncodeToString(
		[]byte(c.clientID + ":" + c.clientSecret),
	)

	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {fmt.Sprintf("tsg_id:%s", c.tsgID)},
	}

	req, err := http.NewRequest("POST", c.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", aisec.WrapError("failed to create token request", aisec.OAuthError, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+credentials)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
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
		return "", aisec.NewAISecSDKError(msg, aisec.OAuthError)
	}

	var tokenResp oauthTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", aisec.WrapError("failed to parse token response", aisec.OAuthError, err)
	}

	c.mu.Lock()
	c.accessToken = tokenResp.AccessToken
	c.expiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	c.mu.Unlock()

	return tokenResp.AccessToken, nil
}
