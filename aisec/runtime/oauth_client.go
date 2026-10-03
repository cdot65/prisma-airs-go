package runtime

import (
	"context"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	"net/http"
	"time"
)

// TokenInfo is a credential-free snapshot of the OAuth token cache.
type TokenInfo struct {
	HasToken, IsValid, IsExpired, IsExpiringSoon bool
	ExpiresIn                                    time.Duration
	ExpiresAt                                    time.Time
}

// OAuthClientOptions configures a standalone cached token manager.
type OAuthClientOptions struct {
	ClientID, ClientSecret, TsgID, TokenEndpoint string
	TokenBufferMs                                int
	HTTPClient                                   *http.Client
	// OnTokenRefresh runs synchronously after refresh, before waiting token calls return.
	// It must return promptly; panics propagate to the refreshing caller.
	OnTokenRefresh func(TokenInfo)
}

// OAuthClient manages client-credentials tokens with automatic refresh and concurrent request deduplication.
type OAuthClient struct{ client *internal.OAuthClient }

// NewOAuthClient creates a standalone token manager without fetching a token.
func NewOAuthClient(opts OAuthClientOptions) (*OAuthClient, error) {
	if opts.ClientID == "" || opts.ClientSecret == "" || opts.TsgID == "" {
		return nil, aisec.NewAISecSDKError("OAuth client ID, secret, and tenant are required", aisec.MissingVariableError)
	}
	if opts.TokenBufferMs < 0 {
		return nil, aisec.NewAISecSDKError("token buffer must be nonnegative", aisec.UserRequestPayloadError)
	}
	var refresh func(internal.TokenInfo)
	if opts.OnTokenRefresh != nil {
		refresh = func(info internal.TokenInfo) { opts.OnTokenRefresh(TokenInfo(info)) }
	}
	return &OAuthClient{client: internal.NewOAuthClient(internal.OAuthClientOpts{ClientID: opts.ClientID, ClientSecret: opts.ClientSecret, TsgID: opts.TsgID, TokenEndpoint: opts.TokenEndpoint, TokenBufferMs: opts.TokenBufferMs, HTTPClient: opts.HTTPClient, OnTokenRefresh: refresh})}, nil
}

// GetToken returns a valid token, fetching or refreshing only when needed.
func (c *OAuthClient) GetToken(ctx context.Context) (string, error) {
	return c.client.GetTokenContext(ctx)
}

// ClearToken invalidates the cache; the next GetToken fetches a new token.
func (c *OAuthClient) ClearToken() { c.client.ClearToken() }

// IsTokenExpired reports whether a token is absent or expired.
func (c *OAuthClient) IsTokenExpired() bool { return c.client.IsTokenExpired() }

// IsTokenExpiringSoon reports whether the cache is within the refresh buffer.
func (c *OAuthClient) IsTokenExpiringSoon() bool { return c.client.IsTokenExpiringSoon() }

// GetTokenInfo returns token timing without the bearer value.
func (c *OAuthClient) GetTokenInfo() TokenInfo { return TokenInfo(c.client.GetTokenInfo()) }

// TokenEndpoint returns the configured OAuth endpoint.
func (c *OAuthClient) TokenEndpoint() string { return c.client.TokenEndpoint() }
