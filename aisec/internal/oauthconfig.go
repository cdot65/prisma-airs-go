package internal

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/cdot65/prisma-airs-go/aisec"
)

// OAuthServiceConfig is the resolved OAuth configuration for a service.
type OAuthServiceConfig struct {
	BaseURL    string
	OAuth      *OAuthClient
	NumRetries int
	TsgID      string
	// HTTPClient, when set, is used for API requests (token requests use the
	// OAuthClient's own client, configured from the same value).
	HTTPClient *http.Client
}

// ResolveOAuthConfigOpts are options for resolving OAuth config.
type ResolveOAuthConfigOpts struct {
	ClientID          string
	ClientSecret      string
	TsgID             string
	BaseURL           string
	NumRetries        int
	TokenEndpoint     string
	TokenBufferMs     int
	PrimaryEnvPrefix  string // e.g. "PANW_RED_TEAM"
	FallbackEnvPrefix string // e.g. "PANW_MGMT"
	HTTPClient        *http.Client
}

// ResolveOAuthConfig resolves OAuth2 credentials from options -> primary env vars -> fallback env vars.
func ResolveOAuthConfig(opts ResolveOAuthConfigOpts) (*OAuthServiceConfig, error) {
	clientID := firstNonEmpty(opts.ClientID,
		os.Getenv(opts.PrimaryEnvPrefix+"_CLIENT_ID"),
		envOrEmpty(opts.FallbackEnvPrefix, "_CLIENT_ID"),
	)
	clientSecret := firstNonEmpty(opts.ClientSecret,
		os.Getenv(opts.PrimaryEnvPrefix+"_CLIENT_SECRET"),
		envOrEmpty(opts.FallbackEnvPrefix, "_CLIENT_SECRET"),
	)
	tsgID := firstNonEmpty(opts.TsgID,
		os.Getenv(opts.PrimaryEnvPrefix+"_TSG_ID"),
		envOrEmpty(opts.FallbackEnvPrefix, "_TSG_ID"),
	)
	tokenEndpoint := firstNonEmpty(opts.TokenEndpoint,
		os.Getenv(opts.PrimaryEnvPrefix+"_TOKEN_ENDPOINT"),
		envOrEmpty(opts.FallbackEnvPrefix, "_TOKEN_ENDPOINT"),
	)

	numRetries := opts.NumRetries
	if numRetries < 0 {
		numRetries = 0
	}
	if numRetries > aisec.MaxNumberOfRetries {
		numRetries = aisec.MaxNumberOfRetries
	}

	if clientID == "" {
		hint := opts.PrimaryEnvPrefix + "_CLIENT_ID"
		if opts.FallbackEnvPrefix != "" {
			hint += " / " + opts.FallbackEnvPrefix + "_CLIENT_ID"
		}
		return nil, aisec.NewAISecSDKError(
			fmt.Sprintf("clientId is required (option or %s env var)", hint),
			aisec.MissingVariableError,
		)
	}
	if clientSecret == "" {
		hint := opts.PrimaryEnvPrefix + "_CLIENT_SECRET"
		if opts.FallbackEnvPrefix != "" {
			hint += " / " + opts.FallbackEnvPrefix + "_CLIENT_SECRET"
		}
		return nil, aisec.NewAISecSDKError(
			fmt.Sprintf("clientSecret is required (option or %s env var)", hint),
			aisec.MissingVariableError,
		)
	}
	if tsgID == "" {
		hint := opts.PrimaryEnvPrefix + "_TSG_ID"
		if opts.FallbackEnvPrefix != "" {
			hint += " / " + opts.FallbackEnvPrefix + "_TSG_ID"
		}
		return nil, aisec.NewAISecSDKError(
			fmt.Sprintf("tsgId is required (option or %s env var)", hint),
			aisec.MissingVariableError,
		)
	}

	oauthClient := NewOAuthClient(OAuthClientOpts{
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		TsgID:         tsgID,
		TokenEndpoint: tokenEndpoint,
		TokenBufferMs: opts.TokenBufferMs,
		HTTPClient:    opts.HTTPClient,
	})

	return &OAuthServiceConfig{
		BaseURL:    strings.TrimRight(opts.BaseURL, "/"),
		OAuth:      oauthClient,
		HTTPClient: opts.HTTPClient,
		NumRetries: numRetries,
		TsgID:      tsgID,
	}, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func envOrEmpty(prefix, suffix string) string {
	if prefix == "" {
		return ""
	}
	return os.Getenv(prefix + suffix)
}

// ResolveEndpoint picks a base URL: explicit option, then the environment
// variable named envVar, then the default. Trailing slashes are removed.
func ResolveEndpoint(explicit, envVar, def string) string {
	return strings.TrimRight(firstNonEmpty(explicit, envOrEmpty(envVar, ""), def), "/")
}
