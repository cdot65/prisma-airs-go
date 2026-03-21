package internal

import (
	"fmt"
	"os"

	"github.com/cdot65/prisma-airs-go/aisec"
)

// OAuthServiceConfig is the resolved OAuth configuration for a service.
type OAuthServiceConfig struct {
	BaseURL    string
	OAuth      *OAuthClient
	NumRetries int
	TsgID      string
}

// ResolveOAuthConfigOpts are options for resolving OAuth config.
type ResolveOAuthConfigOpts struct {
	ClientID         string
	ClientSecret     string
	TsgID            string
	BaseURL          string
	NumRetries       int
	TokenEndpoint    string
	TokenBufferMs    int
	PrimaryEnvPrefix string // e.g. "PANW_RED_TEAM"
	FallbackEnvPrefix string // e.g. "PANW_MGMT"
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
	})

	return &OAuthServiceConfig{
		BaseURL:    opts.BaseURL,
		OAuth:      oauthClient,
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
