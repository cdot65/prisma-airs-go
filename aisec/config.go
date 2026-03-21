package aisec

import (
	"os"
	"strings"
)

// Config holds scan API configuration.
type Config struct {
	apiKey     string
	apiToken   string
	endpoint   string
	numRetries int
}

// ConfigOption is a functional option for NewConfig.
type ConfigOption func(*Config)

// WithAPIKey sets the API key for HMAC-SHA256 auth.
func WithAPIKey(key string) ConfigOption {
	return func(c *Config) { c.apiKey = key }
}

// WithAPIToken sets the bearer token for auth.
func WithAPIToken(token string) ConfigOption {
	return func(c *Config) { c.apiToken = token }
}

// WithEndpoint overrides the default scan API endpoint.
func WithEndpoint(endpoint string) ConfigOption {
	return func(c *Config) { c.endpoint = endpoint }
}

// WithNumRetries sets the max retry count (clamped to 0–MaxNumberOfRetries).
func WithNumRetries(n int) ConfigOption {
	return func(c *Config) { c.numRetries = n }
}

// NewConfig creates a Config, reading environment variables as fallbacks.
func NewConfig(opts ...ConfigOption) *Config {
	c := &Config{
		endpoint:   DefaultEndpoint,
		numRetries: MaxNumberOfRetries,
	}

	for _, opt := range opts {
		opt(c)
	}

	// Env var fallbacks (only if not set explicitly)
	if c.apiKey == "" {
		c.apiKey = strings.TrimSpace(os.Getenv(EnvAISecAPIKey))
	}
	if c.apiToken == "" {
		c.apiToken = strings.TrimSpace(os.Getenv(EnvAISecAPIToken))
	}
	if c.endpoint == DefaultEndpoint {
		if env := os.Getenv(EnvAISecAPIEndpoint); env != "" {
			c.endpoint = env
		}
	}

	// Strip trailing slashes from endpoint
	c.endpoint = strings.TrimRight(c.endpoint, "/")

	// Clamp retries
	if c.numRetries < 0 {
		c.numRetries = 0
	}
	if c.numRetries > MaxNumberOfRetries {
		c.numRetries = MaxNumberOfRetries
	}

	return c
}

// APIKey returns the configured API key.
func (c *Config) APIKey() string { return c.apiKey }

// APIToken returns the configured bearer token.
func (c *Config) APIToken() string { return c.apiToken }

// Endpoint returns the configured API endpoint.
func (c *Config) Endpoint() string { return c.endpoint }

// NumRetries returns the max retry count.
func (c *Config) NumRetries() int { return c.numRetries }
