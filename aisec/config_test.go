package aisec

import (
	"strings"
	"testing"
)

func TestNewConfig_WithAPIKey(t *testing.T) {
	cfg := NewConfig(WithAPIKey("test-key"))
	if cfg.APIKey() != "test-key" {
		t.Errorf("APIKey() = %q", cfg.APIKey())
	}
	if cfg.Endpoint() != DefaultEndpoint {
		t.Errorf("Endpoint() = %q", cfg.Endpoint())
	}
	if cfg.NumRetries() != MaxNumberOfRetries {
		t.Errorf("NumRetries() = %d", cfg.NumRetries())
	}
}

func TestNewConfig_WithAPIToken(t *testing.T) {
	cfg := NewConfig(WithAPIToken("test-token"))
	if cfg.APIToken() != "test-token" {
		t.Errorf("APIToken() = %q", cfg.APIToken())
	}
}

func TestNewConfig_WithEndpoint(t *testing.T) {
	cfg := NewConfig(WithAPIKey("k"), WithEndpoint("https://custom.example.com/"))
	// trailing slash should be stripped
	if strings.HasSuffix(cfg.Endpoint(), "/") {
		t.Errorf("Endpoint should strip trailing slash: %q", cfg.Endpoint())
	}
	if cfg.Endpoint() != "https://custom.example.com" {
		t.Errorf("Endpoint() = %q", cfg.Endpoint())
	}
}

func TestNewConfig_WithNumRetries(t *testing.T) {
	cfg := NewConfig(WithAPIKey("k"), WithNumRetries(3))
	if cfg.NumRetries() != 3 {
		t.Errorf("NumRetries() = %d", cfg.NumRetries())
	}
}

func TestNewConfig_NumRetriesClamped(t *testing.T) {
	cfg := NewConfig(WithAPIKey("k"), WithNumRetries(99))
	if cfg.NumRetries() != MaxNumberOfRetries {
		t.Errorf("NumRetries should be clamped to %d, got %d", MaxNumberOfRetries, cfg.NumRetries())
	}

	cfg2 := NewConfig(WithAPIKey("k"), WithNumRetries(-5))
	if cfg2.NumRetries() != 0 {
		t.Errorf("NumRetries should be clamped to 0, got %d", cfg2.NumRetries())
	}
}

func TestNewConfig_FromEnvVars(t *testing.T) {
	t.Setenv("PANW_AI_SEC_API_KEY", "env-key")
	t.Setenv("PANW_AI_SEC_API_ENDPOINT", "https://env.example.com")

	cfg := NewConfig()
	if cfg.APIKey() != "env-key" {
		t.Errorf("APIKey() = %q, want env-key", cfg.APIKey())
	}
	if cfg.Endpoint() != "https://env.example.com" {
		t.Errorf("Endpoint() = %q", cfg.Endpoint())
	}
}

func TestNewConfig_ExplicitOverridesEnv(t *testing.T) {
	t.Setenv("PANW_AI_SEC_API_KEY", "env-key")

	cfg := NewConfig(WithAPIKey("explicit-key"))
	if cfg.APIKey() != "explicit-key" {
		t.Errorf("APIKey() = %q, want explicit-key", cfg.APIKey())
	}
}
