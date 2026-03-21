package internal

import (
	"errors"
	"testing"

	"github.com/cdot65/prisma-airs-go/aisec"
)

func TestResolveOAuthConfig_Explicit(t *testing.T) {
	cfg, err := ResolveOAuthConfig(ResolveOAuthConfigOpts{
		ClientID:         "my-id",
		ClientSecret:     "my-secret",
		TsgID:            "123",
		BaseURL:          "https://api.example.com",
		NumRetries:       3,
		PrimaryEnvPrefix: "PANW_TEST",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BaseURL != "https://api.example.com" {
		t.Errorf("BaseURL = %q", cfg.BaseURL)
	}
	if cfg.NumRetries != 3 {
		t.Errorf("NumRetries = %d", cfg.NumRetries)
	}
	if cfg.TsgID != "123" {
		t.Errorf("TsgID = %q", cfg.TsgID)
	}
}

func TestResolveOAuthConfig_FromEnv(t *testing.T) {
	t.Setenv("PANW_TEST_CLIENT_ID", "env-id")
	t.Setenv("PANW_TEST_CLIENT_SECRET", "env-secret")
	t.Setenv("PANW_TEST_TSG_ID", "456")

	cfg, err := ResolveOAuthConfig(ResolveOAuthConfigOpts{
		BaseURL:          "https://api.example.com",
		PrimaryEnvPrefix: "PANW_TEST",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TsgID != "456" {
		t.Errorf("TsgID = %q", cfg.TsgID)
	}
}

func TestResolveOAuthConfig_Fallback(t *testing.T) {
	t.Setenv("PANW_MGMT_CLIENT_ID", "fallback-id")
	t.Setenv("PANW_MGMT_CLIENT_SECRET", "fallback-secret")
	t.Setenv("PANW_MGMT_TSG_ID", "789")

	cfg, err := ResolveOAuthConfig(ResolveOAuthConfigOpts{
		BaseURL:           "https://api.example.com",
		PrimaryEnvPrefix:  "PANW_MODEL_SEC",
		FallbackEnvPrefix: "PANW_MGMT",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TsgID != "789" {
		t.Errorf("TsgID = %q", cfg.TsgID)
	}
}

func TestResolveOAuthConfig_MissingClientID(t *testing.T) {
	_, err := ResolveOAuthConfig(ResolveOAuthConfigOpts{
		ClientSecret:     "secret",
		TsgID:            "123",
		BaseURL:          "https://api.example.com",
		PrimaryEnvPrefix: "PANW_EMPTY",
	})
	if err == nil {
		t.Fatal("expected error for missing clientId")
	}
	var sdkErr *aisec.AISecSDKError
	if !errors.As(err, &sdkErr) || sdkErr.ErrorType != aisec.MissingVariableError {
		t.Errorf("wrong error: %v", err)
	}
}

func TestResolveOAuthConfig_MissingClientSecret(t *testing.T) {
	_, err := ResolveOAuthConfig(ResolveOAuthConfigOpts{
		ClientID:         "id",
		TsgID:            "123",
		BaseURL:          "https://api.example.com",
		PrimaryEnvPrefix: "PANW_EMPTY",
	})
	if err == nil {
		t.Fatal("expected error for missing clientSecret")
	}
}

func TestResolveOAuthConfig_MissingTsgID(t *testing.T) {
	_, err := ResolveOAuthConfig(ResolveOAuthConfigOpts{
		ClientID:         "id",
		ClientSecret:     "secret",
		BaseURL:          "https://api.example.com",
		PrimaryEnvPrefix: "PANW_EMPTY",
	})
	if err == nil {
		t.Fatal("expected error for missing tsgId")
	}
}

func TestResolveOAuthConfig_RetriesClamped(t *testing.T) {
	cfg, _ := ResolveOAuthConfig(ResolveOAuthConfigOpts{
		ClientID:         "id",
		ClientSecret:     "secret",
		TsgID:            "123",
		BaseURL:          "https://api.example.com",
		NumRetries:       99,
		PrimaryEnvPrefix: "PANW_TEST",
	})
	if cfg.NumRetries != aisec.MaxNumberOfRetries {
		t.Errorf("NumRetries = %d", cfg.NumRetries)
	}
}
