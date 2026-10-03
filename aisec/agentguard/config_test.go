package agentguard

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/agentguard/schema"
)

func TestSubClientsAllPresentAndShareToken(t *testing.T) {
	c, tokens := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"scans":[],"pagination":{},"rules":[]}`)
	})
	if c.Scans == nil || c.Statistics == nil || c.Instances == nil || c.Rules == nil || c.RuleInstances == nil || c.SkillOverrides == nil {
		t.Fatal("missing sub-client")
	}
	if c.Scans.cfg.OAuth != c.Rules.cfg.OAuth || c.Scans.cfg.HTTPClient != c.Rules.cfg.HTTPClient {
		t.Fatal("planes do not share auth/client")
	}
	if _, err := c.Scans.List(context.Background(), ScanListOpts{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Rules.List(context.Background(), ListOpts{}); err != nil {
		t.Fatal(err)
	}
	if tokens.Load() != 1 {
		t.Errorf("fetched %d tokens", tokens.Load())
	}
}

func TestConfigPrecedence(t *testing.T) {
	for _, prefix := range []string{"PANW_MGMT", "PANW_AGENT_GUARD"} {
		t.Setenv(prefix+"_CLIENT_ID", prefix+"-id")
		t.Setenv(prefix+"_CLIENT_SECRET", prefix+"-secret")
		t.Setenv(prefix+"_TSG_ID", prefix+"-tsg")
		t.Setenv(prefix+"_TOKEN_ENDPOINT", "https://token.example/"+prefix)
	}
	t.Setenv(aisec.EnvAgentGuardDataEndpoint, "https://data.example/preview/")
	t.Setenv(aisec.EnvAgentGuardMgmtEndpoint, "https://mgmt.example/preview/")
	c, err := NewClient(Opts{NumRetries: 99})
	if err != nil {
		t.Fatal(err)
	}
	if c.Scans.cfg.BaseURL != "https://data.example/preview" || c.Rules.cfg.BaseURL != "https://mgmt.example/preview" || c.Rules.cfg.TsgID != "PANW_AGENT_GUARD-tsg" || c.Rules.cfg.NumRetries != 5 {
		t.Fatal("service environment not resolved")
	}
	c, err = NewClient(Opts{ClientID: "explicit", ClientSecret: "explicit", TsgID: "explicit", DataEndpoint: "https://explicit.example/data/", MgmtEndpoint: "https://explicit.example/mgmt/", NumRetries: -1})
	if err != nil {
		t.Fatal(err)
	}
	if c.Scans.cfg.BaseURL != "https://explicit.example/data" || c.Rules.cfg.TsgID != "explicit" || c.Rules.cfg.NumRetries != 0 {
		t.Fatal("explicit options not preferred")
	}
	for _, suffix := range []string{"_CLIENT_ID", "_CLIENT_SECRET", "_TSG_ID", "_TOKEN_ENDPOINT"} {
		t.Setenv("PANW_AGENT_GUARD"+suffix, "")
	}
	c, err = NewClient(Opts{})
	if err != nil {
		t.Fatal(err)
	}
	if c.Rules.cfg.TsgID != "PANW_MGMT-tsg" {
		t.Fatal("fallback missing")
	}
}

func TestRequiredConfig(t *testing.T) {
	base := Opts{ClientID: "id", ClientSecret: "secret", TsgID: "tsg", DataEndpoint: "https://data.example", MgmtEndpoint: "https://mgmt.example"}
	for _, field := range []string{"data", "mgmt", "id", "secret", "tsg"} {
		t.Run(field, func(t *testing.T) {
			opts := base
			switch field {
			case "data":
				opts.DataEndpoint = ""
			case "mgmt":
				opts.MgmtEndpoint = ""
			case "id":
				opts.ClientID = ""
			case "secret":
				opts.ClientSecret = ""
			case "tsg":
				opts.TsgID = ""
			}
			_, err := NewClient(opts)
			var sdkErr *aisec.AISecSDKError
			if !errors.As(err, &sdkErr) || sdkErr.ErrorType != aisec.MissingVariableError {
				t.Fatalf("error %v", err)
			}
		})
	}
	for _, endpoint := range []string{"relative", "ftp://example.com", "https://", "https://user:pass@example.com", "https://example.com?q=x", "https://example.com#fragment", "https://example.com?", "https://example.com#"} {
		opts := base
		opts.DataEndpoint = endpoint
		_, err := NewClient(opts)
		var sdkErr *aisec.AISecSDKError
		if !errors.As(err, &sdkErr) || sdkErr.ErrorType != aisec.UserRequestPayloadError {
			t.Fatalf("endpoint %q error %v", endpoint, err)
		}
	}
}

func TestInvalidIdentifiersDoNotCallAPI(t *testing.T) {
	c, tokens := testClient(t, func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected API call") })
	calls := []func() error{
		func() error { _, err := c.Scans.Get(context.Background(), "bad"); return err },
		func() error { _, err := c.Scans.ListAttackChains(context.Background(), "bad", ListOpts{}); return err },
		func() error { _, err := c.Scans.GetAttackChain(context.Background(), testUUID, "bad"); return err },
		func() error { _, err := c.Scans.GetAttackChain(context.Background(), "bad", chainUUID); return err },
		func() error {
			_, err := c.Scans.UploadComplete(context.Background(), "bad", schema.AgentGuardUploadCompleteRequest{}, UploadCompleteOpts{})
			return err
		},
		func() error {
			_, err := c.Scans.ListVulnerabilities(context.Background(), "bad", VulnerabilityListOpts{})
			return err
		},
		func() error { return c.SkillOverrides.Delete(context.Background(), "bad") },
		func() error { _, err := c.Scans.Lookup(context.Background(), strings.Repeat("A", 64)); return err },
		func() error { _, err := c.Scans.Lookup(context.Background(), strings.Repeat("a", 63)); return err },
		func() error { _, err := c.Instances.Get(context.Background(), " "); return err },
		func() error {
			_, err := c.Instances.Update(context.Background(), "", schema.InstanceCreateModel{})
			return err
		},
		func() error { _, err := c.Instances.Delete(context.Background(), ""); return err },
	}
	for _, call := range calls {
		err := call()
		var sdkErr *aisec.AISecSDKError
		if !errors.As(err, &sdkErr) || sdkErr.ErrorType != aisec.UserRequestPayloadError {
			t.Fatalf("error %v", err)
		}
	}
	if tokens.Load() != 0 {
		t.Error("invalid input fetched tokens")
	}
}

// Build complete response fixtures directly from the pinned contract, including
// optional fields, so the HTTP matrix detects fields dropped by decoding.
func contractFixture(shape, spec map[string]any) any {
	if ref, ok := shape["$ref"].(string); ok {
		return contractFixture(spec["components"].(map[string]any)["schemas"].(map[string]any)[strings.TrimPrefix(ref, "#/components/schemas/")].(map[string]any), spec)
	}
	if variants, ok := shape["anyOf"].([]any); ok {
		return contractFixture(variants[0].(map[string]any), spec)
	}
	if values, ok := shape["enum"].([]any); ok {
		return values[0]
	}
	switch shape["type"] {
	case "object":
		result := map[string]any{}
		if props, ok := shape["properties"].(map[string]any); ok {
			for key, prop := range props {
				result[key] = contractFixture(prop.(map[string]any), spec)
			}
		}
		return result
	case "array":
		return []any{contractFixture(shape["items"].(map[string]any), spec)}
	case "string":
		if shape["format"] == "uuid" {
			return testUUID
		}
		if shape["format"] == "date-time" {
			return "2026-08-21T01:02:03Z"
		}
		return "example"
	case "integer":
		return 7
	case "number":
		return 1.25
	case "boolean":
		return false
	default:
		return map[string]any{"free": "form"}
	}
}
