package management

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestAPIKeyDPInfo_RequiredFieldsSerialized verifies spec-required fields
// appear in JSON output even at zero values.
func TestAPIKeyDPInfo_RequiredFieldsSerialized(t *testing.T) {
	resp := APIKeyDPInfo{}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"api_key_name", "dp_name", "auth_code"} {
		if _, ok := m[key]; !ok {
			t.Errorf("required field %q missing from JSON", key)
		}
	}
}

func TestAppProtectionConfig_DefaultURLCategory(t *testing.T) {
	input := `{
		"allow-url-category": {},
		"block-url-category": {},
		"default-url-category": {"member": ["malicious"]},
		"url-detected-action": "block"
	}`

	var cfg AppProtectionConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.DefaultURLCategory == nil {
		t.Fatal("DefaultURLCategory is nil")
	}
	want := []string{"malicious"}
	if !reflect.DeepEqual(cfg.DefaultURLCategory.Member, want) {
		t.Errorf("DefaultURLCategory.Member = %v, want %v", cfg.DefaultURLCategory.Member, want)
	}
	if cfg.UrlDetectedAction != "block" {
		t.Errorf("UrlDetectedAction = %q, want %q", cfg.UrlDetectedAction, "block")
	}

	// round-trip
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var rt AppProtectionConfig
	if err := json.Unmarshal(data, &rt); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if !reflect.DeepEqual(cfg, rt) {
		t.Error("round-trip mismatch")
	}
}

func TestAppProtectionConfig_DefaultURLCategoryNull(t *testing.T) {
	input := `{
		"default-url-category": {"member": null},
		"url-detected-action": ""
	}`

	var cfg AppProtectionConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.DefaultURLCategory == nil {
		t.Fatal("DefaultURLCategory should not be nil when key is present")
	}
	if cfg.DefaultURLCategory.Member != nil {
		t.Errorf("Member should be nil, got %v", cfg.DefaultURLCategory.Member)
	}
}

func TestAppProtectionConfig_MaliciousCodeProtection(t *testing.T) {
	input := `{
		"default-url-category": {"member": ["malicious"]},
		"malicious-code-protection": {"name": "malicious-code", "action": "block"},
		"url-detected-action": "block"
	}`

	var cfg AppProtectionConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.MaliciousCodeProtection == nil {
		t.Fatal("MaliciousCodeProtection is nil")
	}
	if cfg.MaliciousCodeProtection.Name != "malicious-code" {
		t.Errorf("Name = %q, want %q", cfg.MaliciousCodeProtection.Name, "malicious-code")
	}
	if cfg.MaliciousCodeProtection.Action != "block" {
		t.Errorf("Action = %q, want %q", cfg.MaliciousCodeProtection.Action, "block")
	}

	// round-trip
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var rt AppProtectionConfig
	if err := json.Unmarshal(data, &rt); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if !reflect.DeepEqual(cfg, rt) {
		t.Error("round-trip mismatch")
	}
}

func TestAppProtectionConfig_MaliciousCodeProtectionAbsent(t *testing.T) {
	input := `{
		"default-url-category": {"member": ["malicious"]},
		"url-detected-action": "block"
	}`

	var cfg AppProtectionConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.MaliciousCodeProtection != nil {
		t.Error("MaliciousCodeProtection should be nil when absent")
	}
}

func TestAppProtectionConfig_FullRealResponse(t *testing.T) {
	// Real API response from examples/output.json (AI-Firewall-High-Security-Profile)
	input := `{
		"allow-url-category": {"member": ["dynamic-dns","grayware","abused-drugs","adult","encrypted-dns","high-risk","phishing","sports"]},
		"block-url-category": {"member": []},
		"default-url-category": {"member": null},
		"malicious-code-protection": {"action": "block", "name": "malicious-code"},
		"url-detected-action": "block"
	}`

	var cfg AppProtectionConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(cfg.AllowURLCategory.Member) != 8 {
		t.Errorf("AllowURLCategory.Member len = %d, want 8", len(cfg.AllowURLCategory.Member))
	}
	if cfg.DefaultURLCategory == nil {
		t.Fatal("DefaultURLCategory is nil")
	}
	if cfg.MaliciousCodeProtection == nil {
		t.Fatal("MaliciousCodeProtection is nil")
	}
	if cfg.UrlDetectedAction != "block" {
		t.Errorf("UrlDetectedAction = %q, want %q", cfg.UrlDetectedAction, "block")
	}
}
