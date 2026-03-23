package runtime

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

func TestDataProtectionConfig_DatabaseSecurity(t *testing.T) {
	input := `{
		"data-leak-detection": {"action": "block", "member": [{"text": "IP Addresses", "id": "11995029", "version": "1"}]},
		"database-security": [
			{"name": "database-security-create", "action": "block"},
			{"name": "database-security-read", "action": "allow"},
			{"name": "database-security-update", "action": "block"},
			{"name": "database-security-delete", "action": "block"}
		]
	}`

	var cfg DataProtectionConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(cfg.DatabaseSecurity) != 4 {
		t.Fatalf("DatabaseSecurity len = %d, want 4", len(cfg.DatabaseSecurity))
	}
	if cfg.DatabaseSecurity[0].Name != "database-security-create" {
		t.Errorf("DatabaseSecurity[0].Name = %q, want %q", cfg.DatabaseSecurity[0].Name, "database-security-create")
	}
	if cfg.DatabaseSecurity[1].Action != "allow" {
		t.Errorf("DatabaseSecurity[1].Action = %q, want %q", cfg.DatabaseSecurity[1].Action, "allow")
	}

	// round-trip
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var rt DataProtectionConfig
	if err := json.Unmarshal(data, &rt); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if !reflect.DeepEqual(cfg, rt) {
		t.Error("round-trip mismatch")
	}
}

func TestDataProtectionConfig_DatabaseSecurityNull(t *testing.T) {
	input := `{
		"data-leak-detection": {"action": "", "member": null},
		"database-security": null
	}`

	var cfg DataProtectionConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.DatabaseSecurity != nil {
		t.Errorf("DatabaseSecurity should be nil, got %v", cfg.DatabaseSecurity)
	}
}

// TestBoolFalse_NotOmitted verifies that explicit false on plain bool fields
// is serialized into JSON (not silently dropped by omitempty).
func TestBoolFalse_NotOmitted(t *testing.T) {
	tests := []struct {
		name string
		val  any
		keys []string
	}{
		{
			name: "ModelConfiguration.MaskDataInStorage=false",
			val:  &ModelConfiguration{MaskDataInStorage: false},
			keys: []string{"mask-data-in-storage"},
		},
		{
			name: "DataLeakDetectionConfig.MaskDataInline=false",
			val:  &DataLeakDetectionConfig{MaskDataInline: false},
			keys: []string{"mask-data-inline"},
		},
		{
			name: "SecurityProfile.Active=false",
			val:  &SecurityProfile{Active: false},
			keys: []string{"active"},
		},
		{
			name: "CustomTopic.Active=false",
			val:  &CustomTopic{Active: false},
			keys: []string{"active"},
		},
		{
			name: "ApiKey.Revoked=false",
			val:  &ApiKey{Revoked: false},
			keys: []string{"revoked"},
		},
		{
			name: "CustomerApp.AgentApp=false",
			val:  &CustomerApp{AgentApp: false},
			keys: []string{"agent_app"},
		},
		{
			name: "ScanLog.IsPrompt+IsResponse+ContentMasked=false",
			val:  &ScanLog{IsPrompt: false, IsResponse: false, ContentMasked: false},
			keys: []string{"is_prompt", "is_response", "content_masked"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.val)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			m := make(map[string]any)
			if err := json.Unmarshal(data, &m); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			for _, key := range tt.keys {
				v, ok := m[key]
				if !ok {
					t.Errorf("bool field %q omitted from JSON when false", key)
					continue
				}
				if v != false {
					t.Errorf("bool field %q = %v, want false", key, v)
				}
			}
		})
	}
}

func TestDataProtectionConfig_DatabaseSecurityAbsent(t *testing.T) {
	input := `{
		"data-leak-detection": {"action": "block", "member": null}
	}`

	var cfg DataProtectionConfig
	if err := json.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.DatabaseSecurity != nil {
		t.Errorf("DatabaseSecurity should be nil when absent, got %v", cfg.DatabaseSecurity)
	}
}
