package management

import (
	"encoding/json"
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
