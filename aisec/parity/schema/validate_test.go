package schema

import (
	"encoding/json"
	"github.com/cdot65/prisma-airs-go/aisec"
	"testing"
)

func TestValidateRejectsMalformedMissingAndStrictFields(t *testing.T) {
	for _, body := range []string{`{}`, `{"name":"test"}`, `{"name":"test","scope_name":"ws_test","unexpected":true}`, `{"name":"test","scope_name":"ws_test"} {}`} {
		if err := ValidateJSON("GatewayWorkspaceCreateRequestSchema", []byte(body)); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
	if err := ValidateJSON("GatewayWorkspaceCreateRequestSchema", []byte(`{"name":"test","scope_name":"ws_test"}`)); err != nil {
		t.Fatal(err)
	}
	if err := ValidateJSON("missing", []byte(`{}`)); err == nil {
		t.Fatal("accepted missing contract")
	}
}
func TestNullableUnknownFieldsAndTypedAdditionalProperties(t *testing.T) {
	var patch DataPatternPatchRequest
	if err := json.Unmarshal([]byte(`{"name":"test","type":"custom","detection_config":{"technique":"regex"},"description":null,"extra":{"keep":true}}`), &patch); err != nil {
		t.Fatal(err)
	}
	if !patch.Description.IsNull() || patch.AdditionalFields["extra"] == nil {
		t.Fatalf("lost explicit null or unknown fields: %#v", patch)
	}
	if err := Validate("DataPatternPatchRequestSchema", patch); err != nil {
		t.Fatal(err)
	}
	patch.Description = aisec.Value("")
	if err := Validate("DataPatternPatchRequestSchema", patch); err != nil {
		t.Fatal(err)
	}
	if err := Validate("GatewayRealtimeConnectRequestSchema", map[string]any{"model": "test", "other": 7}); err == nil {
		t.Fatal("accepted nonstring realtime parameter")
	}
}

func TestPinnedPatternCacheRetainsSuccessAndCompileErrors(t *testing.T) {
	for i := 0; i < 2; i++ {
		if ok, err := matchPattern(`^abc$`, "abc"); !ok || err != nil {
			t.Fatalf("matched=%v err=%v", ok, err)
		}
		if ok, err := matchPattern(`^abc$`, "def"); ok || err != nil {
			t.Fatalf("matched=%v err=%v", ok, err)
		}
		if _, err := matchPattern(`(?=unsupported)`, "test"); err == nil {
			t.Fatal("unsupported pinned pattern accepted")
		}
	}
}
