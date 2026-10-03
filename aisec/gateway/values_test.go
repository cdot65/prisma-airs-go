package gateway

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestDottedValuesAreImmutableAndRejectAmbiguity(t *testing.T) {
	root, err := BuildDottedObject([]DottedValueEntry{{"targets[0].provider", "@primary"}, {"retry.attempts", 3}, {`metadata.team\.name`, "blue"}})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := SetDottedValue(root, "retry.attempts", 5)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(root)
	b, _ := json.Marshal(updated)
	if !strings.Contains(string(a), `"attempts":3`) || !strings.Contains(string(b), `"attempts":5`) {
		t.Fatal("mutation or wrong assignment")
	}
	for _, entries := range [][]DottedValueEntry{{{"a", 1}, {"a", 2}}, {{"targets[1]", "missing zero"}}, {{"__proto__.key", 1}}, {{"a..b", 1}}, {{"a[0]b", 1}}, {{"a", math.NaN()}}, {{"a", nil}, {"a.b", 1}}} {
		if _, err = BuildDottedObject(entries); err == nil {
			t.Fatalf("accepted ambiguous input: %v", entries)
		}
	}
}
func TestOperationScopedSecretRedactionAndHostSettings(t *testing.T) {
	input := map[string]any{"key": "secret", "other": "retain", "configurations": map[string]any{"custom_headers": map[string]any{"Authorization": "token"}, "vertex_region": "us"}}
	redacted, err := RedactAIGatewaySecrets("integrations.create", input, "request")
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(redacted)
	if strings.Contains(string(wire), "secret") || strings.Contains(string(wire), "token") || !strings.Contains(string(wire), "retain") || input["key"] != "secret" {
		t.Fatalf("redaction=%s input=%v", wire, input)
	}
	if _, err = RedactAIGatewaySecrets("unknown", input, ""); err == nil {
		t.Fatal("unknown operation accepted")
	}
	headers := map[string]string{"X-Test": "one"}
	host, err := CustomHostConfiguration(CustomHostConfigurationOptions{Host: "http://model.internal/v1", Headers: headers})
	if err != nil || host["provider_auth_type"] != "apiKey" {
		t.Fatalf("host=%v %v", host, err)
	}
	headers["X-Test"] = "two"
	if host["custom_headers"].(map[string]string)["X-Test"] != "one" {
		t.Fatal("header aliasing")
	}
}

func TestDottedArrayOrderAndGlobalAllocationBudget(t *testing.T) {
	if _, err := BuildDottedObject([]DottedValueEntry{{"a[1]", "one"}, {"a[0]", "zero"}}); err != nil {
		t.Fatal("legitimate reordered dense array rejected:", err)
	}
	if _, err := BuildDottedObject([]DottedValueEntry{{"a[5000].b[5000]", 1}}); err == nil {
		t.Fatal("nested allocation exceeded global budget")
	}
}
