package modelsecurity

import (
	"encoding/json"
	"testing"
)

func TestScanBaseResponse_RequiredFieldsSerialized(t *testing.T) {
	resp := ScanBaseResponse{}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	required := []string{
		"tsg_id", "created_at", "updated_at", "model_uri", "owner",
		"scan_origin", "security_group_uuid", "security_group_name",
		"model_version_uuid", "eval_outcome", "source_type",
	}
	for _, key := range required {
		if _, ok := m[key]; !ok {
			t.Errorf("required field %q missing from JSON", key)
		}
	}
}

func TestRuleEvaluationResponse_RequiredFieldsSerialized(t *testing.T) {
	resp := RuleEvaluationResponse{}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	required := []string{
		"tsg_id", "created_at", "updated_at", "result", "violation_count",
		"rule_instance_uuid", "scan_uuid", "rule_name", "rule_description",
		"rule_instance_state",
	}
	for _, key := range required {
		if _, ok := m[key]; !ok {
			t.Errorf("required field %q missing from JSON", key)
		}
	}
}

func TestFileResponse_RequiredFieldsSerialized(t *testing.T) {
	resp := FileResponse{}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	required := []string{
		"tsg_id", "created_at", "updated_at", "path", "parent_path",
		"type", "result", "model_version_uuid",
	}
	for _, key := range required {
		if _, ok := m[key]; !ok {
			t.Errorf("required field %q missing from JSON", key)
		}
	}
}

func TestViolationResponse_RequiredFieldsSerialized(t *testing.T) {
	resp := ViolationResponse{}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	required := []string{
		"tsg_id", "created_at", "updated_at", "description",
		"rule_instance_uuid", "rule_name", "rule_description",
		"rule_instance_state",
	}
	for _, key := range required {
		if _, ok := m[key]; !ok {
			t.Errorf("required field %q missing from JSON", key)
		}
	}
}

func TestModelSecurityGroupResponse_RequiredFieldsSerialized(t *testing.T) {
	resp := ModelSecurityGroupResponse{}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	required := []string{
		"tsg_id", "created_at", "updated_at", "name", "description",
		"source_type", "state", "is_tombstone",
	}
	for _, key := range required {
		if _, ok := m[key]; !ok {
			t.Errorf("required field %q missing from JSON", key)
		}
	}
}

func TestModelSecurityRuleInstanceResponse_RequiredFieldsSerialized(t *testing.T) {
	resp := ModelSecurityRuleInstanceResponse{}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	required := []string{
		"tsg_id", "created_at", "updated_at", "security_group_uuid",
		"security_rule_uuid", "state", "rule",
	}
	for _, key := range required {
		if _, ok := m[key]; !ok {
			t.Errorf("required field %q missing from JSON", key)
		}
	}
}

func TestModelSecurityRuleResponse_RequiredFieldsSerialized(t *testing.T) {
	resp := ModelSecurityRuleResponse{}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	required := []string{
		"name", "description", "rule_type", "compatible_sources",
		"default_state", "remediation", "editable_fields",
		"constant_values", "default_values",
	}
	for _, key := range required {
		if _, ok := m[key]; !ok {
			t.Errorf("required field %q missing from JSON", key)
		}
	}
}

func TestPyPIAuthResponse_RequiredFieldsSerialized(t *testing.T) {
	resp := PyPIAuthResponse{}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"url", "expires_at"} {
		if _, ok := m[key]; !ok {
			t.Errorf("required field %q missing from JSON", key)
		}
	}
}
