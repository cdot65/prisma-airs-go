package runtime

import (
	"encoding/json"
	"testing"
)

// TestScanResponse_RequiredFieldsSerialized verifies spec-required fields
// appear in JSON output even at zero values (no omitempty).
func TestScanResponse_RequiredFieldsSerialized(t *testing.T) {
	resp := ScanResponse{}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"timeout", "error", "errors"} {
		if _, ok := m[key]; !ok {
			t.Errorf("required field %q missing from JSON", key)
		}
	}
}

func TestAsyncScanResponse_RequiredFieldsSerialized(t *testing.T) {
	resp := AsyncScanResponse{}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"received", "scan_id"} {
		if _, ok := m[key]; !ok {
			t.Errorf("required field %q missing from JSON", key)
		}
	}
}

func TestScanSummary_RequiredFieldsSerialized(t *testing.T) {
	resp := ScanSummary{}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"detections", "threats"} {
		if _, ok := m[key]; !ok {
			t.Errorf("required field %q missing from JSON", key)
		}
	}
}

func TestDlpSnippetMeta_RequiredFieldsSerialized(t *testing.T) {
	resp := DlpSnippetMeta{}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"data_pattern", "confidence_level", "occurrence"} {
		if _, ok := m[key]; !ok {
			t.Errorf("required field %q missing from JSON", key)
		}
	}
}

// TestToolDetectionFlags_BoolFalse_NotOmitted verifies that false detection
// flags are serialized (not dropped by omitempty).
func TestToolDetectionFlags_BoolFalse_NotOmitted(t *testing.T) {
	flags := ToolDetectionFlags{} // all false
	data, err := json.Marshal(flags)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{
		"injection", "url_cats", "dlp", "db_security",
		"toxic_content", "malicious_code", "agent", "topic_violation",
	} {
		v, ok := m[key]
		if !ok {
			t.Errorf("bool field %q omitted from JSON when false", key)
			continue
		}
		if v != false {
			t.Errorf("bool field %q = %v, want false", key, v)
		}
	}
}

func TestDlpSnippetObject_RequiredFieldsSerialized(t *testing.T) {
	resp := DlpSnippetObject{}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"meta", "snippets"} {
		if _, ok := m[key]; !ok {
			t.Errorf("required field %q missing from JSON", key)
		}
	}
}
