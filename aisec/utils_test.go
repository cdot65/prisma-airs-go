package aisec

import "testing"

func TestIsValidUUID(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"550e8400-e29b-41d4-a716-446655440000", true},
		{"ABCDEF12-3456-7890-ABCD-EF1234567890", true},
		{"not-a-uuid", false},
		{"", false},
		{"550e8400-e29b-41d4-a716-44665544000", false},   // too short
		{"550e8400-e29b-41d4-a716-4466554400000", false}, // too long
		{"550e8400e29b41d4a716446655440000", false},      // no dashes
	}
	for _, tt := range tests {
		if got := IsValidUUID(tt.input); got != tt.want {
			t.Errorf("IsValidUUID(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestGeneratePayloadHash(t *testing.T) {
	// Known test vector: HMAC-SHA256 of "hello" with key "secret"
	hash := GeneratePayloadHash("hello", "secret")
	// expected: 88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b
	expected := "88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b"
	if hash != expected {
		t.Errorf("GeneratePayloadHash = %q, want %q", hash, expected)
	}
}

func TestGeneratePayloadHash_EmptyPayload(t *testing.T) {
	hash := GeneratePayloadHash("", "key")
	if hash == "" {
		t.Error("hash should not be empty for empty payload")
	}
}

func TestValidateJobID_Valid(t *testing.T) {
	err := ValidateJobID("550e8400-e29b-41d4-a716-446655440000")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateJobID_Invalid(t *testing.T) {
	err := ValidateJobID("not-a-uuid")
	if err == nil {
		t.Error("expected error for invalid UUID")
	}
}
