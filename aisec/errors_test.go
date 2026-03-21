package aisec

import (
	"errors"
	"testing"
)

func TestErrorType_String(t *testing.T) {
	tests := []struct {
		et   ErrorType
		want string
	}{
		{ServerSideError, "AISEC_SERVER_SIDE_ERROR"},
		{ClientSideError, "AISEC_CLIENT_SIDE_ERROR"},
		{UserRequestPayloadError, "AISEC_USER_REQUEST_PAYLOAD_ERROR"},
		{MissingVariableError, "AISEC_MISSING_VARIABLE"},
		{AISecSDKInternalError, "AISEC_SDK_ERROR"},
		{OAuthError, "AISEC_OAUTH_ERROR"},
	}
	for _, tt := range tests {
		if got := tt.et.String(); got != tt.want {
			t.Errorf("ErrorType(%d).String() = %q, want %q", tt.et, got, tt.want)
		}
	}
}

func TestAISecSDKError_Error(t *testing.T) {
	err := NewAISecSDKError("something failed", ServerSideError)
	want := "AISEC_SERVER_SIDE_ERROR:something failed"
	if err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}

func TestAISecSDKError_ErrorWithoutType(t *testing.T) {
	err := &AISecSDKError{Message: "bare error"}
	if err.Error() != "bare error" {
		t.Errorf("Error() = %q", err.Error())
	}
}

func TestAISecSDKError_Unwrap(t *testing.T) {
	inner := errors.New("root cause")
	err := WrapError("wrapped", ServerSideError, inner)

	if !errors.Is(err, inner) {
		t.Error("errors.Is should find inner error")
	}

	var sdkErr *AISecSDKError
	if !errors.As(err, &sdkErr) {
		t.Error("errors.As should find AISecSDKError")
	}
	if sdkErr.ErrorType != ServerSideError {
		t.Errorf("ErrorType = %v", sdkErr.ErrorType)
	}
}

func TestAISecSDKError_Is(t *testing.T) {
	err := NewAISecSDKError("test", OAuthError)
	var target *AISecSDKError
	if !errors.As(err, &target) {
		t.Error("errors.As should match")
	}
}
