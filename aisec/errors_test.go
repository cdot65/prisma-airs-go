package aisec

import (
	"errors"
	"fmt"
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

func TestHTTPError_SentinelsMatchByStatus(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{400, ErrBadRequest}, {401, ErrUnauthorized}, {403, ErrForbidden},
		{404, ErrNotFound}, {409, ErrConflict}, {429, ErrRateLimited},
	}
	for _, c := range cases {
		err := NewHTTPError("boom", ClientSideError, c.status)
		if !errors.Is(err, c.want) {
			t.Errorf("status %d: errors.Is(err, %v) = false", c.status, c.want)
		}
		for _, other := range []error{ErrBadRequest, ErrUnauthorized, ErrForbidden, ErrNotFound, ErrConflict, ErrRateLimited} {
			if other != c.want && errors.Is(err, other) {
				t.Errorf("status %d wrongly matches %v", c.status, other)
			}
		}
		if err.StatusCode != c.status {
			t.Errorf("StatusCode = %d", err.StatusCode)
		}
	}
}

func TestHTTPError_UnmappedAndMissingStatusMatchNothing(t *testing.T) {
	if errors.Is(NewHTTPError("x", ServerSideError, 500), ErrNotFound) {
		t.Error("500 must not match ErrNotFound")
	}
	if errors.Is(NewAISecSDKError("x", ClientSideError), ErrNotFound) || IsNotFound(NewAISecSDKError("x", ClientSideError)) {
		t.Error("an error with no status must not match any sentinel")
	}
	if IsNotFound(nil) {
		t.Error("IsNotFound(nil) = true")
	}
}

func TestHTTPError_WorksThroughWrapping(t *testing.T) {
	inner := NewHTTPError("gone", ClientSideError, 404)
	wrapped := fmt.Errorf("reading profile: %w", inner)
	if !IsNotFound(wrapped) {
		t.Error("IsNotFound should see through fmt.Errorf %w wrapping")
	}
	var sdk *AISecSDKError
	if !errors.As(wrapped, &sdk) || sdk.StatusCode != 404 {
		t.Errorf("errors.As failed: %#v", sdk)
	}
}

func TestHTTPError_MessageFormatUnchanged(t *testing.T) {
	// Downstream code (e.g. the Terraform provider) matches on error text, so
	// adding a status code must not change the rendered message.
	err := NewHTTPError("profile missing", ClientSideError, 404)
	if got, want := err.Error(), "AISEC_CLIENT_SIDE_ERROR:profile missing"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
