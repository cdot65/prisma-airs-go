package aisec

import "fmt"

// ErrorType classifies SDK errors by origin.
type ErrorType int

const (
	// ServerSideError indicates a 5xx response from the AIRS API.
	ServerSideError ErrorType = iota
	// ClientSideError indicates a 4xx response or network failure.
	ClientSideError
	// UserRequestPayloadError indicates invalid user-supplied input.
	UserRequestPayloadError
	// MissingVariableError indicates a required configuration value is missing.
	MissingVariableError
	// AISecSDKInternalError indicates an internal SDK error.
	AISecSDKInternalError
	// OAuthError indicates an OAuth2 token fetch failure.
	OAuthError
)

var errorTypeStrings = [...]string{
	"AISEC_SERVER_SIDE_ERROR",
	"AISEC_CLIENT_SIDE_ERROR",
	"AISEC_USER_REQUEST_PAYLOAD_ERROR",
	"AISEC_MISSING_VARIABLE",
	"AISEC_SDK_ERROR",
	"AISEC_OAUTH_ERROR",
}

// String returns the string representation matching the TS SDK enum values.
func (e ErrorType) String() string {
	if int(e) < len(errorTypeStrings) {
		return errorTypeStrings[e]
	}
	return fmt.Sprintf("UNKNOWN_ERROR_TYPE(%d)", e)
}

// AISecSDKError is the base error type for all SDK errors.
type AISecSDKError struct {
	ErrorType ErrorType
	Message   string
	Err       error // wrapped error for errors.Is/As support
	hasType   bool  // distinguishes zero-value ErrorType from explicitly set
}

// Error implements the error interface.
func (e *AISecSDKError) Error() string {
	if e.hasType {
		return e.ErrorType.String() + ":" + e.Message
	}
	return e.Message
}

// Unwrap supports errors.Is and errors.As.
func (e *AISecSDKError) Unwrap() error {
	return e.Err
}

// NewAISecSDKError creates a new SDK error with the given message and type.
func NewAISecSDKError(message string, errorType ErrorType) *AISecSDKError {
	return &AISecSDKError{
		ErrorType: errorType,
		Message:   message,
		hasType:   true,
	}
}

// WrapError creates a new SDK error wrapping an existing error.
func WrapError(message string, errorType ErrorType, err error) *AISecSDKError {
	return &AISecSDKError{
		ErrorType: errorType,
		Message:   message,
		Err:       err,
		hasType:   true,
	}
}
