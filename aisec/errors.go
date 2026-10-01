package aisec

import (
	"errors"
	"fmt"
	"net/http"
)

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
	// StatusCode is the HTTP status of the failing response, or 0 when the
	// error did not originate from an HTTP response (validation, network, ...).
	// One exception: client-side lookups with no server endpoint (for example
	// Profiles.GetByID) report "not found" with 404 so errors.Is(err,
	// ErrNotFound) behaves identically for server and client-side misses; their
	// ErrorType remains ClientSideError.
	StatusCode int
	hasType    bool // distinguishes zero-value ErrorType from explicitly set
}

// Error implements the error interface.
func (e *AISecSDKError) Error() string {
	if e.hasType {
		return e.ErrorType.String() + ":" + e.Message
	}
	return e.Message
}

// Sentinel errors matched by errors.Is against any *AISecSDKError carrying the
// corresponding HTTP status code.
var (
	ErrBadRequest   = errors.New("aisec: bad request (400)")
	ErrUnauthorized = errors.New("aisec: unauthorized (401)")
	ErrForbidden    = errors.New("aisec: forbidden (403)")
	ErrNotFound     = errors.New("aisec: not found (404)")
	ErrConflict     = errors.New("aisec: conflict (409)")
	ErrRateLimited  = errors.New("aisec: rate limited (429)")
)

var statusSentinels = map[int]error{
	http.StatusBadRequest:      ErrBadRequest,
	http.StatusUnauthorized:    ErrUnauthorized,
	http.StatusForbidden:       ErrForbidden,
	http.StatusNotFound:        ErrNotFound,
	http.StatusConflict:        ErrConflict,
	http.StatusTooManyRequests: ErrRateLimited,
}

// Is reports whether target is the sentinel for this error's HTTP status, so
// callers can write errors.Is(err, aisec.ErrNotFound).
func (e *AISecSDKError) Is(target error) bool {
	if e.StatusCode == 0 {
		return false
	}
	sentinel, ok := statusSentinels[e.StatusCode]
	return ok && sentinel == target
}

// NewHTTPError creates an SDK error for a failed HTTP response, recording the
// status code so callers can branch on it.
func NewHTTPError(message string, errorType ErrorType, statusCode int) *AISecSDKError {
	return &AISecSDKError{
		ErrorType:  errorType,
		Message:    message,
		StatusCode: statusCode,
		hasType:    true,
	}
}

// IsNotFound reports whether err is (or wraps) an SDK error for HTTP 404, or
// one of the SDK's client-side "not found" lookups.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
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
