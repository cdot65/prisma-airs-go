package internal

import (
	"bytes"
	"encoding/json"

	"github.com/cdot65/prisma-airs-go/aisec"
)

// ResponsePolicy describes the successful bodies an endpoint accepts.
// All policies reject JSON null, malformed JSON, and incompatible JSON types.
type ResponsePolicy int

const (
	// RequireJSON requires a non-empty JSON result. Unknown fields are accepted.
	RequireJSON ResponsePolicy = iota
	// AllowEmptyJSON also accepts an empty body (e.g. a documented 204).
	AllowEmptyJSON
	// AllowTextOrEmpty also accepts plain text and empty success bodies. Plain
	// text yields a zero-value result, preserving the legacy delete/upload behavior.
	AllowTextOrEmpty
)

// DecodeMgmtResponse interprets a fully-read successful OAuth response. JSON
// requests and multipart uploads share this implementation, so endpoint-specific
// exceptions never suppress JSON errors or expose partially decoded results.
func DecodeMgmtResponse[T any](raw *RawResponse, policy ResponsePolicy) (*Response[T], error) {
	body := bytes.TrimSpace(raw.Body)
	var data T
	if len(body) == 0 {
		if policy == RequireJSON {
			return nil, aisec.NewHTTPError("expected JSON response body, got empty body", aisec.AISecSDKInternalError, raw.Status)
		}
		return &Response[T]{Status: raw.Status, Data: data}, nil
	}
	if bytes.Equal(body, []byte("null")) {
		return nil, aisec.NewHTTPError("expected JSON response body, got null", aisec.AISecSDKInternalError, raw.Status)
	}
	if policy == AllowTextOrEmpty && plainTextResponse(body) {
		return &Response[T]{Status: raw.Status, Data: data}, nil
	}
	if err := json.Unmarshal(body, &data); err != nil {
		sdkErr := aisec.WrapError("failed to parse response JSON: "+err.Error(), aisec.AISecSDKInternalError, err)
		sdkErr.StatusCode = raw.Status
		return nil, sdkErr
	}
	return &Response[T]{Status: raw.Status, Data: data}, nil
}

// Text exceptions use the body's shape because these endpoints can mislabel
// plain text as JSON. Valid JSON, broken objects/arrays/quoted strings, and markup
// must still pass JSON decoding rather than silently succeeding as text.
func plainTextResponse(body []byte) bool {
	if json.Valid(body) {
		return false
	}
	switch body[0] {
	case '{', '[', '"', '<':
		return false
	default:
		return true
	}
}
