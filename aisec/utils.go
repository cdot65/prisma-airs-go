package aisec

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
)

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// IsValidUUID tests whether a string is a valid RFC 4122 UUID.
func IsValidUUID(value string) bool {
	return uuidRE.MatchString(value)
}

// ValidateJobID validates that a job ID is a valid UUID.
func ValidateJobID(jobID string) error {
	if !IsValidUUID(jobID) {
		return NewAISecSDKError("Invalid job id: "+jobID, UserRequestPayloadError)
	}
	return nil
}

// GeneratePayloadHash computes an HMAC-SHA256 hex digest for API key auth.
func GeneratePayloadHash(payload, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}
