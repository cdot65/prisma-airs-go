package gateway

import (
	_ "embed"
	"encoding/json"
	"sync"
)

// GatewayRedacted is the stable marker used for operation-scoped secrets.
const GatewayRedacted = "[REDACTED]"

// GatewaySecretFieldRule records one secret path, including wildcard and one-time fields.
type GatewaySecretFieldRule struct {
	Path    []string `json:"path"`
	Redact  string   `json:"redact"`
	OneTime bool     `json:"oneTime,omitempty"`
}

// GatewaySecretOperationMetadata separates request from response rules.
type GatewaySecretOperationMetadata struct{ Request, Response []GatewaySecretFieldRule }

//go:embed secret-fields.json
var secretFieldsJSON []byte
var secretFieldsOnce sync.Once
var secretFields map[string]GatewaySecretOperationMetadata
var secretFieldsErr error

// GatewaySecretFields returns a caller-owned copy of the pinned TypeScript secret catalog.
func GatewaySecretFields() (map[string]GatewaySecretOperationMetadata, error) {
	var result map[string]GatewaySecretOperationMetadata
	err := json.Unmarshal(secretFieldsJSON, &result)
	return result, err
}

// RedactAIGatewaySecrets returns a finite JSON clone with only the selected operation's secrets masked.
// Direction must be request or response. Returned SDK API values are not automatically redacted.
func RedactAIGatewaySecrets(operation string, input any, direction string) (any, error) {
	secretFieldsOnce.Do(func() { secretFieldsErr = json.Unmarshal(secretFieldsJSON, &secretFields) })
	if secretFieldsErr != nil {
		return nil, secretFieldsErr
	}
	metadata, ok := secretFields[operation]
	if !ok {
		return nil, invalidInput("unknown secret operation")
	}
	rules := metadata.Request
	switch direction {
	case "", "request":
	case "response":
		rules = metadata.Response
	default:
		return nil, invalidInput("secret direction must be request or response")
	}
	value, err := cloneFinite(input)
	if err != nil {
		return nil, err
	}
	for _, rule := range rules {
		value = applySecretRule(value, rule.Path)
	}
	return value, nil
}
func applySecretRule(value any, path []string) any {
	if len(path) == 0 {
		return GatewayRedacted
	}
	switch v := value.(type) {
	case []any:
		if path[0] == "*" {
			for i, item := range v {
				v[i] = applySecretRule(item, path[1:])
			}
		}
	case map[string]any:
		if path[0] == "*" {
			for k, item := range v {
				v[k] = applySecretRule(item, path[1:])
			}
		} else if item, ok := v[path[0]]; ok {
			v[path[0]] = applySecretRule(item, path[1:])
		}
	}
	return value
}
