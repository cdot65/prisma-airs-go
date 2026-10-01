package gateway

import (
	"encoding/json"
	"github.com/cdot65/prisma-airs-go/aisec"
	"net/url"
)

// APIKeyKind separates user and service key ownership.
type APIKeyKind string

const (
	APIKeyService APIKeyKind = "service"
	APIKeyUser    APIKeyKind = "user"
)

func queryValues(opts any, deepKeys []string) (url.Values, error) {
	b, err := json.Marshal(opts)
	if err != nil {
		return nil, aisec.WrapError("failed to encode Gateway query", aisec.UserRequestPayloadError, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return nil, aisec.WrapError("failed to encode Gateway query", aisec.UserRequestPayloadError, err)
	}
	query := url.Values{}
	deep := map[string]bool{}
	for _, key := range deepKeys {
		deep[key] = true
	}
	for key, raw := range fields {
		if string(raw) == "null" {
			continue
		}
		if deep[key] && len(raw) > 0 && raw[0] == '{' {
			var object map[string]json.RawMessage
			if err := json.Unmarshal(raw, &object); err != nil {
				return nil, aisec.WrapError("invalid deep-object query", aisec.UserRequestPayloadError, err)
			}
			for k, v := range object {
				query.Add(key+"["+k+"]", queryScalar(v))
			}
			continue
		}
		if len(raw) > 0 && raw[0] == '[' {
			var items []json.RawMessage
			if err := json.Unmarshal(raw, &items); err != nil {
				return nil, aisec.WrapError("invalid array query", aisec.UserRequestPayloadError, err)
			}
			for _, item := range items {
				query.Add(key, queryScalar(item))
			}
			continue
		}
		query.Add(key, queryScalar(raw))
	}
	return query, nil
}
func queryScalar(raw json.RawMessage) string {
	var value string
	if len(raw) > 0 && raw[0] == '"' && json.Unmarshal(raw, &value) == nil {
		return value
	}
	return string(raw)
}
