package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
)

// JSONDocument preserves a Gateway configuration returned as an object or a
// JSON-encoded string. Decode accesses its object without changing its wire form.
type JSONDocument json.RawMessage

func (x *JSONDocument) UnmarshalJSON(data []byte) error {
	if _, err := documentObject(data); err != nil {
		return err
	}
	*x = append((*x)[:0], data...)
	return nil
}
func (x JSONDocument) MarshalJSON() ([]byte, error) {
	if _, err := documentObject(x); err != nil {
		return nil, err
	}
	return append([]byte(nil), x...), nil
}

// Decode decodes the configuration object into a caller's typed value.
func (x JSONDocument) Decode(value any) error {
	b, err := documentObject(x)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, value)
}

// NewJSONDocument encodes an object for use in configuration write requests.
func NewJSONDocument(value any) (JSONDocument, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if _, err := documentObject(b); err != nil {
		return nil, err
	}
	return JSONDocument(b), nil
}
func documentObject(data []byte) ([]byte, error) {
	b := bytes.TrimSpace(data)
	if len(b) > 0 && b[0] == '"' {
		var encoded string
		if err := json.Unmarshal(b, &encoded); err != nil {
			return nil, err
		}
		b = bytes.TrimSpace([]byte(encoded))
	}
	if !json.Valid(b) || len(b) == 0 || b[0] != '{' {
		return nil, fmt.Errorf("Gateway configuration must be an object or a JSON-encoded object")
	}
	return b, nil
}
func marshalFields(value any, extra map[string]json.RawMessage, known []string) ([]byte, error) {
	b, err := internal.MarshalOptionalFields(value)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return nil, err
	}
	keys := map[string]bool{}
	for _, key := range known {
		keys[key] = true
	}
	for k, v := range extra {
		if !keys[k] {
			fields[k] = v
		}
	}
	return json.Marshal(fields)
}
func unmarshalFields(data []byte, value any, known []string) (map[string]json.RawMessage, error) {
	if err := json.Unmarshal(data, value); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	for _, key := range known {
		delete(fields, key)
	}
	return fields, nil
}
