package schema

import (
	"encoding/json"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
)

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
