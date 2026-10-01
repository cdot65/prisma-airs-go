package internal

import (
	"encoding/json"
	"reflect"
	"strings"
)

// MarshalOptionalFields marshals an alias of a generated schema struct, then
// omits unset optional-nullable fields. Go 1.22 encoding/json cannot omit a
// value struct via omitempty, even when it implements IsZero or MarshalJSON.
func MarshalOptionalFields(value any) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil {
		return nil, err
	}
	v := reflect.ValueOf(value)
	typ := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := typ.Field(i)
		tag := strings.Split(field.Tag.Get("json"), ",")
		if len(tag) < 2 || tag[1] != "omitempty" {
			continue
		}
		if optional, ok := v.Field(i).Interface().(interface{ IsSet() bool }); ok && !optional.IsSet() {
			delete(object, tag[0])
		}
	}
	return json.Marshal(object)
}
