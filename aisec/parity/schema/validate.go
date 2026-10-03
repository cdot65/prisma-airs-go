package schema

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/mail"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

//go:embed contracts.json
var contractJSON []byte
var once sync.Once
var contractSchemas map[string]any
var contractError error

// Validate checks a typed request against its pinned TypeScript JSON-schema shape before authentication.
// Zod-only refinements and binary inputs require the endpoint's additional validation.
func Validate(name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return ValidateJSON(name, data)
}

// ValidateJSON verifies required fields, declared types and schema constraints without returning confidential values.
func ValidateJSON(name string, data []byte) error {
	once.Do(func() {
		var d struct {
			Components struct {
				Schemas map[string]any `json:"schemas"`
			} `json:"components"`
		}
		contractError = json.Unmarshal(contractJSON, &d)
		contractSchemas = d.Components.Schemas
	})
	if contractError != nil {
		return fmt.Errorf("invalid pinned contracts: %w", contractError)
	}
	shape, ok := contractSchemas[name]
	if !ok {
		return fmt.Errorf("unknown pinned schema: %s", name)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return fmt.Errorf("invalid JSON for %s", name)
	}
	if dec.Decode(new(any)) != io.EOF {
		return fmt.Errorf("invalid trailing JSON for %s", name)
	}
	if err := validate(shape, value, 0); err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	return nil
}
func validate(raw, value any, depth int) error {
	if depth > 128 {
		return fmt.Errorf("maximum schema depth exceeded")
	}
	s, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	if ref, ok := s["$ref"].(string); ok {
		key := strings.TrimPrefix(ref, "#/components/schemas/")
		target, found := contractSchemas[key]
		if !found {
			return fmt.Errorf("unresolved schema reference")
		}
		return validate(target, value, depth+1)
	}
	if value == nil {
		if s["nullable"] == true || s["type"] == "null" || len(s) == 0 {
			return nil
		}
	}
	for _, key := range []string{"anyOf", "oneOf", "allOf"} {
		if alternatives, ok := s[key].([]any); ok {
			matches := 0
			for _, alt := range alternatives {
				if validate(alt, value, depth+1) == nil {
					matches++
				}
			}
			if (key == "anyOf" && matches == 0) || (key == "oneOf" && matches != 1) || (key == "allOf" && matches != len(alternatives)) {
				return fmt.Errorf("schema alternatives did not match")
			}
		}
	}
	if enum, ok := s["enum"].([]any); ok {
		found := false
		for _, candidate := range enum {
			if equalValue(value, candidate) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("value is outside the declared enum")
		}
	}
	if candidate, ok := s["const"]; ok && !equalValue(value, candidate) {
		return fmt.Errorf("value differs from the declared constant")
	}
	if types, ok := s["type"].([]any); ok {
		for _, typ := range types {
			copyShape := make(map[string]any, len(s))
			for k, v := range s {
				copyShape[k] = v
			}
			copyShape["type"] = typ
			if validate(copyShape, value, depth+1) == nil {
				return nil
			}
		}
		return fmt.Errorf("unexpected type")
	}
	switch s["type"] {
	case "null":
		if value != nil {
			return fmt.Errorf("expected null")
		}
	case "object":
		obj, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("expected object")
		}
		props, _ := s["properties"].(map[string]any)
		if req, ok := s["required"].([]any); ok {
			for _, key := range req {
				if _, present := obj[fmt.Sprint(key)]; !present {
					return fmt.Errorf("missing required field %s", key)
				}
			}
		}
		for key, item := range obj {
			shape, declared := props[key]
			if !declared {
				if s["additionalProperties"] == false {
					return fmt.Errorf("undeclared field %s", key)
				}
				shape = s["additionalProperties"]
			}
			if err := validate(shape, item, depth+1); err != nil {
				return fmt.Errorf("field %s: %w", key, err)
			}
		}
		if n, ok := s["minProperties"].(float64); ok && float64(len(obj)) < n {
			return fmt.Errorf("too few object properties")
		}
	case "array":
		items, ok := value.([]any)
		if !ok {
			return fmt.Errorf("expected array")
		}
		if n, ok := s["minItems"].(float64); ok && float64(len(items)) < n {
			return fmt.Errorf("too few array items")
		}
		if n, ok := s["maxItems"].(float64); ok && float64(len(items)) > n {
			return fmt.Errorf("too many array items")
		}
		for _, item := range items {
			if err := validate(s["items"], item, depth+1); err != nil {
				return err
			}
		}
	case "string":
		str, ok := value.(string)
		if !ok {
			return fmt.Errorf("expected string")
		}
		if !utf8.ValidString(str) {
			return fmt.Errorf("invalid UTF-8 string")
		}
		switch s["format"] {
		case "uuid":
			if ok, _ := regexp.MatchString(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`, str); !ok {
				return fmt.Errorf("invalid UUID")
			}
		case "date-time":
			if _, err := time.Parse(time.RFC3339Nano, str); err != nil {
				return fmt.Errorf("invalid date-time")
			}
		case "email":
			if addr, err := mail.ParseAddress(str); err != nil || addr.Address != str {
				return fmt.Errorf("invalid email")
			}
		}
		size := float64(utf8.RuneCountInString(str))
		if n, ok := s["minLength"].(float64); ok && size < n {
			return fmt.Errorf("string is too short")
		}
		if n, ok := s["maxLength"].(float64); ok && size > n {
			return fmt.Errorf("string is too long")
		}
		if p, ok := s["pattern"].(string); ok {
			matched, err := regexp.MatchString(p, str)
			if err != nil {
				return fmt.Errorf("pinned schema has an unsupported regex")
			}
			if !matched {
				return fmt.Errorf("string does not match declared pattern")
			}
		}
	case "integer", "number":
		n, ok := value.(json.Number)
		if !ok {
			return fmt.Errorf("expected number")
		}
		f, err := n.Float64()
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return fmt.Errorf("invalid number")
		}
		if s["type"] == "integer" && math.Trunc(f) != f {
			return fmt.Errorf("expected integer")
		}
		if bound, ok := s["minimum"].(float64); ok && (f < bound || (s["exclusiveMinimum"] == true && f == bound)) {
			return fmt.Errorf("number below minimum")
		}
		if bound, ok := s["maximum"].(float64); ok && (f > bound || (s["exclusiveMaximum"] == true && f == bound)) {
			return fmt.Errorf("number above maximum")
		}
		if step, ok := s["multipleOf"].(float64); ok && step > 0 {
			q := f / step
			if math.Abs(q-math.Round(q)) > 1e-9 {
				return fmt.Errorf("number is not a declared multiple")
			}
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("expected boolean")
		}
	}
	return nil
}
func equalValue(a, b any) bool {
	if n, ok := a.(json.Number); ok {
		if f, ok := b.(float64); ok {
			parsed, err := n.Float64()
			return err == nil && parsed == f
		}
	}
	return reflect.DeepEqual(a, b)
}
