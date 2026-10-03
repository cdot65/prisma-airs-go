package gateway

import (
	"bytes"
	"encoding/json"
	"github.com/cdot65/prisma-airs-go/aisec"
	"net/url"
	"strconv"
	"strings"
)

// CustomHostConfigurationOptions selects an OpenAI-compatible host and copied headers.
type CustomHostConfigurationOptions struct {
	Host    string
	Headers map[string]string
}

// CustomHostConfiguration builds integration settings for a self-hosted HTTP(S) endpoint.
func CustomHostConfiguration(opts CustomHostConfigurationOptions) (map[string]any, error) {
	u, err := url.Parse(opts.Host)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, invalidInput("custom host must be an absolute HTTP(S) URL")
	}
	headers := map[string]string{}
	for k, v := range opts.Headers {
		headers[k] = v
	}
	return map[string]any{"provider_auth_type": "apiKey", "custom_host": opts.Host, "custom_headers": headers}, nil
}

// DottedValueEntry assigns a native JSON value through an escaped property/array path.
type DottedValueEntry struct {
	Path  string
	Value any
}
type pathPart struct {
	property string
	index    int
	array    bool
}
type missingValue struct{}

func dottedPath(path string) ([]pathPart, error) {
	if path == "" {
		return nil, invalidInput("dotted path is required")
	}
	parts := []pathPart{}
	property := ""
	afterDot, afterIndex := false, false
	push := func() error {
		if property == "" || property == "__proto__" || property == "constructor" || property == "prototype" {
			return invalidInput("empty or unsafe dotted path segment")
		}
		parts = append(parts, pathPart{property: property})
		property = ""
		return nil
	}
	for i := 0; i < len(path); i++ {
		switch path[i] {
		case '\\':
			i++
			if i >= len(path) || !strings.ContainsRune(".[]\\", rune(path[i])) || afterIndex {
				return nil, invalidInput("invalid dotted path escape")
			}
			property += string(path[i])
			afterDot = false
		case '.':
			if property != "" {
				if err := push(); err != nil {
					return nil, err
				}
			} else if !afterIndex {
				return nil, invalidInput("empty dotted path segment")
			}
			afterDot = true
			afterIndex = false
		case '[':
			if afterDot {
				return nil, invalidInput("array index follows dot")
			}
			if property != "" {
				if err := push(); err != nil {
					return nil, err
				}
			} else if len(parts) == 0 {
				return nil, invalidInput("path must start with an object property")
			}
			closeAt := strings.IndexByte(path[i+1:], ']')
			if closeAt < 0 {
				return nil, invalidInput("unclosed array index")
			}
			closeAt += i + 1
			raw := path[i+1 : closeAt]
			index, err := strconv.Atoi(raw)
			if err != nil || index < 0 || index >= aisec.MaxDottedArrayElements || strconv.Itoa(index) != raw {
				return nil, invalidInput("invalid or oversized array index")
			}
			parts = append(parts, pathPart{index: index, array: true})
			i = closeAt
			afterIndex = true
			afterDot = false
		case ']':
			return nil, invalidInput("unexpected closing bracket")
		default:
			if afterIndex {
				return nil, invalidInput("missing dot after array index")
			}
			property += string(path[i])
			afterDot = false
		}
	}
	if property != "" {
		if err := push(); err != nil {
			return nil, err
		}
	} else if afterDot {
		return nil, invalidInput("path ends with dot")
	}
	if len(parts) > 128 {
		return nil, invalidInput("dotted path exceeds depth limit")
	}
	return parts, nil
}
func cloneFinite(value any) (any, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return nil, invalidInput("value must be finite JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var clone any
	if err = dec.Decode(&clone); err != nil {
		return nil, err
	}
	return clone, nil
}
func assignDotted(node any, parts []pathPart, value any, replace bool, budget *int) (any, error) {
	part := parts[0]
	var old any
	exists := false
	var object map[string]any
	var array []any
	if part.array {
		var ok bool
		array, ok = node.([]any)
		if !ok {
			return nil, invalidInput("array/object path conflict")
		}
		required := part.index + 1 - len(array)
		if required > 0 {
			if required > *budget {
				return nil, invalidInput("dotted array allocation exceeds its bound")
			}
			*budget -= required
		}
		for len(array) <= part.index {
			array = append(array, missingValue{})
		}
		old = array[part.index]
		_, missing := old.(missingValue)
		exists = !missing
	} else {
		var ok bool
		object, ok = node.(map[string]any)
		if !ok {
			return nil, invalidInput("object/array path conflict")
		}
		old, exists = object[part.property]
	}
	var assigned any
	if len(parts) == 1 {
		if exists && !replace {
			return nil, invalidInput("duplicate dotted path")
		}
		assigned = value
	} else {
		if !exists {
			if parts[1].array {
				old = []any{}
			} else {
				old = map[string]any{}
			}
		}
		var err error
		assigned, err = assignDotted(old, parts[1:], value, replace, budget)
		if err != nil {
			return nil, err
		}
	}
	if part.array {
		array[part.index] = assigned
		return array, nil
	}
	object[part.property] = assigned
	return object, nil
}
func dense(value any, depth int) error {
	if depth > 128 {
		return invalidInput("JSON exceeds depth limit")
	}
	switch v := value.(type) {
	case missingValue:
		return invalidInput("sparse arrays are unsupported")
	case []any:
		for _, x := range v {
			if err := dense(x, depth+1); err != nil {
				return err
			}
		}
	case map[string]any:
		for _, x := range v {
			if err := dense(x, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// BuildDottedObject constructs a finite JSON object, rejecting duplicates, conflicts and sparse arrays.
func BuildDottedObject(entries []DottedValueEntry) (map[string]any, error) {
	root := map[string]any{}
	budget := aisec.MaxDottedArrayElements
	for _, entry := range entries {
		parts, err := dottedPath(entry.Path)
		if err != nil {
			return nil, err
		}
		value, err := cloneFinite(entry.Value)
		if err != nil {
			return nil, err
		}
		if _, err = assignDotted(root, parts, value, false, &budget); err != nil {
			return nil, err
		}
	}
	if err := dense(root, 0); err != nil {
		return nil, err
	}
	return root, nil
}

// SetDottedValue returns a cloned object with one value set, leaving input unchanged.
func SetDottedValue(input map[string]any, path string, value any) (map[string]any, error) {
	clone, err := cloneFinite(input)
	if err != nil {
		return nil, err
	}
	root, ok := clone.(map[string]any)
	if !ok {
		return nil, invalidInput("input must be a JSON object")
	}
	parts, err := dottedPath(path)
	if err != nil {
		return nil, err
	}
	budget := aisec.MaxDottedArrayElements
	v, err := cloneFinite(value)
	if err != nil {
		return nil, err
	}
	if _, err = assignDotted(root, parts, v, true, &budget); err != nil {
		return nil, err
	}
	if err = dense(root, 0); err != nil {
		return nil, err
	}
	return root, nil
}
