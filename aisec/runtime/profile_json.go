package runtime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
)

// JSONPresence distinguishes an omitted field, JSON null, and a present value.
type JSONPresence uint8

const (
	// JSONOmitted means the field is absent from the JSON object.
	JSONOmitted JSONPresence = iota
	// JSONNull means an explicitly null nullable field.
	JSONNull
	// JSONPresent includes false, zero, empty strings, objects, and arrays.
	JSONPresent
)

// ProfileJSON preserves additive fields and explicit JSON presence within profiles.
// Extensions cannot shadow typed fields, even when the typed field is omitted.
// Treat a profile and its maps/slices as owned by one editor; copy before sharing.
type ProfileJSON struct {
	Extensions map[string]json.RawMessage `json:"-"`
	presence   map[string]JSONPresence
	explicit   map[string]bool
	decoded    bool
}

// SetFieldPresence controls a known field using its JSON name. JSONPresent forces
// emission of zero values; JSONNull requires a nullable nil field; JSONOmitted
// suppresses the field. Invalid names/states are rejected at marshal/submission.
// Value fields remain authoritative: assigning a non-nil value after decoding a
// null array emits that value. To remove an override, use ResetFieldPresence.
func (p *ProfileJSON) SetFieldPresence(name string, presence JSONPresence) {
	// Copy on write also avoids changing the source when a profile value is copied.
	next := make(map[string]JSONPresence, len(p.presence)+1)
	for k, v := range p.presence {
		next[k] = v
	}
	next[name] = presence
	p.presence = next
	marked := make(map[string]bool, len(p.explicit)+1)
	for k, v := range p.explicit {
		marked[k] = v
	}
	marked[name] = true
	p.explicit = marked
}

// ResetFieldPresence removes an explicit override and infers presence from the
// typed value. On a decoded object, zero scalar values then become omitted.
func (p *ProfileJSON) ResetFieldPresence(name string) {
	next := make(map[string]JSONPresence, len(p.presence))
	for k, v := range p.presence {
		if k != name {
			next[k] = v
		}
	}
	p.presence = next
	marked := make(map[string]bool, len(p.explicit))
	for k, v := range p.explicit {
		if k != name {
			marked[k] = v
		}
	}
	p.explicit = marked
}

// SetExtension adds a future field, initializing extension storage as needed.
// It copies the map and input bytes; known typed fields still take precedence.
func (p *ProfileJSON) SetExtension(name string, value json.RawMessage) error {
	if !json.Valid(value) {
		return fmt.Errorf("%s: invalid extension JSON", name)
	}
	next := make(map[string]json.RawMessage, len(p.Extensions)+1)
	for k, v := range p.Extensions {
		next[k] = v
	}
	next[name] = append(json.RawMessage(nil), value...)
	p.Extensions = next
	return nil
}

// SetMaskDataInline preserves an explicitly supplied false as well as true.
func (v *DataLeakDetectionConfig) SetMaskDataInline(value bool) {
	v.MaskDataInline = value
	v.SetFieldPresence("mask-data-inline", JSONPresent)
}

// SetMaskDataInStorage preserves an explicitly supplied false as well as true.
func (v *ModelConfiguration) SetMaskDataInStorage(value bool) {
	v.MaskDataInStorage = value
	v.SetFieldPresence("mask-data-in-storage", JSONPresent)
}

// Field metadata is immutable and cached only for scoped profile model aliases.
var profileJSONFieldCache sync.Map // reflect.Type -> []profileJSONField

type profileJSONField struct {
	index     int
	name      string
	omitEmpty bool
	nullable  bool
}

func profileJSONFields(typ reflect.Type) []profileJSONField {
	if cached, ok := profileJSONFieldCache.Load(typ); ok {
		return cached.([]profileJSONField)
	}
	fields := make([]profileJSONField, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")
		if tag[0] == "-" || tag[0] == "" {
			continue
		}
		fields = append(fields, profileJSONField{i, tag[0], len(tag) > 1 && tag[1] == "omitempty", f.Tag.Get("profile") == "nullable"})
	}
	cached, _ := profileJSONFieldCache.LoadOrStore(typ, fields)
	return cached.([]profileJSONField)
}

func inferredProfilePresence(value reflect.Value, field profileJSONField, state ProfileJSON) JSONPresence {
	v := value.Field(field.index)
	if presence, ok := state.presence[field.name]; ok {
		if presence == JSONNull && field.nullable && !v.IsZero() {
			return JSONPresent
		}
		if presence == JSONPresent && (v.Kind() == reflect.Pointer || v.Kind() == reflect.Map || v.Kind() == reflect.Slice) && v.IsNil() {
			if field.nullable {
				return JSONNull
			}
			if !state.explicit[field.name] {
				return JSONOmitted
			}
		}
		return presence
	}
	// Non-nil empty slices/maps are intentionally empty, regardless of omitempty.
	if (v.Kind() == reflect.Slice || v.Kind() == reflect.Map) && !v.IsNil() {
		return JSONPresent
	}
	if v.IsZero() && (state.decoded || field.omitEmpty) {
		return JSONOmitted
	}
	if field.nullable && (v.Kind() == reflect.Pointer || v.Kind() == reflect.Map || v.Kind() == reflect.Slice) && v.IsNil() {
		return JSONNull
	}
	return JSONPresent
}

func profileHasField(value any, state ProfileJSON, name string) bool {
	for _, field := range profileJSONFields(reflect.TypeOf(value)) {
		if field.name == name {
			return true
		}
	}
	_, ok := state.Extensions[name]
	return ok
}

func profileFieldPresence(value any, state ProfileJSON, name string) JSONPresence {
	v := reflect.ValueOf(value)
	for _, field := range profileJSONFields(v.Type()) {
		if field.name == name {
			return inferredProfilePresence(v, field, state)
		}
	}
	if raw, ok := state.Extensions[name]; ok {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return JSONNull
		}
		return JSONPresent
	}
	return JSONOmitted
}

func marshalProfileObject(value any, state ProfileJSON) ([]byte, error) {
	v := reflect.ValueOf(value)
	fields := profileJSONFields(v.Type())
	known := make(map[string]bool, len(fields))
	object := make(map[string]json.RawMessage, len(fields)+len(state.Extensions))
	for _, field := range fields {
		known[field.name] = true
		presence := inferredProfilePresence(v, field, state)
		switch presence {
		case JSONOmitted:
			continue
		case JSONNull:
			if !field.nullable || !v.Field(field.index).IsZero() {
				return nil, fmt.Errorf("%s: null requires a nullable nil field", field.name)
			}
			object[field.name] = json.RawMessage("null")
		case JSONPresent:
			data, err := json.Marshal(v.Field(field.index).Interface())
			if err != nil {
				return nil, fmt.Errorf("%s: %w", field.name, err)
			}
			if err := validateProfileField(data, v.Field(field.index).Type(), field.nullable); err != nil {
				return nil, fmt.Errorf("%s: %w", field.name, err)
			}
			object[field.name] = data
		default:
			return nil, fmt.Errorf("%s: invalid JSON presence %d", field.name, presence)
		}
	}
	for name := range state.presence {
		if !known[name] {
			return nil, fmt.Errorf("unknown profile presence field %q", name)
		}
	}
	for name, data := range state.Extensions {
		if !known[name] {
			if !json.Valid(data) {
				return nil, fmt.Errorf("%s: invalid extension JSON", name)
			}
			object[name] = data
		}
	}
	return json.Marshal(object)
}

func unmarshalProfileObject(data []byte, target any) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return err
	}
	if object == nil {
		return fmt.Errorf("profile model must be a JSON object")
	}
	v := reflect.ValueOf(target).Elem()
	state := ProfileJSON{decoded: true, presence: make(map[string]JSONPresence)}
	for _, field := range profileJSONFields(v.Type()) {
		raw, ok := object[field.name]
		if !ok {
			continue
		}
		dst := v.Field(field.index)
		if err := validateProfileField(raw, dst.Type(), field.nullable); err != nil {
			return fmt.Errorf("%s: %w", field.name, err)
		}
		// UseNumber keeps arbitrary DLP rule values precise in the legacy map API.
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if err := d.Decode(dst.Addr().Interface()); err != nil {
			return fmt.Errorf("%s: %w", field.name, err)
		}
		presence := JSONPresent
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			presence = JSONNull
		}
		state.presence[field.name] = presence
		delete(object, field.name)
	}
	state.Extensions = object // Always writable after successful object decoding.
	v.FieldByName("ProfileJSON").Set(reflect.ValueOf(state))
	return nil
}

// validateProfileField closes encoding/json's permissive null handling for
// known scalars/objects and non-nullable arrays, without constraining extensions.
func validateProfileField(raw []byte, typ reflect.Type, nullable bool) error {
	raw = bytes.TrimSpace(raw)
	if typ == reflect.TypeOf(json.RawMessage{}) {
		return nil
	}
	if bytes.Equal(raw, []byte("null")) {
		if nullable {
			return nil
		}
		return fmt.Errorf("null is not allowed")
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		return json.Unmarshal(raw, &object)
	case reflect.Map:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			return err
		}
		// rule1/rule2 are the only profile fields with map[string]any types.
		if action, ok := object["action"]; ok {
			if err := validateProfileField(action, reflect.TypeOf(""), false); err != nil {
				return fmt.Errorf("action: %w", err)
			}
		}
	case reflect.Slice:
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return err
		}
		for i, item := range items {
			if err := validateProfileField(item, typ.Elem(), false); err != nil {
				return fmt.Errorf("item %d: %w", i, err)
			}
		}
	default:
		if err := json.Unmarshal(raw, reflect.New(typ).Interface()); err != nil {
			return err
		}
	}
	return nil
}

// marshalProfileRequest validates/encodes a scoped profile once. Passing the raw
// JSON to DoMgmtRequest avoids walking the policy twice and keeps OAuth transport
// centralized. Callers classify local serialization errors as payload errors.
type profileRequest interface {
	CreateProfileRequest | UpdateProfileRequest
}

func marshalProfileRequest[T profileRequest](req T) (json.RawMessage, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("invalid security profile request: %w", err)
	}
	return json.RawMessage(body), nil
}
