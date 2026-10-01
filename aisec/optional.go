package aisec

import (
	"bytes"
	"encoding/json"
)

// Optional represents an omitted field, an explicit JSON null, or a value.
// It is used by current-schema models whose generated MarshalJSON methods omit
// unset fields. Plain encoding/json does not omit an unset Optional in a caller's
// own struct: callers must implement their containing struct's omission policy.
type Optional[T any] struct {
	set   bool
	value *T
}

// Value sets a field, including an explicit empty string, zero, or false.
func Value[T any](value T) Optional[T] { return Optional[T]{set: true, value: &value} }

// Null sets a field to JSON null, such as clearing a nullable configuration.
func Null[T any]() Optional[T] { return Optional[T]{set: true} }

// IsSet reports whether the field was provided, including explicit null.
func (o Optional[T]) IsSet() bool { return o.set }

// IsNull reports an explicitly provided JSON null.
func (o Optional[T]) IsNull() bool { return o.set && o.value == nil }

// Get returns the non-null value and whether it exists.
func (o Optional[T]) Get() (T, bool) {
	if o.value != nil {
		return *o.value, true
	}
	var zero T
	return zero, false
}

// MarshalJSON encodes the value or null. Containing generated models omit unset
// fields before returning the final object.
func (o Optional[T]) MarshalJSON() ([]byte, error) { return json.Marshal(o.value) }

// UnmarshalJSON records explicit null separately from a missing field.
func (o *Optional[T]) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		*o = Null[T]()
		return nil
	}
	var value T
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*o = Value(value)
	return nil
}
