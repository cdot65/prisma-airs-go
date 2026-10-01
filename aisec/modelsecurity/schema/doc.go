// Package schema contains the current pinned Model Security wire contracts.
// Existing modelsecurity models remain source-compatible; detailed/new methods
// return these types to preserve newer fields and nullable values. Use
// aisec.Value or aisec.Null for optional nullable updates; an unset field is
// omitted. Pointer fields distinguish omitted optional values from false/zero.
// Union types retain the original JSON and provide typed constructors/accessors.
// Generate with PATH=<go bin>:$PATH python3 scripts/schema_models.py modelsecurity.
package schema
