// Package schema models the pinned Gateway CRUD contracts and recorded SCM
// compatibility fields. Optional nullable fields use aisec.Optional. Additional
// fields are preserved as raw JSON without overriding known typed fields.
// Configuration documents preserve object or JSON-encoded string wire forms.
// The service validates semantic constraints and string enums accept new values.
package schema
