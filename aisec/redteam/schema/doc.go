// Package schema provides complete models for the pinned current Red Team and
// Network Broker contracts. Legacy redteam models remain source compatible.
//
// Optional nullable fields use aisec.Optional to preserve omission, null, and
// values. Union values expose typed constructors/accessors. The server validates
// semantic constraints and limits; string enums accept future values.
package schema
