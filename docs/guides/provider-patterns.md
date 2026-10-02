# Updates and provider state

The SDK performs the API call you request. Your application or Terraform
provider owns refresh, reconciliation, dependency ordering, timeouts, and state.
This guide explains the wire values and lifecycle distinctions that matter for
that work.

## Distinguish omission, null, and a value

Generated current-schema models use pointers for optional non-nullable fields
and `aisec.Optional[T]` for optional nullable fields.

| Go value in a generated model | Wire meaning |
| --- | --- |
| Nil optional pointer | Omit the field |
| Pointer to `false`, `0`, or an empty collection | Send that value explicitly |
| Unset `aisec.Optional[T]` | Omit the field |
| `aisec.Null[T]()` | Send JSON `null` |
| `aisec.Value(value)` | Send the value, including empty, zero, or false |

The containing generated model implements omission. `encoding/json` alone does
not omit an unset `Optional` in a custom struct; implement your containing
struct's policy when using this helper outside the generated models.

## Inspect the update body before sending it

This complete offline program shows an MCP integration description omitted, cleared,
and set to an empty string. It makes no API requests:

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"

    "github.com/cdot65/prisma-airs-go/aisec"
    "github.com/cdot65/prisma-airs-go/aisec/gateway/schema"
)

func main() {
    updates := []schema.UpdateMCPIntegration{
        {},
        {Description: aisec.Null[string]()},
        {Description: aisec.Value("")},
    }
    for _, update := range updates {
        body, err := json.Marshal(update)
        if err != nil {
            log.Fatal(err)
        }
        fmt.Println(string(body))
    }
}
```

Expected output:

```json
{}
{"description":null}
{"description":""}
```

The `schema` types are service-specific. Import the package belonging to the
method you call; similar names in another domain are separate contracts.

## Read after a create or update receipt

Create and update receipts may differ from read models. Persist the identifier
and any one-time secret that the response exposes, then call the explicit get
method for the stored representation. Keep secrets out of logs and diagnostics.

Some identifiers change across revisions. Runtime profile updates create a new
revision with a new profile ID; use `GetByName` for the latest revision and
update provider state to the resulting ID. Gateway configuration version IDs
identify history; the configuration's resource identifier is a different value.

## Preserve whole documents

Gateway config documents can be returned as JSON objects or encoded object
strings. `schema.JSONDocument` preserves the wire form and decodes the underlying
object. `NewJSONDocument` constructs a valid object for a write.

A nested configuration document update can replace the prior document. Build the
whole intended object and retain settings you still own. Workspace/deployment
bindings can merge by default; use the endpoint's override/removal fields for
explicit replacement and removals. Consult the selected method's request model
rather than assuming every PUT follows the same policy.

## Handle deletion according to the resource

Runtime force deletes and topic deletes accept message objects, JSON strings,
plain text, or an empty response under their documented exceptions. A decode
error may follow a server-side operation that already completed. Refresh state
before deciding to repeat a write.

Gateway deployment deletion archives a record, and archived records can remain
in list results. Other resources have their own deletion behavior. Interpret
404 using `errors.Is(err, aisec.ErrNotFound)` where appropriate for your resource's
refresh policy, rather than matching error text.

## Bound refresh and reconciliation

Reuse clients, pass contexts, and inject an HTTP client when you need a transport
or overall timeout. The SDK retries configured transient failures and performs
one OAuth refresh/retry for an authorization rejection. It does not automatically
poll jobs, reconcile state, rotate secrets, create workspaces, or retry successful
HTTP responses whose bodies cannot be decoded.

The [error guide](../reference/error-handling.md),
[Gateway guide](../services/ai-gateway-api.md), and
[live evidence](../developer/live-verification.md) describe the boundaries.
