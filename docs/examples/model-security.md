# Model Security inventory

List model inventory using the data plane, then inspect scans and policy using
the appropriate sub-client. The tenant must have a Model Security license and
an OAuth client with service access.

## Before you start

Set `PANW_MODEL_SEC_CLIENT_ID`, `PANW_MODEL_SEC_CLIENT_SECRET`, and
`PANW_MODEL_SEC_TSG_ID`, or the `PANW_MGMT_*` fallbacks. Endpoint overrides are
listed in [configuration](../getting-started/configuration.md).

This example lists up to ten models and prints the returned inventory as JSON.
It does not create scans or change policy.

## 1. Read a model inventory page

```go
package main

import (
    "context"
    "encoding/json"
    "log"
    "os"
    "time"

    "github.com/cdot65/prisma-airs-go/aisec/modelsecurity"
)

func main() {
    client, err := modelsecurity.NewClient(modelsecurity.Opts{})
    if err != nil {
        log.Fatal(err)
    }
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    result, err := client.Models.List(ctx, modelsecurity.ModelListOpts{
        Limit: 10,
    })
    if err != nil {
        log.Fatal(err)
    }
    encoder := json.NewEncoder(os.Stdout)
    encoder.SetIndent("", "  ")
    if err := encoder.Encode(result); err != nil {
        log.Fatal(err)
    }
}
```

Copy this program into a module with the SDK installed, then run `go run .`.
The result is a typed `schema.ModelList`. Empty inventory is a valid result;
service access does not imply that your tenant has already scanned a model.

## 2. Inspect a model and its versions

Use a UUID returned by the inventory, not a model display name:

```go
model, err := client.Models.Get(ctx, modelUUID)
if err != nil {
    return err
}
versions, err := client.Models.ListVersions(ctx, modelUUID, modelsecurity.ModelVersionListOpts{
    Limit: 10,
})
if err != nil {
    return err
}
```

A version UUID identifies the version's file inventory:

```go
files, err := client.ModelVersions.ListFiles(ctx, versionUUID, modelsecurity.PageOpts{
    Limit: 20,
})
```

Offset-paginated methods expose `Skip` and `Limit`; snapshot methods instead use
an opaque `NextToken`. Preserve the pagination method used by that endpoint.

## 3. Inspect scans and policy

```go
scans, err := client.Scans.List(ctx, modelsecurity.ScanListOpts{Limit: 10})
if err != nil {
    return err
}
groups, err := client.SecurityGroups.List(ctx, modelsecurity.GroupListOpts{Limit: 10})
if err != nil {
    return err
}
```

`Models`, `ModelVersions`, and `Scans` route to the data plane. `CustomRules`,
`SecurityGroups`, and `SecurityRules` route to management. The two planes reuse
one OAuth lifecycle.

## Next steps

Use the [Model Security service guide](../services/model-security-api.md) for
scans, custom rules, assignments, and history. The
[complete method reference](../reference/generated/modelsecurity.md) includes
both established methods and additive complete-response variants. A “No active
license found” response is a tenant entitlement issue; see
[troubleshooting](../guides/troubleshooting.md).
