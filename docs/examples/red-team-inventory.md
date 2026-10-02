# Red Team inventory

Read targets and attack categories before creating a red-team assessment. This
complete program performs reads only; launching a job is an explicit later step.

## Before you start

Set `PANW_RED_TEAM_CLIENT_ID`, `PANW_RED_TEAM_CLIENT_SECRET`, and
`PANW_RED_TEAM_TSG_ID`, or the `PANW_MGMT_*` fallbacks. The OAuth client needs
Red Team service access in the selected tenant.

## 1. List targets and categories

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/cdot65/prisma-airs-go/aisec/redteam"
)

func main() {
    client, err := redteam.NewClient(redteam.Opts{})
    if err != nil {
        log.Fatal(err)
    }
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    targets, err := client.Targets.List(ctx, redteam.TargetListOpts{Limit: 10})
    if err != nil {
        log.Fatal(err)
    }
    for _, target := range targets.Data {
        fmt.Printf("Target: %s (%s)\n", target.Name, target.UUID)
    }
    categories, err := client.Scans.GetCategories(ctx)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Attack categories: %d\n", len(categories))
}
```

Run it from a Go module with the SDK installed. An empty target list is valid.
A listed target's UUID is the identifier for subsequent reads and jobs; its
status and connection settings determine whether an assessment can run.

## 2. Read an existing assessment

```go
job, err := client.Scans.Get(ctx, jobUUID)
if err != nil {
    return err
}
report, err := client.Reports.GetStaticReport(ctx, jobUUID)
if err != nil {
    return err
}
```

A queued or running job may not yet have a report. The caller owns polling and
its deadline. Reuse your client and bind each request to a context.

## 3. Launch an assessment when ready

Follow [Red Team scanning](red-team-scanning.md) for target creation, connectivity
probes, job creation, progress, reports, and remediation. Those steps create
resources and send attacks to the configured target application.

The SDK also exposes custom attacks, adapters, provider catalogs, versioned
reports, and Network Broker methods. See the
[service guide](../services/red-team-api.md) and
[complete reference](../reference/generated/redteam.md). The current upstream
scan-metadata limitation is recorded in [live verification](../developer/live-verification.md).
