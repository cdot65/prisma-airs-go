# AgentGuard scanning (public preview)

Use the AgentGuard client to inspect skill scans, vulnerabilities, attack chains,
and scan statistics. This example reads existing scans and uses the public preview
API described in the [AgentGuard service guide](../services/agentguard-api.md).

## Before you start

AgentGuard public preview support is included in SDK v0.7.0. Install it in a
separate Go application:

```sh
go mod init example.com/agentguard-example
go get github.com/cdot65/prisma-airs-go@v0.8.0
```

Supply SCM OAuth credentials with access to an AgentGuard preview tenant through
`PANW_AGENT_GUARD_CLIENT_ID`, `PANW_AGENT_GUARD_CLIENT_SECRET`, and
`PANW_AGENT_GUARD_TSG_ID`, or their `PANW_MGMT_*` fallbacks. Set both
`PANW_AGENT_GUARD_DATA_ENDPOINT` and `PANW_AGENT_GUARD_MGMT_ENDPOINT` to the
service base URLs supplied for your tenant. The preview schemas omit server
URLs, so the SDK has no default URLs for this product.

Optionally set `AGENTGUARD_SCAN_UUID` to inspect a particular existing scan.
Otherwise, the program selects the first completed scan from the newest results.
The list call returns one page; an empty page means there is no matching scan to
inspect in that response.

## Inspect a completed scan

Save this complete program as `main.go`:

```go
package main

import (
    "context"
    "fmt"
    "log"
    "net/http"
    "os"
    "time"

    "github.com/cdot65/prisma-airs-go/aisec/agentguard"
    "github.com/cdot65/prisma-airs-go/aisec/agentguard/schema"
)

func main() {
    client, err := agentguard.NewClient(agentguard.Opts{
        HTTPClient: &http.Client{Timeout: 45 * time.Second},
    })
    if err != nil { log.Fatal(err) }
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
    defer cancel()

    scanUUID := os.Getenv("AGENTGUARD_SCAN_UUID")
    if scanUUID == "" {
        scans, err := client.Scans.List(ctx, agentguard.ScanListOpts{
            ListOpts: agentguard.ListOpts{Limit: 10},
            ScanFilter: agentguard.ScanFilter{
                Status: schema.AgentGuardScanStatusCompleted,
                SortOrder: schema.SortDirectionDesc,
            },
        })
        if err != nil { log.Fatal(err) }
        if len(scans.Scans) == 0 {
            fmt.Println("No completed scans returned; upload and analyze a skill first.")
            return
        }
        scanUUID = scans.Scans[0].UUID
    }

    scan, err := client.Scans.Get(ctx, scanUUID)
    if err != nil { log.Fatal(err) }
    fmt.Printf("Scan %s: %s (%s)\n", scan.UUID, scan.Name, scan.Status)
    if scan.Status != schema.AgentGuardScanStatusCompleted {
        fmt.Println("Analysis is not complete; inspect its status again later.")
        return
    }

    findings, err := client.Scans.ListVulnerabilities(ctx, scanUUID,
        agentguard.VulnerabilityListOpts{
            ListOpts: agentguard.ListOpts{Limit: 500},
        })
    if err != nil { log.Fatal(err) }
    chains, err := client.Scans.ListAttackChains(ctx, scanUUID,
        agentguard.ListOpts{Limit: 500})
    if err != nil { log.Fatal(err) }
    fmt.Printf("Returned findings: %d; attack chains: %d\n",
        len(findings.Vulnerabilities), len(chains.AttackChains))

    stats, err := client.Statistics.Scans(ctx, schema.TimePeriodValue30Days)
    if err != nil { log.Fatal(err) }
    fmt.Printf("Last 30 days: %d unique skills; %d findings\n",
        stats.UniqueSkillsScanned.Count, stats.TotalVulnerabilitiesFound.Count)
}
```

Run it with `go run .`. The program reports status and returned page sizes.
A completed scan can still contain vulnerabilities or have a blocked policy
outcome. Inspect `EvalOutcome`, `EvalSummary`, and `EvalDetails` when your
application decides whether to trust the scanned skill. Follow additional pages
with `Skip` when the response represents more findings or chains than the page
contains.

## Upload a new skill

The API separates upload reservation from analysis:

1. Call `client.Scans.UploadURL(ctx)` to obtain a scan UUID and signed upload URL.
2. Upload the archive using the storage method and headers specified by your
   service integration. The supplied preview does not define that storage
   request, and the SDK does not follow the signed URL automatically.
3. Call `client.Scans.UploadComplete` with the returned scan UUID, a name, and
   optional Git URL, device metadata, and checksum. Reuse that UUID to inspect
   status and findings.

```go
scan, err := client.Scans.UploadComplete(ctx, scanUUID,
    schema.AgentGuardUploadCompleteRequest{Name: "my-skill"},
    agentguard.UploadCompleteOpts{ArtifactType: schema.ArtifactTypeSkill})
if err != nil {
    return err
}
```

This snippet assumes the archive upload has already completed. The SDK makes
each requested API call explicitly; your application owns polling and deadlines.

## Export and policy follow-up

`client.Scans.ExportCSV(ctx, filter)` returns response bytes and headers for
matching scans. See the [service guide](../services/agentguard-api.md#filters-pagination-and-csv)
for gzip and HTTP transport behavior.

Use `client.Rules.List` and `client.RuleInstances.List` to inspect policy before
changing it. `RuleInstances.Update` changes configured rule states atomically;
`SkillOverrides.Create` trusts a fingerprint, and `SkillOverrides.Delete` removes
that trust. Those calls change tenant policy and are separate from the read
program above. The service guide documents their request models and nullable
fields.

The example is compiled by documentation checks. A live public ZIP scan on
2026-10-03 exercised upload reservation/completion and scan/finding/chain reads
without extracting the ZIP locally, with `COMPLETED` and `ALLOWED` results.
Other preview operations retain mock-only coverage. See
[live verification](../developer/live-verification.md#agentguard-public-preview--2026-10-03)
and the [AgentGuard API reference](../reference/generated/agentguard.md).
