# Skill scanning — AgentGuard API (public preview)

The `aisec/agentguard` package implements all 21 operations in the supplied
August 21, 2026 public preview schemas (version `0.1.0`). This support is
available in SDK v0.7.0. It provides scans, attack chains, vulnerabilities, CSV export,
statistics, tenant instances, skill rules, rule configuration, and trusted skill
overrides. Complete request and response models live in
`aisec/agentguard/schema`.

For a complete program that reads a scan, its findings, attack chains, and
statistics, follow [AgentGuard scanning](../examples/agentguard-scanning.md).
It includes installation and configuration for a separate application.

## Configure the client

AgentGuard uses SCM OAuth client credentials, confirmed by the owner. Credentials
resolve from constructor options, then `PANW_AGENT_GUARD_*`, then `PANW_MGMT_*`.
Both planes share one token cache and the SDK's context, retry, and error handling.
API requests include `x-tsg-id`; token and signed storage requests do not.

The preview files omit `servers` and security definitions. Supply both service
base URLs through `DataEndpoint` / `MgmtEndpoint`, or
`PANW_AGENT_GUARD_DATA_ENDPOINT` / `PANW_AGENT_GUARD_MGMT_ENDPOINT`. There are no
assumed URL defaults, and management credential fallback does not select an API
URL. Base URLs include any product prefix before `/v1`.

The locally verified TypeScript SDK supplies production bases
`https://api.apps.paloaltonetworks.com/aiag/data` and
`https://api.apps.paloaltonetworks.com/aiag/mgmt`. The data base was used for the
live ZIP scan on 2026-10-03. Pass your tenant's selected bases explicitly; this
Go preview client still requires endpoint configuration.

```go
package main

import (
    "context"
    "fmt"
    "log"
    "net/http"
    "time"

    "github.com/cdot65/prisma-airs-go/aisec/agentguard"
)

func main() {
    // Set both PANW_AGENT_GUARD_*_ENDPOINT variables and OAuth credentials.
    client, err := agentguard.NewClient(agentguard.Opts{
        HTTPClient: &http.Client{Timeout: 45 * time.Second},
    })
    if err != nil { log.Fatal(err) }
    ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
    defer cancel()
    scans, err := client.Scans.List(ctx, agentguard.ScanListOpts{
        ListOpts: agentguard.ListOpts{Limit: 10},
    })
    if err != nil { log.Fatal(err) }
    fmt.Printf("Returned %d scans\n", len(scans.Scans))
}
```

## Operations and routing

| Sub-client | Plane | Methods |
| --- | --- | --- |
| `Scans` | Data | `List`, `ExportCSV`, `Lookup`, `UploadURL`, `Get`, `ListAttackChains`, `GetAttackChain`, `UploadComplete`, `ListVulnerabilities` |
| `Statistics` | Data | `Rules`, `Scans` |
| `Instances` | Management | `Create`, `Get`, `Update`, `Delete` |
| `Rules` | Management | `List` |
| `RuleInstances` | Management | `List`, `Update` |
| `SkillOverrides` | Management | `List`, `Create`, `Delete` |

`Instances.Delete` returns a JSON receipt; `SkillOverrides.Delete` returns only
an error and accepts the documented empty 204 response. Tenant IDs are strings
and escaped as one path segment. Scan, chain, and override IDs must be UUIDs.
`Lookup` requires a 64-character lowercase hexadecimal SHA-256 fingerprint.

## Upload and inspect an archive

1. Call `Scans.UploadURL(ctx)` without a request body. It returns `ScanUUID`,
   `UploadURL`, and `UploadExpiresAt`.
2. Upload your archive to that signed URL according to the service's upload
   requirements, using a separate HTTP request. The preview does not specify
   the storage upload method or headers. OAuth credentials belong to the API;
   the SDK does not forward them to storage or automatically follow the URL.

   The 2026-10-03 live reservation returned a Google Cloud Storage URL signing
   `content-type;host`. Uploading the unchanged ZIP with `PUT` and
   `Content-Type: application/zip` returned 200. An additional unsigned
   `x-goog-hash` header was rejected; compare the storage response's CRC32C with
   the local archive checksum and pass that checksum to `UploadComplete`.
3. Call `Scans.UploadComplete(ctx, scanUUID, request, options)` with a name and
   optional Git URL, device metadata, and base64 CRC32C checksum. The optional
   artifact type is a query parameter.
4. Call `Scans.Get`, `ListVulnerabilities`, or `ListAttackChains` explicitly.
   Polling and archive preparation belong to the caller.

```go
request := schema.AgentGuardUploadCompleteRequest{
    Name: "my-skill",
    GitURL: aisec.Value("https://example.com/team/skill"),
    ChecksumCrc32c: aisec.Value("yZRlqg=="),
}
scan, err := client.Scans.UploadComplete(ctx, scanUUID, request,
    agentguard.UploadCompleteOpts{}) // artifact auto-detection
```

Import `aisec` and `aisec/agentguard/schema` for the snippet above.
`aisec.Optional[T]` preserves omitted fields, explicit `null`, and values.
Instance creation permits free-form metadata and top-level extensions through
`AdditionalFields`; typed fields take precedence over extension keys.

## Filters, pagination, and CSV

Zero options retain server defaults. `ListOpts` provides `Limit` and `Skip`;
the API defaults to 10 scans/rules, 50 overrides, and 500 findings/attack chains.
Setting a limit sends the offset even when zero. Scan and override list limits
are capped at 100 by the API; attack-chain and vulnerability lists have no
maximum in the preview. Other constraints are validated by the service.

`ScanFilter` provides sorting, search, status, artifact type, fingerprint, and
RFC3339 time bounds. `Statuses` and `ArtifactTypes` use repeated query parameters.
`VulnerabilityListOpts.InChain` is a `*bool`: `nil` omits the filter, and a pointer
to `false` selects vulnerabilities outside attack chains. Override `Q` is a
broad search distinct from typed filters; the server requires at least three
characters when it is supplied.

`Scans.ExportCSV` accepts the same scan filters without pagination and returns
`CSVExport{Body, Header}`. The contract describes gzip-compressed CSV; the body
contains the bytes returned by your configured HTTP transport. Go's default
transport may decompress responses carrying `Content-Encoding: gzip`.

## Policy and statistics

`RuleInstances.Update` atomically changes rule states in the tenant's singleton
skill security group. `RuleConfigurations` maps rule UUIDs to desired
`schema.SkillSecurityRuleConfiguration` values (`DISABLED`, `ALLOWING`, or
`BLOCKING`); the preview requires 1–100 entries. A skill override trusts an exact
fingerprint with an `ALLOW` decision, trusting user, and optional reason/original
scan UUID. Removing an override restores normal policy evaluation.

`Statistics.Rules` and `Statistics.Scans` accept a `schema.TimePeriod`; an empty
period retains the server's `30_DAYS` default. Statistics distinguish null from
zero. Unique skills count fingerprints, while findings count per scan; repeatedly
scanning a skill can add findings without adding a unique skill.

## Verification

Pinned JSON artifacts, source hashes, and all-operation HTTP tests validate
verbs, paths, planes, queries, bodies, response fields, and no-content handling.
Tests also exercise credential resolution, token reuse/refresh, cancellation,
typed HTTP failures, and omitted/null/false values. A live scan on 2026-10-03
submitted a public skill ZIP without extracting it locally, reached `COMPLETED`,
and returned `ALLOWED`, zero vulnerabilities, and zero attack chains. Upload
reservation/completion and scan/finding/chain reads were exercised; other
operations retain mock-only verification. See [API reference](../reference/api-reference.md)
and [live verification](../developer/live-verification.md).

The opt-in `TestIntegration_ArchiveScan` accepts
`PANW_AGENT_GUARD_TEST_ARCHIVE` for a local ZIP, or
`PANW_AGENT_GUARD_TEST_SCAN_UUID` to resume an existing scan without another
submission. It never opens ZIP entries. A full submission retains its scan
record because the preview exposes no scan deletion operation.

```sh
# Configure AgentGuard endpoints and OAuth credentials first.
PANW_AGENT_GUARD_TEST_ARCHIVE=/path/to/skill.zip \
  go test -race -v -tags=integration ./aisec/agentguard -run '^TestIntegration_ArchiveScan$'
```

The unreleased parity update preserves TypeScript's `isBackgroundRefresh` scan
query, including explicit false. All 21 Go preview operations remain available,
beyond the four read operations currently exposed by the TypeScript client.
