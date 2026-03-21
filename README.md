# prisma-airs-go

[![CI](https://github.com/cdot65/prisma-airs-go/actions/workflows/ci.yml/badge.svg)](https://github.com/cdot65/prisma-airs-go/actions/workflows/ci.yml)
[![Tests](https://github.com/cdot65/prisma-airs-go/actions/workflows/test.yml/badge.svg)](https://github.com/cdot65/prisma-airs-go/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/cdot65/prisma-airs-go.svg)](https://pkg.go.dev/github.com/cdot65/prisma-airs-go)
[![Go 1.22+](https://img.shields.io/badge/go-%3E%3D1.22-00ADD8)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Go SDK for Palo Alto Networks **Prisma AIRS** — covering the full lifecycle from configuration management to operational scanning across all three service domains: **AI Runtime Security**, **AI Red Teaming**, and **Model Security**.

## Installation

```bash
go get github.com/cdot65/prisma-airs-go
```

Requires Go 1.22+. Zero external dependencies (stdlib only).

## What's Included

| Service                 | Client                  | Auth    | Capabilities                                               |
| ----------------------- | ----------------------- | ------- | ---------------------------------------------------------- |
| **AI Runtime Security** | `scan.Scanner`          | API Key | Sync/async content scanning, prompt injection detection    |
| **Management**          | `management.Client`     | OAuth2  | Profiles, topics, API keys, apps, DLP, deployment, logs    |
| **Model Security**      | `modelsecurity.Client`  | OAuth2  | ML model scanning, security groups, rule management        |
| **AI Red Teaming**      | `redteam.Client`        | OAuth2  | Automated red team scans, reports, targets, custom attacks |

All OAuth2 services share credentials and handle token lifecycle automatically (caching, proactive refresh, 401/403 auto-retry).

## Quick Start

### AI Runtime Security — Content Scanning (API Key)

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/cdot65/prisma-airs-go/aisec"
    "github.com/cdot65/prisma-airs-go/aisec/scan"
)

func main() {
    cfg := aisec.NewConfig(aisec.WithAPIKey("YOUR_API_KEY"))
    scanner := scan.NewScanner(cfg)

    content, err := scan.NewContent(scan.ContentOpts{
        Prompt:   "What is the capital of France?",
        Response: "The capital of France is Paris.",
    })
    if err != nil {
        log.Fatal(err)
    }

    result, err := scanner.SyncScan(context.Background(), scan.AiProfile{ProfileName: "my-profile"}, content)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(result.Category) // "benign" | "malicious"
    fmt.Println(result.Action)   // "allow" | "block"
}
```

### Management — Configuration CRUD (OAuth2)

```go
import "github.com/cdot65/prisma-airs-go/aisec/management"

client, err := management.NewClient(management.Opts{}) // reads PANW_MGMT_* env vars

// 8 sub-clients available:
client.Profiles           // AI security profile CRUD
client.Topics             // Custom detection topic CRUD
client.ApiKeys            // API key lifecycle (create, list, regenerate, delete)
client.CustomerApps       // Customer application management
client.DlpProfiles        // DLP data profile listing
client.DeploymentProfiles // Deployment profile listing
client.ScanLogs           // Scan activity log queries
client.OAuth              // OAuth token management (get/invalidate)
```

### Model Security — ML Model Scanning (OAuth2)

```go
import "github.com/cdot65/prisma-airs-go/aisec/modelsecurity"

client, err := modelsecurity.NewClient(modelsecurity.Opts{}) // falls back to PANW_MGMT_* env vars

// 3 sub-clients + GetPyPIAuth convenience method
scans, _ := client.Scans.List(ctx, modelsecurity.ScanListOpts{Limit: 10})
groups, _ := client.SecurityGroups.List(ctx, modelsecurity.GroupListOpts{})
rules, _ := client.SecurityRules.List(ctx, modelsecurity.RuleListOpts{})
pypi, _ := client.GetPyPIAuth(ctx)
```

### AI Red Teaming — Automated Testing (OAuth2)

```go
import "github.com/cdot65/prisma-airs-go/aisec/redteam"

client, err := redteam.NewClient(redteam.Opts{}) // falls back to PANW_MGMT_* env vars

// 5 sub-clients + 7 convenience methods
scans, _ := client.Scans.List(ctx, redteam.ScanListOpts{Limit: 5})
targets, _ := client.Targets.List(ctx, redteam.TargetListOpts{})
categories, _ := client.Scans.GetCategories(ctx)
quota, _ := client.GetQuota(ctx) // convenience method
```

## Authentication

| Auth Method                     | Used By                                                     |
| ------------------------------- | ----------------------------------------------------------- |
| **API Key** (HMAC-SHA256)       | AI Runtime Security scans only                              |
| **OAuth2** (client_credentials) | Everything else — Management CRUD, Red Team, Model Security |

```bash
# AI Runtime Security scans
export PANW_AI_SEC_API_KEY=your-api-key

# OAuth2 (shared by Management, Red Team, Model Security)
export PANW_MGMT_CLIENT_ID=your-client-id
export PANW_MGMT_CLIENT_SECRET=your-client-secret
export PANW_MGMT_TSG_ID=1234567890
```

## Error Handling

```go
import "github.com/cdot65/prisma-airs-go/aisec"

result, err := scanner.SyncScan(ctx, profile, content)
if err != nil {
    var sdkErr *aisec.AISecSDKError
    if errors.As(err, &sdkErr) {
        fmt.Println(sdkErr.ErrorType) // aisec.ServerSideError, etc.
        fmt.Println(sdkErr.Message)
    }
}
```

Error types: `ServerSideError`, `ClientSideError`, `UserRequestPayloadError`, `MissingVariableError`, `AISecSDKInternalError`, `OAuthError`.

## Documentation

Full documentation at **[cdot65.github.io/prisma-airs-go](https://cdot65.github.io/prisma-airs-go/)** — includes API reference, service guides, OAuth lifecycle docs, and examples.

## Development

```bash
make build          # go build ./...
make test           # go test -race ./...
make test-coverage  # go test with coverage report
make lint           # golangci-lint
make check          # fmt + vet + lint + test
```

## License

MIT
