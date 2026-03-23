# Quick Start

## Authentication Overview

| Auth Method | Used By | Credentials |
|-------------|---------|-------------|
| **API Key** (HMAC-SHA256) | Runtime API (scanning) | `PANW_AI_SEC_API_KEY` |
| **OAuth2** (client_credentials) | Runtime (management), Model Security, Red Team | `PANW_MGMT_CLIENT_ID`, `PANW_MGMT_CLIENT_SECRET`, `PANW_MGMT_TSG_ID` |

## AI Runtime Security — Content Scanning

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/cdot65/prisma-airs-go/aisec"
    "github.com/cdot65/prisma-airs-go/aisec/runtime"
)

func main() {
    cfg := aisec.NewConfig(aisec.WithAPIKey("YOUR_API_KEY"))
    scanner := runtime.NewScanner(cfg)

    content, err := runtime.NewContent(runtime.ContentOpts{
        Prompt:   "What is the capital of France?",
        Response: "The capital of France is Paris.",
    })
    if err != nil {
        log.Fatal(err)
    }

    result, err := scanner.SyncScan(
        context.Background(),
        runtime.AiProfile{ProfileName: "my-profile"},
        content,
    )
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Category: %s\n", result.Category)
    fmt.Printf("Action: %s\n", result.Action)
    fmt.Printf("Scan ID: %s\n", result.ScanID)
}
```

## Runtime API — Profile CRUD

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/cdot65/prisma-airs-go/aisec/runtime"
)

func main() {
    client, err := runtime.NewClient(runtime.Opts{
        ClientID:     "your-client-id",
        ClientSecret: "your-client-secret",
        TsgID:        "1234567890",
    })
    if err != nil {
        log.Fatal(err)
    }

    // List security profiles
    profiles, err := client.Profiles.List(context.Background(), runtime.ListOpts{
        Limit: 10,
    })
    if err != nil {
        log.Fatal(err)
    }

    for _, p := range profiles.Items {
        fmt.Printf("Profile: %s (ID: %s)\n", p.ProfileName, p.ProfileID)
    }
}
```

## Model Security — Scans

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/cdot65/prisma-airs-go/aisec/modelsecurity"
)

func main() {
    client, err := modelsecurity.NewClient(modelsecurity.Opts{}) // reads PANW_MGMT_* env vars
    if err != nil {
        log.Fatal(err)
    }

    scans, err := client.Scans.List(context.Background(), modelsecurity.ScanListOpts{
        Limit: 10,
    })
    if err != nil {
        log.Fatal(err)
    }

    for _, s := range scans.Items {
        fmt.Printf("Scan: %s (Status: %s)\n", s.UUID, s.EvalOutcome)
    }
}
```

## Red Team — Targets and Scans

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/cdot65/prisma-airs-go/aisec/redteam"
)

func main() {
    client, err := redteam.NewClient(redteam.Opts{}) // reads PANW_MGMT_* env vars
    if err != nil {
        log.Fatal(err)
    }

    // List targets
    targets, err := client.Targets.List(context.Background(), redteam.TargetListOpts{})
    if err != nil {
        log.Fatal(err)
    }

    for _, t := range targets.Data {
        fmt.Printf("Target: %s (%s)\n", t.Name, t.UUID)
    }

    // Get attack categories
    categories, err := client.Scans.GetCategories(context.Background())
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Available categories: %d\n", len(categories))
}
```
