# Installation

## Requirements

- Go 1.22 or later

## Install

```bash
go get github.com/cdot65/prisma-airs-go
```

## Import

```go
import (
    "github.com/cdot65/prisma-airs-go/aisec"
    "github.com/cdot65/prisma-airs-go/aisec/scan"
    "github.com/cdot65/prisma-airs-go/aisec/management"
    "github.com/cdot65/prisma-airs-go/aisec/modelsecurity"
    "github.com/cdot65/prisma-airs-go/aisec/redteam"
)
```

## Dependencies

The SDK has **zero external dependencies** — it uses only Go standard library packages:

- `net/http` — HTTP client
- `crypto/hmac`, `crypto/sha256` — HMAC-SHA256 signing
- `encoding/json` — JSON serialization
- `encoding/base64` — OAuth2 Basic auth

## Verify Installation

```go
package main

import (
    "fmt"
    "github.com/cdot65/prisma-airs-go/aisec"
)

func main() {
    fmt.Println("SDK Version:", aisec.Version)
}
```
