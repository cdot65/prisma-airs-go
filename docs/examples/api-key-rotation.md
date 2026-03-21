# API Key Rotation

This example demonstrates end-to-end API key management using the Management API.

## Prerequisites

```bash
export PANW_MGMT_CLIENT_ID=your-client-id
export PANW_MGMT_CLIENT_SECRET=your-client-secret
export PANW_MGMT_TSG_ID=1234567890
```

## Full Rotation Script

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/cdot65/prisma-airs-go/aisec/management"
)

func main() {
    ctx := context.Background()
    client := management.NewClient(management.Opts{})

    // 1. List existing keys
    keys, err := client.ApiKeys.List(ctx, management.ListOpts{Limit: 100})
    if err != nil {
        log.Fatal("Failed to list keys:", err)
    }
    fmt.Printf("Found %d API keys\n", len(keys.Items))

    // 2. Identify expiring keys (within 7 days)
    threshold := time.Now().Add(7 * 24 * time.Hour)
    for _, key := range keys.Items {
        if key.ExpiresAt.Before(threshold) {
            fmt.Printf("Key %s expires at %s — regenerating\n",
                key.ApiKeyName, key.ExpiresAt.Format(time.RFC3339))

            // 3. Regenerate the key
            newKey, err := client.ApiKeys.Regenerate(ctx, key.ApiKeyID, management.RegenerateKeyRequest{
                UpdatedBy: "rotation-script",
            })
            if err != nil {
                log.Printf("Failed to regenerate %s: %v", key.ApiKeyName, err)
                continue
            }
            fmt.Printf("Regenerated key %s (new ID: %s)\n",
                newKey.ApiKeyName, newKey.ApiKeyID)
        }
    }

    // 4. Optionally delete old/unused keys
    // resp, err := client.ApiKeys.Delete(ctx, "old-key-name", "admin@example.com")

    fmt.Println("Rotation complete")
}
```

## Error Handling

```go
import "github.com/cdot65/prisma-airs-go/aisec"

newKey, err := client.ApiKeys.Regenerate(ctx, keyID, request)
if err != nil {
    var sdkErr *aisec.AISecSDKError
    if errors.As(err, &sdkErr) {
        switch sdkErr.ErrorType {
        case aisec.ClientSideError:
            log.Printf("Key not found or invalid: %s", sdkErr.Message)
        case aisec.OAuthError:
            log.Printf("Auth failed: %s", sdkErr.Message)
        default:
            log.Printf("SDK error: %s", sdkErr.Message)
        }
    }
}
```
