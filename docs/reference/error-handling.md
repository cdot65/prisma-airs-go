# Error Handling

The SDK uses a custom error type `AISecSDKError` with typed error categories for programmatic handling.

## Error Types

| Type | Description |
|------|-------------|
| `ServerSideError` | API returned 5xx status code |
| `ClientSideError` | API returned 4xx status code or network failure |
| `UserRequestPayloadError` | Invalid input (bad UUID, oversized content, etc.) |
| `MissingVariableError` | Required configuration value not found |
| `AISecSDKInternalError` | Internal SDK error |
| `OAuthError` | OAuth2 token fetch failure |

## Usage

```go
import (
    "errors"
    "github.com/cdot65/prisma-airs-go/aisec"
)

result, err := scanner.SyncScan(ctx, profile, content)
if err != nil {
    var sdkErr *aisec.AISecSDKError
    if errors.As(err, &sdkErr) {
        switch sdkErr.ErrorType {
        case aisec.ServerSideError:
            log.Printf("Server error (retries exhausted): %s", sdkErr.Message)
        case aisec.ClientSideError:
            log.Printf("Client error: %s", sdkErr.Message)
        case aisec.UserRequestPayloadError:
            log.Printf("Invalid input: %s", sdkErr.Message)
        case aisec.MissingVariableError:
            log.Printf("Missing config: %s", sdkErr.Message)
        case aisec.OAuthError:
            log.Printf("Auth failed: %s", sdkErr.Message)
        default:
            log.Printf("SDK error: %s", sdkErr.Message)
        }
    }
}
```

## Retry Behavior

### Retryable Errors (5xx)

Status codes 500, 502, 503, 504 are retried automatically with exponential backoff:

- **Max retries:** 5 (configurable)
- **Backoff:** `random * (2^attempt * 1000 + 1)` ms (full jitter)
- **Example timing:** ~1s, ~2s, ~4s, ~8s, ~16s

### Auth Errors (401/403)

On OAuth2-authenticated endpoints, 401 and 403 responses trigger:

1. Token cache is cleared
2. New token is fetched
3. Request is retried once
4. This does **not** consume the retry budget

### Non-Retryable Errors (4xx)

All other 4xx errors fail immediately without retry.

## Error Wrapping

All SDK errors support Go's `errors.Is` and `errors.As` for unwrapping:

```go
if errors.Is(err, context.DeadlineExceeded) {
    // request timed out
}

var sdkErr *aisec.AISecSDKError
if errors.As(err, &sdkErr) {
    // handle SDK-specific error
}
```
