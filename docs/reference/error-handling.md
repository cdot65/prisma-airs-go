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

### Retryable Errors (429 and 5xx)

Status codes 429, 500, 502, 503, 504 are retried automatically with exponential backoff:

- **Max retries:** 5 (configurable)
- **Backoff:** `random * (2^attempt * 1000 + 1)` ms (full jitter)
- **Example timing:** ~1s, ~2s, ~4s, ~8s, ~16s
- **`Retry-After`:** when the server sends it (seconds or an HTTP date), it replaces the computed backoff for that attempt, capped at 30 seconds
- **Cancellation:** backoff sleeps end immediately when the request's `context` is cancelled

### Auth Errors (401/403)

On OAuth2-authenticated endpoints, 401 and 403 responses trigger:

1. Token cache is cleared
2. New token is fetched
3. Request is retried **once**
4. This single refresh does **not** consume the retry budget

If the retried request is also rejected with 401/403, the failure is treated as a genuine
authorization error (wrong TSG, missing entitlement, revoked client) and is returned to the
caller as an `*AISecSDKError` — the SDK does not keep refreshing tokens.

### Non-Retryable Errors (4xx)

All other 4xx errors fail immediately without retry.

## HTTP Status and Sentinel Errors

Errors that come from an HTTP response carry the status in `AISecSDKError.StatusCode` (0 for
errors that did not come from a response, such as validation failures). The rendered message is
unchanged. `errors.Is` matches sentinel errors by status:

| Sentinel | Status |
|----------|--------|
| `aisec.ErrBadRequest` | 400 |
| `aisec.ErrUnauthorized` | 401 |
| `aisec.ErrForbidden` | 403 |
| `aisec.ErrNotFound` | 404 |
| `aisec.ErrConflict` | 409 |
| `aisec.ErrRateLimited` | 429 |

```go
if aisec.IsNotFound(err) { // same as errors.Is(err, aisec.ErrNotFound)
    // remove from state, create, etc.
}
```

Client-side lookups that have no server endpoint (`Profiles.GetByID`, `Profiles.GetByName`,
`DlpProfiles.Get`) report a missing item the same way, so `IsNotFound` works for both.
Prefer these over matching on error text.

## Successful HTTP Responses with Invalid Bodies

OAuth operations that require structured JSON return `*aisec.AISecSDKError` with
`ErrorType == aisec.AISecSDKInternalError` if the response is malformed, contains
incompatible field types, is empty, or is JSON `null`. The result is nil; partially
decoded data is never returned as success. `StatusCode` records the successful HTTP
status (for example, 200), and JSON decoding errors preserve their cause for
`errors.As`. Unknown JSON fields remain accepted; this is decoding validation, not
full schema validation.

The SDK preserves endpoint-specific success exceptions:

| Operations | Accepted success bodies |
|------------|-------------------------|
| `Profiles.ForceDelete`, `Topics.Delete`, `Topics.ForceDelete`, `CustomAttacks.UploadPromptsCsv` | Typed JSON, plain text, or empty body; plain text yields an empty result/message |
| `Targets.Delete`, `CustomAttacks.DeletePrompt`, `SecurityGroups.Delete`, `Scans.DeleteLabels` | Typed JSON or empty body, including documented 204 responses |
| `Reports.DownloadReport`, `CustomAttacks.DownloadTemplate` | Raw bytes |

Profile force deletion and topic deletions accept both JSON strings and JSON message
objects. Text exceptions are determined by the body's shape, even if the server
mislabels plain text as `application/json` or a `+json` media type. They do not
suppress errors for malformed objects/arrays/quoted strings, markup such as HTML,
or valid JSON of the wrong type. JSON `null` is rejected even for endpoints that
allow empty bodies.

This changes earlier behavior: a successful HTTP status alone no longer guarantees
success for an operation that requires JSON. Body interpretation happens after
HTTP retry handling, so a decoding error does not retry a completed operation.

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
