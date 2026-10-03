# Troubleshooting

Start with the operation, service, and credential path. Record the HTTP status,
request identifier where available, and wrapped error cause. Keep credentials
and one-time secrets out of diagnostics.

## Installation or compilation

Use Go 1.22+ and install `github.com/cdot65/prisma-airs-go@v0.8.1` from a module.
The executable name and package import name are different: Runtime lives in
`aisec/runtime`; Gateway management lives in `aisec/gateway`.

If a copied snippet has undefined names, initialize the client and context that
its guide names, or start with a complete program from the
[example catalog](../examples/index.md). Schema imports belong to the service
whose method you are using.

## Missing configuration

`MissingVariableError` indicates a missing required value. Verify the exact
variable name and precedence in [authentication](../getting-started/authentication.md)
and [environment variables](../reference/environment-variables.md).

A Runtime scanning API key is different from an OAuth client ID and secret.
Gateway management requires SCM OAuth client credentials plus a TSG ID; a
workspace inference key is not a substitute for that client configuration.

## OAuth rejection or service access

| Symptom | What to verify |
| --- | --- |
| Token endpoint rejects client credentials | Client ID, secret, token endpoint, and selected TSG |
| API still returns 401/403 after refresh | Service grants, resource ownership, workspace scope, and entitlement |
| Model Security returns “No active license found” | Model Security license on the selected tenant |
| Gateway generic API-key list returns 403 | Use the documented service/user key-kind routes for the tested SCM behavior |
| A workspace integration create returns 403 | Use an org integration and an explicit workspace grant as documented |

The SDK refreshes OAuth after an API 401/403 and retries once. A second rejection
is returned to the caller. Repeating token refresh cannot create a missing grant.
The [Gateway guide](../services/ai-gateway-api.md) documents the observed SCM
routing differences; [live verification](../developer/live-verification.md)
records tenant-specific limits.

## Timeout, cancellation, or rate limiting

Every API method takes a context. Use a deadline that covers your operation and
its allowed retries. `errors.Is(err, context.DeadlineExceeded)` and
`errors.Is(err, context.Canceled)` can inspect wrapped causes when applicable.

429 and selected 5xx statuses use bounded retry/backoff. A `Retry-After` response
can replace the computed delay within the SDK's cap. Inspect `StatusCode` and
`errors.Is(err, aisec.ErrRateLimited)` when the retry budget is exhausted. See
[error handling](../reference/error-handling.md) for exact retry rules.

## A successful status with a decoding error

The server may have completed the operation before sending a body that the SDK
cannot interpret. The error retains the response's status and its JSON cause;
it can therefore carry status 200 and no HTTP-error sentinel.

Malformed JSON and wrong-type JSON are errors. Endpoint-specific text/empty
exceptions are documented in the service guides. Refresh the resource before
repeating a write after a decoding failure. The SDK does not retry body decoding.

## Empty pages or incomplete history

An empty page is a valid response when there are no matching resources. For
paginated methods, use the endpoint's offset fields or opaque cursor as declared.
Do not turn a cursor into an item count. Preserve service filters between pages.

Established convenience methods may return a subset of a current service model.
Use the additive complete-response methods and generated schema types when you
need the full contract. The [method reference](../reference/api-reference.md)
lists both forms.

## Known upstream limits

The strict live Red Team scan-metadata check currently returns upstream 422 in
the recorded environment. Some Gateway helpers require real traffic,
third-party credentials, infrastructure, or attended user consent and remain
mock-verified. A passing SDK contract check is not evidence that these dependencies
exist in a particular tenant. Read the [verification record](../developer/live-verification.md)
before planning acceptance tests.

## Prepare a reproducible issue

Include SDK version, Go version, service, method, endpoint region, HTTP status,
wrapped error type, and a minimal request with secrets removed. State whether
reading the resource after the failure showed that the write completed. Link
any response contract difference to the corresponding pinned specification or
API issue. Contributor steps are in [development](../developer/development.md).
