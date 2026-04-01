# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project

Go SDK for Palo Alto Networks Prisma AIRS. Port of TypeScript `@cdot65/prisma-airs-sdk`. Zero external dependencies (stdlib only). Foundation for a Terraform provider.

## Quick Reference

```bash
make check          # fmt + vet + lint + test — run before every commit
make test           # go test -race ./...
make lint           # golangci-lint run ./...
go test -v ./aisec/runtime/ -run TestSyncScan   # single test
```

## Repository Layout

```
aisec/                      # Core package: constants, config, errors, utils
  internal/                 # Private: HTTP client, retry, OAuth client
  runtime/                  # Runtime API — Scanner (API key) + Client with 8 sub-clients (OAuth2)
  modelsecurity/            # Model Security API — 3 sub-clients, dual endpoint (OAuth2)
  redteam/                  # Red Team API — 7 sub-clients, dual endpoint (OAuth2)
docs/                       # MkDocs Material source
.github/workflows/          # CI (lint/test), test matrix (Go 1.22-1.24), mkdocs deploy, release
examples/                   # Usage examples
```

## Architecture

Three service domains, two auth methods:

| Domain | Package | Auth | Entry Point |
|--------|---------|------|-------------|
| AI Runtime Security (scan) | `aisec/runtime` | API Key (HMAC-SHA256) | `runtime.NewScanner(cfg)` |
| AI Runtime Security (mgmt) | `aisec/runtime` | OAuth2 client_credentials | `runtime.NewClient(opts)` |
| Model Security | `aisec/modelsecurity` | OAuth2 client_credentials | `modelsecurity.NewClient(opts)` |
| Red Team | `aisec/redteam` | OAuth2 client_credentials | `redteam.NewClient(opts)` |

OAuth2 services use dual endpoints (data plane + management plane) where applicable. Token lifecycle is automatic: caching, proactive refresh (30s buffer), concurrent deduplication, 401/403 auto-retry.

Internal package (`aisec/internal/`) is not part of the public API. It provides:
- `DoRequest[T]` — generic HTTP client with HMAC signing for scan API
- `DoMgmtRequest[T]` — generic HTTP client with OAuth bearer for management APIs
- `ExecuteWithRetry` — exponential backoff with full jitter
- `OAuthClient` — token lifecycle (cache, refresh, dedup)
- `ResolveOAuthConfig` — credential resolution: explicit → primary env → fallback env

## Coding Conventions

- **Go 1.22+**, stdlib only — no external dependencies
- **`context.Context`** as first parameter on all API methods
- **Errors**: wrap with `fmt.Errorf("...: %w", err)`, use `AISecSDKError` for SDK-specific errors
- **Tests**: `_test.go` alongside source, `httptest.NewServer` for HTTP mocking, race detector always on
- **JSON**: struct tags for marshaling, `omitempty` on optional fields
- **Formatting**: `gofmt -s` enforced by CI, golangci-lint with errcheck enabled
- **Packages**: lowercase, no underscores
- **Batch limits**: 5 items max

## Environment Variables

Credentials resolve in order: constructor options → service-specific env → fallback env.

| Prefix | Service | Fallback |
|--------|---------|----------|
| `PANW_AI_SEC_` | Runtime scan API | — |
| `PANW_MGMT_` | Runtime management API | — |
| `PANW_MODEL_SEC_` | Model Security | `PANW_MGMT_` |
| `PANW_RED_TEAM_` | Red Team | `PANW_MGMT_` |

Suffixes: `_CLIENT_ID`, `_CLIENT_SECRET`, `_TSG_ID`, `_TOKEN_ENDPOINT`, `_DATA_ENDPOINT`, `_MGMT_ENDPOINT`.

## CI/CD

| Workflow | Trigger | What |
|----------|---------|------|
| `ci.yml` | push/PR | gofmt check, go vet, golangci-lint (Go 1.24) |
| `test.yml` | push/PR | `go test -race` matrix: Go 1.22, 1.23, 1.24 |
| `mkdocs-deploy.yml` | push to main | Build + deploy docs to GitHub Pages |
| `release.yml` | release created | fmt + vet + test + build + tag verify |

## Testing Patterns

All API clients are tested with dual mock servers (token server + API server):

```go
func newTestServers(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *httptest.Server) {
    tokenServer := httptest.NewServer(...)  // returns {"access_token": "test-token", ...}
    apiServer := httptest.NewServer(...)    // validates Bearer auth, delegates to handler
    return tokenServer, apiServer
}
```

Scan API tests use a single mock server with API key validation.

## Common Tasks

### Adding a new API method

1. Add the model types to `models.go` (or `scan_models.go` for scan types) in `aisec/runtime/`
2. Write a failing test in `client_test.go` or `scanner_test.go` (RED)
3. Implement the method in `client.go` or `scanner.go` (GREEN)
4. Run `make check` — must pass before committing
5. Update docs if the method is user-facing

### Adding a new sub-client

1. Add types to `models.go`
2. Add the client struct and methods to `client.go`
3. Wire it into the parent `Client` struct and `NewClient()` constructor
4. Add tests for all methods
5. Update `TestSubClients_AllPresent` to include the new sub-client

### Updating constants

All API paths, endpoints, env var names, and limits live in `aisec/constants.go`. Tests in `aisec/constants_test.go` verify values — update both.
