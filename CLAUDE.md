# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository. For broader agent guidance (architecture details, testing patterns, common tasks), see [AGENTS.md](AGENTS.md).

## Overview

Go SDK for Palo Alto Networks Prisma AIRS — covers the full lifecycle across three service domains (AI Runtime Security, Model Security, AI Red Teaming). Port of the TypeScript `@cdot65/prisma-airs-sdk`. Zero external dependencies (stdlib only). Foundation for a Terraform provider.

## Commands

```bash
make fmt            # gofmt -s -w .
make vet            # go vet ./...
make lint           # golangci-lint run ./...
make test           # go test -race ./...
make test-coverage  # go test -race -coverprofile=coverage.out ./...
make build          # go build ./...
make check          # fmt + vet + lint + test (CI equivalent)
```

Run a single test:

```bash
go test -v ./aisec/runtime/ -run TestSyncScan
go test -v ./... -run "TestName"
```

## Architecture

**3 service domains**, 2 auth methods:

- **Runtime API — Scan** (API Key): `runtime.NewScanner(cfg)` → SyncScan, AsyncScan, QueryByScanIDs, QueryByReportIDs
- **Runtime API — Management** (OAuth2): `runtime.NewClient(opts)` → 8 sub-clients (profiles, topics, apikeys, apps, dlp, deployment, scanlogs, oauth)
- **Model Security API** (OAuth2): `modelsecurity.NewClient(opts)` → 3 sub-clients (scans, groups, rules) + GetPyPIAuth, dual endpoint
- **Red Team API** (OAuth2): `redteam.NewClient(opts)` → 5 sub-clients (scans, reports, customAttackReports, targets, customAttacks) + 7 convenience methods, dual endpoint

Key packages:

- `aisec/` — constants, config (functional options), errors (`AISecSDKError`), utils (UUID, HMAC)
- `aisec/internal/` — `DoRequest[T]`, `DoMgmtRequest[T]`, `ExecuteWithRetry`, `OAuthClient`, `ResolveOAuthConfig`
- `aisec/runtime/` — Scanner + Content (data plane) and Client + 8 sub-clients (management plane)
- `aisec/modelsecurity/` — Client + 3 sub-clients, data plane / mgmt plane split
- `aisec/redteam/` — Client + 5 sub-clients + 7 convenience methods, data plane / mgmt plane split

**Auth:** API key (HMAC-SHA256) for scans. OAuth2 client_credentials (with token caching, proactive refresh, concurrent dedup, 401/403 auto-retry) for everything else.

**Env var resolution:** constructor options → service-specific env (`PANW_MODEL_SEC_*`) → fallback env (`PANW_MGMT_*`).

## Conventions

- Go 1.22+ minimum, stdlib-only (no external deps)
- `context.Context` as first param on all API methods
- Errors wrapped with `fmt.Errorf("...: %w", err)` for unwrapping
- Custom error type: `AISecSDKError` with `ErrorType` enum (6 types)
- Tests in `_test.go` files alongside source, use `httptest.NewServer` for mocking
- golangci-lint with errcheck enabled — all error returns must be handled (use `_ =` in tests)
- Batch operations limited to 5 items max
- Package names: lowercase, no underscores
- JSON struct tags with `omitempty` on optional fields

## CI/CD

- **ci.yml**: gofmt check, go vet, golangci-lint (Go 1.24)
- **test.yml**: `go test -race` matrix: Go 1.22, 1.23, 1.24
- **mkdocs-deploy.yml**: MkDocs Material build + GitHub Pages deploy on push to main
- **release.yml**: fmt + vet + test + build + tag verification on release

## Docs

MkDocs Material site in `docs/`. Config in `mkdocs.yml`. Deployed to GitHub Pages at cdot65.github.io/prisma-airs-go/.
