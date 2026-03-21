# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Go SDK for Palo Alto Networks Prisma AIRS — covers the full lifecycle across all four service domains (AI Runtime Security, Model Security, AI Red Teaming) plus configuration management. Port of the TypeScript `@cdot65/prisma-airs-sdk`. Zero external dependencies (stdlib only).

## Commands

```bash
make fmt            # gofmt -s -w
make vet            # go vet ./...
make lint           # golangci-lint run
make test           # go test -race ./...
make test-coverage  # go test -race -coverprofile=coverage.out ./...
make build          # go build ./...
make check          # fmt + vet + lint + test (CI equivalent)
```

Run a single test file:

```bash
go test -v ./aisec/scan/ -run TestSyncScan
```

Run a single test by name:

```bash
go test -v ./... -run "TestName"
```

## Architecture

**4 service domains**, 2 auth methods:

- **Scan API** (API Key): `NewScanner()` → `SyncScan()` → AIRS content scanning endpoint
- **Management API** (OAuth2): `NewManagementClient()` → profiles/topics CRUD
- **Model Security API** (OAuth2): `NewModelSecurityClient()` → model scans, security groups, rules
- **Red Team API** (OAuth2): `NewRedTeamClient()` → scans, reports, targets, custom attacks

Key packages:

- `aisec/scan/` — Scanner, Content (API key auth)
- `aisec/management/` — ManagementClient + 8 sub-clients (profiles, topics, apikeys, apps, dlp, deployment, scanlogs, oauth)
- `aisec/modelsecurity/` — ModelSecurityClient + 3 sub-clients (scans, groups, rules)
- `aisec/redteam/` — RedTeamClient + 5 sub-clients (scans, reports, customAttackReports, targets, customAttacks)
- `aisec/internal/` — HTTP client, retry with exponential backoff, OAuth client
- `aisec/` — constants, configuration, errors, utils, models

**Auth:** API key (HMAC-SHA256) for AIRS scans. OAuth2 client_credentials for everything else.

**Validation:** Content validates at setter time, Scanner validates arguments. Models use struct tags for JSON marshaling.

## Conventions

- Go 1.22+ minimum, stdlib-only (no external deps)
- `context.Context` as first param on all API methods
- Errors wrapped with `fmt.Errorf("...: %w", err)` for unwrapping
- Custom error type: `AISecSDKError` with `ErrorType` enum
- Tests in `_test.go` files alongside source, use `httptest.NewServer` for mocking
- Exported API surface from `aisec/` package root
- Batch operations limited to 5 items max
- Package names: lowercase, no underscores

## CI/CD

- GitHub Actions test matrix: Go 1.22, 1.23, 1.24
- golangci-lint for linting
- MkDocs Material for documentation, deployed to GitHub Pages
