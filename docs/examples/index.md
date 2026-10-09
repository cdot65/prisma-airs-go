---
title: Examples
slug: /examples
---

Start with an operation you want to perform. Complete programs include imports
and `main`; snippets show individual calls and assume an initialized client and
context. Every complete Go program in these guides is compiled by documentation
checks.

## Choose an example

| Task | Guide | What it does |
| --- | --- | --- |
| Send your first scan | [Getting started](../getting-started/index.md) | Complete program with a deadline and existing profile |
| Scan content and tool events | [Runtime scanning](runtime-scanning.md) | Prompt, response, async, batch queries, and tool-event snippets |
| Manage security profiles | [Profile CRUD](profile-crud.md) | Create, read, update, revisions, and force delete |
| Manage custom topics | [Topic CRUD](topic-crud.md) | Topic creation, profile references, and deletion |
| Rotate Runtime API keys | [API-key rotation](api-key-rotation.md) | Explicit key lifecycle and one-time secret handling |
| Inspect model inventory | [Model Security](model-security.md) | Complete read program and scan/rule follow-up calls |
| Inspect red-team targets | [Red Team inventory](red-team-inventory.md) | Complete read program before launching an assessment |
| Run red-team jobs | [Red Team scanning](red-team-scanning.md) | Targets, job progress, reports, and remediation |
| Manage Gateway configuration | [Gateway CRUD](gateway-crud.md) | Full create/read/update/delete flow for an owned test configuration |
| Inspect AgentGuard skill scans (public preview) | [AgentGuard scanning](agentguard-scanning.md) | Complete read program for scans, findings, attack chains, and statistics |
| Prepare provider updates | [Provider patterns](../guides/provider-patterns.md) | Nullable values, empty collections, reads, and state |

## Run a complete program

Create a Go module, install the pinned SDK, and copy a complete example into
`main.go`:

```sh
go mod init example.com/airs-example
go get github.com/cdot65/prisma-airs-go@v0.9.0
go run .
```

Set only the credentials and identifiers that the guide names. Read examples do
not create resources. CRUD and assessment examples make the operations described
in their steps; use resources you own and retain their returned identifiers.

AgentGuard public preview support is included in v0.7.0. Its example requires
SCM OAuth credentials and explicit data-plane and management-plane endpoints.

## Use the shipped executables

Each release, including v0.9.0, includes `basic-scan`, `profile-crud`, and `gateway-read`
executables for Linux, macOS, and Windows, on amd64 and arm64. Start with `-help`
and `-version` after [verifying the release checksums](../developer/releases.md).
The Go source lives under `examples/` in the SDK repository.

## Check your result

A successful HTTP request and a successful security outcome are different
results. Inspect verdicts, job status, and stored resource state explicitly.
Create receipts may contain an ID or one-time secret rather than the full read
model. Follow the read call where the guide requires it. The
[live verification record](../developer/live-verification.md) states which
operations were exercised and which helpers remain mock-only.
