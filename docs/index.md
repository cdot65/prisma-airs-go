---
title: Prisma AIRS Go SDK
slug: /overview
---

Typed Go clients for Runtime Security, Model Security, Red Team, AI Gateway
management and inference, and skill scanning (AgentGuard public preview). The SDK uses the standard library, supports Go 1.22+, and is a
foundation for applications and Terraform providers.

```sh
go get github.com/cdot65/prisma-airs-go@v0.8.0
```

These docs cover two kinds of work: understanding the service boundaries and
performing a concrete API operation. Start with the path that fits your task.

## Use the SDK

For a first request, follow [Getting started](getting-started/index.md). You need
an AIRS tenant, access to the service you plan to use, and its credentials.

| Task | Guide |
| --- | --- |
| Install the module and send your first content scan | [Getting started](getting-started/index.md) |
| Choose API key, bearer token, or OAuth client credentials | [Authentication](getting-started/authentication.md) |
| Configure endpoints, deadlines, and an HTTP client | [Configuration](getting-started/configuration.md) |
| Scan prompts, responses, code, and tool events | [Runtime scanning](examples/runtime-scanning.md) |
| Create and update profiles or topics | [Profile CRUD](examples/profile-crud.md) and [topic CRUD](examples/topic-crud.md) |
| Inspect models and scan results | [Model Security example](examples/model-security.md) |
| Launch a red-team job and read reports | [Red Team scanning](examples/red-team-scanning.md) |
| Create, read, update, and delete a Gateway configuration | [Gateway CRUD](examples/gateway-crud.md) |
| Scan skills and manage AgentGuard policy (public preview) | [AgentGuard](services/agentguard-api.md) |
| Inspect existing AgentGuard skill scans and findings | [AgentGuard scanning example](examples/agentguard-scanning.md) |
| Handle omission, null, false, zero, and empty collections | [Updates and provider state](guides/provider-patterns.md) |
| Download examples or reproduce a build | [Release artifacts](developer/releases.md) |
| Diagnose a failed request | [Troubleshooting](guides/troubleshooting.md) |
| Look up a method or model | [API reference](reference/api-reference.md) |

## Understand how it works

API-key or bearer scanning and OAuth management use distinct clients. OAuth
clients share token lifecycle and response interpretation. The caller supplies
contexts and owns application policy, reconciliation, and state.

| Question | Page |
| --- | --- |
| Which client, service, and credential covers each request? | [Architecture](developer/architecture.md) |
| When do tokens refresh and requests retry? | [OAuth lifecycle](services/oauth-lifecycle.md) |
| Which errors retain HTTP status and a wrapped cause? | [Error handling](reference/error-handling.md) |
| Which operations have live evidence? | [Live verification](developer/live-verification.md) |
| How are specs, code, documentation, and releases validated? | [Development](developer/development.md) |

The v0.8.0 TypeScript parity additions include Gateway workspace/IAM
provisioning, inference, streaming, telemetry, and Runtime DLP/dashboard clients.
See [parity status](developer/typescript-parity.md) for installation and verification. The SDK performs explicit requests; a Terraform provider owns
refresh, reconciliation, dependency ordering, timeouts, and state.

The surrounding toolchain includes the [TypeScript SDK](https://cdot65.github.io/prisma-airs-sdk/),
[AIRS CLI](https://cdot65.github.io/prisma-airs-cli/), and
[AIRS Harness](https://cdot65.github.io/prisma-airs-harness/).
