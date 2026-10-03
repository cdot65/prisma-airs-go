---
title: Getting started
slug: /getting-started
---

Install the Go SDK and send your first Runtime Security request. This walkthrough
uses an existing security profile and an API key. Management operations use a
separate OAuth client; that path follows the first scan.

## Before you start

You need Go 1.22 or later, an AIRS tenant with Runtime Security enabled, a scanning
API key, and the name of an existing security profile. Your tenant administrator
provides access and profile details. The [authentication guide](authentication.md)
explains which credential belongs to each service.

This walkthrough sends the example prompt to your configured AIRS scan endpoint.
It prints the response's identifiers and verdict, without logging credentials.

## 1. Create a Go module

In a new directory:

```sh
mkdir airs-first-scan
cd airs-first-scan
go mod init example.com/airs-first-scan
go get github.com/cdot65/prisma-airs-go@v0.7.0
```

The SDK uses the Go standard library. Your application does not need Node or the
documentation site's tooling.

## 2. Configure the scan connection

Set `PANW_AI_SEC_API_KEY` in your environment through your normal secret
management workflow. Set the profile name separately:

```sh
export AIRS_PROFILE_NAME=my-existing-profile
# Optional: set the scan endpoint for your region.
export PANW_AI_SEC_API_ENDPOINT=https://service.api.aisecurity.paloaltonetworks.com
```

`PANW_AI_SEC_API_TOKEN` is an alternative bearer credential. An OAuth management
client ID and secret do not replace a scanning API key. See
[configuration](configuration.md) for regional endpoints and precedence.

## 3. Send a first request

Save this complete program as `main.go`:

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "time"

    "github.com/cdot65/prisma-airs-go/aisec"
    "github.com/cdot65/prisma-airs-go/aisec/runtime"
)

func main() {
    profileName := os.Getenv("AIRS_PROFILE_NAME")
    if profileName == "" {
        log.Fatal("Set AIRS_PROFILE_NAME to an existing profile")
    }
    scanner := runtime.NewScanner(aisec.NewConfig())
    content, err := runtime.NewContent(runtime.ContentOpts{
        Prompt: "What is the capital of France?",
    })
    if err != nil {
        log.Fatal(err)
    }
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    result, err := scanner.SyncScan(ctx, runtime.AiProfile{
        ProfileName: profileName,
    }, content)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("SDK: %s\nScan: %s\nCategory: %s\nAction: %s\n",
        aisec.Version, result.ScanID, result.Category, result.Action)
}
```

Run it:

```sh
go run .
```

You should see SDK version `0.7.0`, a scan ID, a category, and an action. The
category and action depend on your profile and the service verdict; a successful
request does not imply an `allow` action. Use the verdict in your application's
policy. For a failure, start with [troubleshooting](../guides/troubleshooting.md).

## 4. Connect a management client

For profile, topic, Model Security, Red Team, or Gateway management, obtain an
OAuth client ID, client secret, and tenant service group ID with access to that
service. Set `PANW_MGMT_CLIENT_ID`, `PANW_MGMT_CLIENT_SECRET`, and
`PANW_MGMT_TSG_ID`, or use the service-specific variables.

A Runtime management read looks like this:

```go
client, err := runtime.NewClient(runtime.Opts{})
if err != nil {
    return err
}
profiles, err := client.Profiles.List(ctx, runtime.ListOpts{Limit: 10})
if err != nil {
    return err
}
for _, profile := range profiles.Items {
    fmt.Printf("%s: %s\n", profile.ProfileID, profile.ProfileName)
}
```

The SDK caches and refreshes OAuth tokens. Reuse the client across requests,
pass a context to each operation, and keep client credentials in your secret
store. See [OAuth lifecycle](../services/oauth-lifecycle.md).

## 5. Choose your next task

| Task | Continue with |
| --- | --- |
| Scan responses, code, or tool calls | [Runtime scanning](../examples/runtime-scanning.md) |
| Manage profiles and topics | [Profile CRUD](../examples/profile-crud.md), [topic CRUD](../examples/topic-crud.md) |
| Inspect model inventory and scan outcomes | [Model Security](../examples/model-security.md) |
| Run red-team assessments | [Red Team scanning](../examples/red-team-scanning.md) |
| Manage an existing Gateway workspace | [Gateway CRUD](../examples/gateway-crud.md) |
| Inspect skill scans in the AgentGuard preview | [AgentGuard scanning](../examples/agentguard-scanning.md) |
| Build a Terraform provider | [Update and state patterns](../guides/provider-patterns.md) |

The [example catalog](../examples/index.md) distinguishes complete programs from
snippets. The [API reference](../reference/api-reference.md) lists the public
clients, methods, and model packages.
