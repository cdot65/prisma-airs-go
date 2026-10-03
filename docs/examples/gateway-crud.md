# Gateway configuration CRUD

Create a configuration in an existing workspace, read the stored representation,
update it, inspect version history, and delete the configuration you created.
This example manages metadata; it does not send inference requests or provision
infrastructure.

## Before you start

Set `PANW_AI_GW_CLIENT_ID`, `PANW_AI_GW_CLIENT_SECRET`, and `PANW_AI_GW_TSG_ID`
(or the `PANW_MGMT_*` fallbacks). Set the existing workspace ID:

```sh
export GATEWAY_WORKSPACE_ID=your-existing-workspace-uuid
```

The SCM OAuth client needs configuration-management access to this workspace.
The example uses a unique name, prints its returned identifier, and cleans up
only its own configuration. If cleanup fails, it reports that identifier so you
can retry the deletion explicitly.

## 1. Run the complete lifecycle

Save this program as `main.go` in a Go module with v0.8.0 installed:

```go
package main

import (
    "context"
    "errors"
    "fmt"
    "log"
    "os"
    "time"

    "github.com/cdot65/prisma-airs-go/aisec/gateway"
    "github.com/cdot65/prisma-airs-go/aisec/gateway/schema"
)

func main() {
    if err := run(); err != nil {
        log.Fatal(err)
    }
}

func run() (resultErr error) {
    workspaceID := os.Getenv("GATEWAY_WORKSPACE_ID")
    if workspaceID == "" {
        return errors.New("set GATEWAY_WORKSPACE_ID to an existing workspace")
    }
    client, err := gateway.NewClient(gateway.Opts{})
    if err != nil {
        return err
    }
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
    defer cancel()

    name := fmt.Sprintf("sdk-docs-%d", time.Now().UnixNano())
    document, err := schema.NewJSONDocument(map[string]any{
        "provider": "openai",
        "retry": map[string]any{"attempts": 1},
    })
    if err != nil {
        return err
    }
    created, err := client.Configs.Create(ctx, schema.ConfigsCreateRequest{
        Name: &name, WorkspaceID: &workspaceID, Config: &document,
    })
    if err != nil {
        return err
    }
    // SCM can return a flat receipt; upstream uses the data envelope.
    identifier := ""
    candidates := []*string{created.Slug, created.ID}
    if created.Data != nil {
        candidates = append(candidates, created.Data.ID)
    }
    for _, candidate := range candidates {
        if candidate != nil && *candidate != "" {
            identifier = *candidate
            break
        }
    }
    if identifier == "" {
        return fmt.Errorf("create receipt has no identifier; locate configuration %q in workspace %s", name, workspaceID)
    }
    fmt.Printf("Created configuration: %s\n", identifier)
    deleted := false
    defer func() {
        if deleted {
            return
        }
        cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
        defer cleanupCancel()
        if _, err := client.Configs.Delete(cleanupCtx, identifier); err != nil {
            resultErr = errors.Join(resultErr, fmt.Errorf("cleanup configuration %s: %w", identifier, err))
        }
    }()

    stored, err := client.Configs.Get(ctx, identifier)
    if err != nil {
        return err
    }
    config := stored.Config
    if config == nil && stored.Data != nil {
        config = stored.Data.Config
    }
    if config == nil {
        return errors.New("stored configuration has no document")
    }
    var completeDocument map[string]any
    if err := config.Decode(&completeDocument); err != nil {
        return err
    }
    // Preserve the whole document: nested config updates replace prior contents.
    completeDocument["retry"] = map[string]any{"attempts": 0}
    updatedDocument, err := schema.NewJSONDocument(completeDocument)
    if err != nil {
        return err
    }
    updatedName := name + "-updated"
    if _, err := client.Configs.Update(ctx, identifier, schema.ConfigsUpdateRequest{
        Name: &updatedName, Config: &updatedDocument,
    }); err != nil {
        return err
    }
    if _, err := client.Configs.Get(ctx, identifier); err != nil {
        return err
    }
    if _, err := client.Configs.ListVersions(ctx, identifier); err != nil {
        return err
    }
    if _, err := client.Configs.Delete(ctx, identifier); err != nil {
        return err
    }
    deleted = true
    fmt.Println("Read, updated, inspected versions, and deleted the configuration")
    return nil
}
```

```sh
go run .
```

The program creates and deletes a configuration. To inspect existing resources
without changes, use `client.Configs.List` with `schema.ConfigsListOptions` and an
explicit workspace ID, as shown in [quick start](../getting-started/quick-start.md).

## 2. Understand receipts and documents

A create receipt may contain an ID, slug, or version ID without a complete read
model. Use `Configs.Get` to read the stored representation. SCM reads may be flat;
the upstream schema also supports a `data` envelope. `schema.JSONDocument.Decode`
handles either an object or a JSON-encoded object.

A configuration update replaces nested document contents. This example reads
and preserves the complete document before changing one field. Terraform
providers should construct the intended full document rather than applying a
partial nested patch. See [provider patterns](../guides/provider-patterns.md).

## 3. Choose another resource family

| Task | Sub-client | Important distinction |
| --- | --- | --- |
| Manage workspace or org guardrails | `Guardrails`, `OrgGuardrails` | Workspace data plane vs org admin plane |
| Bind provider integrations | `Integrations`, `Providers` | Org creation and workspace grants are separate operations |
| Manage remote tool configuration | `MCPIntegrations`, `MCPServers` | Connectivity and user authorization helpers are explicit calls |
| Manage API keys | `APIKeys` | Service/user ownership routes; create/rotate may expose one-time secrets |
| Manage consumption policy | `UsageLimits`, `RateLimits` | Counter reset is an explicit owned operation |
| Manage external secret references | `SecretReferences` | Reference metadata rather than arbitrary secret retrieval |
| Manage deployments | `Deployments` | Delete archives the record; it can remain listed |

The [Gateway service guide](../services/ai-gateway-api.md) covers routing,
compatibility, and all twelve families. The
[complete method reference](../reference/generated/gateway.md) and
[schema catalog](../reference/generated/gateway-schema.md) cover exact Go names.
The [live verification record](../developer/live-verification.md) distinguishes
exercised CRUD from helpers that need actual traffic or connected infrastructure.
