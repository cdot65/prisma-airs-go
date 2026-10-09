# Gateway workspaces and inference (v0.8.0)

Install SDK v0.9.0 as described in [parity status](../developer/typescript-parity.md).
SCM management credentials and the inference runtime key are separate.

## Provision an IAM-bound workspace

The complete program creates real tenant objects when run. It prints partial
identities on failure and leaves the workspace available for use. It does not
assign service-account permissions. Select a tenant-root admin credential first.

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"
    "github.com/cdot65/prisma-airs-go/aisec/gateway"
)

func main() {
    client, err := gateway.NewClient(gateway.Opts{})
    if err != nil { log.Fatal(err) }
    ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
    defer cancel()
    result, err := client.Workspaces.Provision(ctx, gateway.WorkspaceCreateRequest{
        Name: "My workspace",
    }, gateway.WorkspaceProvisionOptions{})
    if result != nil {
        fmt.Printf("Scope: %s\n", result.ScopeName)
        if result.Workspace != nil {
            fmt.Printf("Workspace UUID: %s; slug: %s\n", result.Workspace.ID, result.Workspace.Slug)
        }
    }
    if err != nil { log.Fatal(err) }
}
```

## Stream a text chat request

Set `PANW_AI_GW_INFERENCE_ENDPOINT` to the runtime API prefix and
`PANW_AI_GW_INFERENCE_API_KEY` to the workspace/runtime key. This program sends a
billable generation request when run. Change the model to one available in your gateway.

```go
package main

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "log"
    "github.com/cdot65/prisma-airs-go/aisec/gateway"
)

func main() {
    client, err := gateway.NewInferenceClient(gateway.InferenceOpts{})
    if err != nil { log.Fatal(err) }
    request, err := gateway.NewChatRequest("gpt-4o", gateway.ChatTextMessage{
        Role: "user", Content: "Explain what this SDK does in one sentence.",
    })
    if err != nil { log.Fatal(err) }
    stream, err := client.StreamChatCompletion(context.Background(), request, gateway.InferenceRequestOptions{})
    if err != nil { log.Fatal(err) }
    defer func() { _ = stream.Close() }()
    for {
        event, err := stream.Next()
        if errors.Is(err, io.EOF) { break }
        if err != nil { log.Fatal(err) }
        data, err := json.Marshal(event)
        if err != nil { log.Fatal(err) }
        fmt.Println(string(data))
    }
}
```

See [Gateway service behavior](../services/ai-gateway-api.md) for partial failures,
archival deletes, credential boundaries and transport limits.
