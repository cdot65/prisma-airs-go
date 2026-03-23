# Runtime API

The Runtime API provides CRUD operations for AIRS configuration — security profiles, custom topics, API keys, customer apps, and more — as well as real-time content scanning for prompts, responses, and tool events. It uses OAuth2 client_credentials for authentication (management operations) and API Key HMAC-SHA256 for scanning operations.

## Authentication

```go
client, err := runtime.NewClient(runtime.Opts{
    ClientID:     "your-client-id",
    ClientSecret: "your-client-secret",
    TsgID:        "1234567890",
})
if err != nil {
    log.Fatal(err)
}
```

Or use environment variables:

```bash
export PANW_MGMT_CLIENT_ID=your-client-id
export PANW_MGMT_CLIENT_SECRET=your-client-secret
export PANW_MGMT_TSG_ID=1234567890
```

```go
client, err := runtime.NewClient(runtime.Opts{})
if err != nil {
    log.Fatal(err)
}
```

## Sub-Clients

The `RuntimeClient` exposes 8 sub-clients:

### Profiles — Security Profile CRUD

```go
// Create
profile, err := client.Profiles.Create(ctx, runtime.CreateProfileRequest{
    ProfileName: "my-profile",
    // ... policy configuration
})

// List with pagination
profiles, err := client.Profiles.List(ctx, runtime.ListOpts{Limit: 10, Offset: 0})

// Get by ID (client-side filter over List)
profile, err := client.Profiles.GetByID(ctx, "profile-uuid")

// Get by name (returns highest revision; client-side filter over List)
profile, err := client.Profiles.GetByName(ctx, "my-profile")

// Update
updated, err := client.Profiles.Update(ctx, "profile-id", runtime.UpdateProfileRequest{...})

// Delete
resp, err := client.Profiles.Delete(ctx, "profile-id")

// Force delete (requires updatedBy; resp.Message may be empty)
resp, err = client.Profiles.ForceDelete(ctx, "profile-id", "admin@example.com")
```

### Topics — Custom Detection Topics

```go
// Create
topic, err := client.Topics.Create(ctx, runtime.CreateTopicRequest{
    TopicName:   "company-secrets",
    Description: "Detect company confidential information",
    Examples:    []string{"revenue figures", "strategic plans"},
})

// List, Update, Delete, ForceDelete
topics, err := client.Topics.List(ctx, runtime.ListOpts{})
updated, err := client.Topics.Update(ctx, "topic-id", runtime.UpdateTopicRequest{...})
resp, err := client.Topics.Delete(ctx, "topic-id")
resp, err = client.Topics.ForceDelete(ctx, "topic-id", "admin@example.com") // resp.Message may be empty
```

### ApiKeys — API Key Lifecycle

```go
key, err := client.ApiKeys.Create(ctx, runtime.CreateApiKeyRequest{...})
keys, err := client.ApiKeys.List(ctx, runtime.ListOpts{})
resp, err := client.ApiKeys.Delete(ctx, "key-name", "admin@example.com")
newKey, err := client.ApiKeys.Regenerate(ctx, "key-id", runtime.RegenerateKeyRequest{...})
```

### CustomerApps — Customer Application Management

```go
apps, err := client.CustomerApps.List(ctx, runtime.ListOpts{})
app, err := client.CustomerApps.Get(ctx, "app-name")
updated, err := client.CustomerApps.Update(ctx, "app-id", runtime.UpdateAppRequest{...})
resp, err := client.CustomerApps.Delete(ctx, "app-name", "admin@example.com")
```

### DlpProfiles — DLP Data Profiles (Read-Only)

```go
profiles, err := client.DlpProfiles.List(ctx, runtime.ListOpts{})
profile, err := client.DlpProfiles.Get(ctx, "profile-id")
```

### DeploymentProfiles — Deployment Profiles (Read-Only)

```go
profiles, err := client.DeploymentProfiles.List(ctx, runtime.ListOpts{})
profile, err := client.DeploymentProfiles.Get(ctx, "profile-id")
```

### ScanLogs — Scan Activity Logs (Read-Only)

```go
logs, err := client.ScanLogs.List(ctx, runtime.ScanLogListOpts{
    TimeInterval: 24,
    TimeUnit:     "hour",
    PageNumber:   1,
    PageSize:     50,
    Filter:       "all",
})
```

### OAuth — Token Management

```go
token, err := client.OAuth.GetToken(ctx, runtime.OAuthTokenRequest{
    ClientID: "your-client-id",
})
resp, err := client.OAuth.InvalidateToken(ctx)
```

## Action Enums

Security profile action fields use typed enums instead of bare strings.

### ProfileAction

Used on all action fields across profile configs (latency, model-protection, agent-protection, data-leak-detection, topic-list) and scan log action fields.

```go
runtime.ProfileActionAllow    // "allow"
runtime.ProfileActionBlock    // "block"
runtime.ProfileActionAlert    // "alert"
runtime.ProfileActionDisabled // "" (empty — disabled/unset)
```

Example:

```go
cfg := runtime.ModelProtectionConfig{
    Name:   "prompt-injection",
    Action: runtime.ProfileActionBlock,
}
```

### ToxicContentAction

Compound action for toxic content categories — encodes severity-level thresholds.

```go
runtime.ToxicContentHighBlockModerateAllow // "high:block, moderate:allow"
runtime.ToxicContentHighBlockModerateBlock // "high:block, moderate:block"
runtime.ToxicContentHighAllowModerateAllow // "high:allow, moderate:allow"
```

Note: `ToxicCategoryConfig.Action` remains `string` since it accepts both simple (`ProfileAction`) and compound (`ToxicContentAction`) values.

## Error Handling

```go
result, err := client.Profiles.Create(ctx, request)
if err != nil {
    var sdkErr *aisec.AISecSDKError
    if errors.As(err, &sdkErr) {
        switch sdkErr.ErrorType {
        case aisec.OAuthError:
            log.Println("Authentication failed:", sdkErr.Message)
        case aisec.ServerSideError:
            log.Println("Server error, retry later:", sdkErr.Message)
        }
    }
}
```
