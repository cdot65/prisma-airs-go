# Management API

The Management API provides CRUD operations for AIRS configuration — security profiles, custom topics, API keys, customer apps, and more. It uses OAuth2 client_credentials for authentication.

## Authentication

```go
client := management.NewClient(management.Opts{
    ClientID:     "your-client-id",
    ClientSecret: "your-client-secret",
    TsgID:        "1234567890",
})
```

Or use environment variables:

```bash
export PANW_MGMT_CLIENT_ID=your-client-id
export PANW_MGMT_CLIENT_SECRET=your-client-secret
export PANW_MGMT_TSG_ID=1234567890
```

```go
client := management.NewClient(management.Opts{})
```

## Sub-Clients

The `ManagementClient` exposes 8 sub-clients:

### Profiles — Security Profile CRUD

```go
// Create
profile, err := client.Profiles.Create(ctx, management.CreateProfileRequest{
    ProfileName: "my-profile",
    // ... policy configuration
})

// List with pagination
profiles, err := client.Profiles.List(ctx, management.ListOpts{Limit: 10, Offset: 0})

// Get by name
profile, err := client.Profiles.GetByName(ctx, "my-profile")

// Update
updated, err := client.Profiles.Update(ctx, "profile-id", management.UpdateProfileRequest{...})

// Delete
resp, err := client.Profiles.Delete(ctx, "profile-id")
```

### Topics — Custom Detection Topics

```go
// Create
topic, err := client.Topics.Create(ctx, management.CreateTopicRequest{
    TopicName:   "company-secrets",
    Description: "Detect company confidential information",
    Examples:    []string{"revenue figures", "strategic plans"},
})

// List, Update, Delete, ForceDelete
topics, err := client.Topics.List(ctx, management.ListOpts{})
updated, err := client.Topics.Update(ctx, "topic-id", management.UpdateTopicRequest{...})
resp, err := client.Topics.Delete(ctx, "topic-id")
resp, err := client.Topics.ForceDelete(ctx, "topic-id")
```

### ApiKeys — API Key Lifecycle

```go
key, err := client.ApiKeys.Create(ctx, management.CreateApiKeyRequest{...})
keys, err := client.ApiKeys.List(ctx, management.ListOpts{})
resp, err := client.ApiKeys.Delete(ctx, "key-name", "admin@example.com")
newKey, err := client.ApiKeys.Regenerate(ctx, "key-id", management.RegenerateKeyRequest{...})
```

### CustomerApps — Customer Application Management

```go
app, err := client.CustomerApps.Create(ctx, management.CreateAppRequest{...})
apps, err := client.CustomerApps.List(ctx, management.ListOpts{})
app, err := client.CustomerApps.Get(ctx, "app-id")
updated, err := client.CustomerApps.Update(ctx, "app-id", management.UpdateAppRequest{...})
resp, err := client.CustomerApps.Delete(ctx, "app-id")
```

### DlpProfiles — DLP Data Profiles (Read-Only)

```go
profiles, err := client.DlpProfiles.List(ctx, management.ListOpts{})
profile, err := client.DlpProfiles.Get(ctx, "profile-id")
```

### DeploymentProfiles — Deployment Profiles (Read-Only)

```go
profiles, err := client.DeploymentProfiles.List(ctx, management.ListOpts{})
profile, err := client.DeploymentProfiles.Get(ctx, "profile-id")
```

### ScanLogs — Scan Activity Logs (Read-Only)

```go
logs, err := client.ScanLogs.List(ctx, management.ScanLogListOpts{
    Limit: 50,
})
logEntry, err := client.ScanLogs.Get(ctx, "log-id")
```

### OAuth — Token Management

```go
token, err := client.OAuth.GetToken(ctx)
resp, err := client.OAuth.InvalidateToken(ctx)
```

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
