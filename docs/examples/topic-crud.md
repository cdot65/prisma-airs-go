# Custom Topics CRUD

End-to-end example for managing custom detection topics. Topics define custom content categories that the scan engine uses for topic guardrail enforcement.

## Prerequisites

```bash
export PANW_MGMT_CLIENT_ID=your-client-id
export PANW_MGMT_CLIENT_SECRET=your-client-secret
export PANW_MGMT_TSG_ID=your-tsg-id
```

## Build & Run

```bash
go run ./examples/topic-crud/
```

## Workflow

### Step 1: Initialize Client

```go
client, err := management.NewClient(management.Opts{
    ClientID:     os.Getenv("PANW_MGMT_CLIENT_ID"),
    ClientSecret: os.Getenv("PANW_MGMT_CLIENT_SECRET"),
    TsgID:        os.Getenv("PANW_MGMT_TSG_ID"),
})
```

### Step 2: Create Topic

Define a custom topic with example phrases that the detection engine uses for classification.

```go
created, err := client.Topics.Create(ctx, management.CreateTopicRequest{
    TopicName:   "company-financials",
    Description: "Detect discussions about internal financial data",
    Examples: []string{
        "quarterly revenue figures",
        "profit margins for Q3",
        "internal budget allocations",
        "projected earnings per share",
    },
})
```

**Response:**

```json
{
  "topic_id": "a1b2c3d4-5678-90ab-cdef-1234567890ab",
  "topic_name": "company-financials",
  "description": "Detect discussions about internal financial data",
  "examples": [
    "quarterly revenue figures",
    "profit margins for Q3",
    "internal budget allocations",
    "projected earnings per share"
  ],
  "created_at": "2026-03-22T14:00:00Z",
  "updated_at": "2026-03-22T14:00:00Z"
}
```

### Step 3: List Topics

```go
listResp, err := client.Topics.List(ctx, management.ListOpts{Limit: 100})

fmt.Printf("Total topics: %d\n", len(listResp.Items))
for _, t := range listResp.Items {
    fmt.Printf("  id=%s name=%s\n", t.TopicID, t.TopicName)
}
```

### Step 4: Update Topic

Add more examples and refine the description. The `TopicName` field is required by the API even on update.

```go
updated, err := client.Topics.Update(ctx, created.TopicID, management.UpdateTopicRequest{
    TopicName:   "company-financials",
    Description: "Detect discussions about internal financial data and forecasts",
    Examples: []string{
        "quarterly revenue figures",
        "profit margins for Q3",
        "internal budget allocations",
        "projected earnings per share",
        "M&A pipeline details",
        "cost reduction targets",
    },
})
```

**Response:**

```json
{
  "topic_id": "a1b2c3d4-5678-90ab-cdef-1234567890ab",
  "topic_name": "company-financials",
  "description": "Detect discussions about internal financial data and forecasts",
  "examples": [
    "quarterly revenue figures",
    "profit margins for Q3",
    "internal budget allocations",
    "projected earnings per share",
    "M&A pipeline details",
    "cost reduction targets"
  ]
}
```

### Step 5: Delete Topic

```go
resp, err := client.Topics.Delete(ctx, created.TopicID)
fmt.Printf("Delete: %s\n", resp.Message)
```

For topics that may be referenced by active profiles, use force delete:

```go
resp, err := client.Topics.ForceDelete(ctx, created.TopicID, "admin@example.com")
```

!!! note "ForceDelete response"
    The API may return a non-JSON response for successful deletes. The SDK handles this
    gracefully — `err` will be `nil` on success, but `resp.Message` may be empty.

## Using Topics in Security Profiles

Once a topic exists, reference it in a security profile's `topic-guardrails` model protection:

```go
created, err := client.Profiles.Create(ctx, management.CreateProfileRequest{
    ProfileName: "financial-guardrails",
    Policy: &management.ProfilePolicy{
        AiSecurityProfiles: []management.AiSecurityProfileConfig{
            {
                ModelType: "default",
                ModelConfiguration: &management.ModelConfiguration{
                    ModelProtection: []management.ModelProtectionConfig{
                        {
                            Name:   "topic-guardrails",
                            Action: management.ProfileActionBlock,
                            TopicList: []management.TopicArrayConfig{
                                {
                                    Action: management.ProfileActionBlock,
                                    Topic: []management.TopicRef{
                                        {TopicName: "company-financials"},
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    },
})
```

When a scan matches this profile, any prompt or response touching "company-financials" topics will be blocked.
