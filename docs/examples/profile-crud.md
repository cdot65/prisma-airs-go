# Security Profile CRUD

End-to-end example demonstrating all security profile operations: Create, List, GetByID, GetByName, Update, and ForceDelete.

Source: [`examples/profile-crud/main.go`](https://github.com/cdot65/prisma-airs-go/blob/main/examples/profile-crud/main.go)

## Prerequisites

```bash
export PANW_MGMT_CLIENT_ID=your-client-id
export PANW_MGMT_CLIENT_SECRET=your-client-secret
export PANW_MGMT_TSG_ID=your-tsg-id
```

Or use `set -a && source .env && set +a` to load from a `.env` file.

## Build & Run

```bash
go build ./examples/profile-crud/
go run ./examples/profile-crud/
```

## Workflow

### Step 1: Initialize Client

```go
client, err := runtime.NewClient(runtime.Opts{
    ClientID:     os.Getenv("PANW_MGMT_CLIENT_ID"),
    ClientSecret: os.Getenv("PANW_MGMT_CLIENT_SECRET"),
    TsgID:        os.Getenv("PANW_MGMT_TSG_ID"),
})
```

### Step 2: Create Profile

Creates a profile with prompt-injection blocking and agent security.

```go
created, err := client.Profiles.Create(ctx, runtime.CreateProfileRequest{
    ProfileName: profileName,
    Policy: &runtime.ProfilePolicy{
        AiSecurityProfiles: []runtime.AiSecurityProfileConfig{
            {
                ModelType: "default",
                ModelConfiguration: &runtime.ModelConfiguration{
                    MaskDataInStorage: false,
                    Latency: &runtime.LatencyConfig{
                        InlineTimeoutAction: runtime.ProfileActionBlock,
                        MaxInlineLatency:    5,
                    },
                    ModelProtection: []runtime.ModelProtectionConfig{
                        {Name: "prompt-injection", Action: runtime.ProfileActionBlock},
                    },
                    AgentProtection: []runtime.AgentProtectionConfig{
                        {Name: "agent-security", Action: runtime.ProfileActionBlock},
                    },
                },
            },
        },
    },
})
```

**Response:**

```json
{
  "profile_id": "de02ba1f-2330-42e8-af28-1f06d95afe69",
  "profile_name": "sdk-example-1774183739921371000",
  "revision": 1,
  "active": true,
  "policy": {
    "ai-security-profiles": [
      {
        "model-type": "default",
        "model-configuration": {
          "latency": {
            "inline-timeout-action": "block",
            "max-inline-latency": 5
          },
          "model-protection": [
            {"name": "prompt-injection", "action": "block"}
          ],
          "agent-protection": [
            {"name": "agent-security", "action": "block"}
          ]
        }
      }
    ]
  },
  "created_by": "test@test.com",
  "updated_by": "test@test.com",
  "last_modified_ts": "2026-03-22T12:49:00Z"
}
```

### Step 3: List Profiles

```go
listResp, err := client.Profiles.List(ctx, runtime.ListOpts{Limit: 100})
```

**Response (abbreviated):**

```
Total profiles: 30
[0] id=de02ba1f-... name=sdk-example-1774183739921371000 revision=1 active=true
[1] id=6794c21b-... name=AI-Firewall-High-Security-Profile revision=4 active=true
[2] id=aeda326a-... name=Truffles Agent revision=2 active=true
...
```

### Step 4: Get by ID

Retrieves a single profile by UUID. No dedicated API endpoint exists — lists all profiles and filters client-side.

```go
byID, err := client.Profiles.GetByID(ctx, created.ProfileID)
```

**Response:** Same structure as Create response.

### Step 5: Get by Name

Retrieves a profile by name. When multiple revisions exist, returns the one with the highest revision number.

```go
byName, err := client.Profiles.GetByName(ctx, profileName)
```

**Response:** Same structure as Create response. After an Update creates revision 2, `GetByName` returns the revision-2 profile.

### Step 6: Update Profile

Adds `contextual-grounding` and `toxic-content` protections, increases latency timeout to 10 seconds, upgrades agent-security to block.

```go
updated, err := client.Profiles.Update(ctx, created.ProfileID, runtime.UpdateProfileRequest{
    ProfileName: profileName,
    Policy: &runtime.ProfilePolicy{
        AiSecurityProfiles: []runtime.AiSecurityProfileConfig{
            {
                ModelType: "default",
                ModelConfiguration: &runtime.ModelConfiguration{
                    MaskDataInStorage: false,
                    Latency: &runtime.LatencyConfig{
                        InlineTimeoutAction: runtime.ProfileActionBlock,
                        MaxInlineLatency:    10,
                    },
                    ModelProtection: []runtime.ModelProtectionConfig{
                        {Name: "prompt-injection", Action: runtime.ProfileActionBlock},
                        {Name: "contextual-grounding", Action: runtime.ProfileActionBlock},
                        {
                            Name:   "toxic-content",
                            Action: runtime.ProfileAction(runtime.ToxicContentHighBlockModerateAllow),
                        },
                    },
                    AgentProtection: []runtime.AgentProtectionConfig{
                        {Name: "agent-security", Action: runtime.ProfileActionBlock},
                    },
                },
            },
        },
    },
})
```

**Response:**

```json
{
  "profile_id": "a5468b56-6512-4e61-b5cd-0f0dea0a56bf",
  "profile_name": "sdk-example-1774183739921371000",
  "revision": 2,
  "active": true,
  "policy": {
    "ai-security-profiles": [
      {
        "model-type": "default",
        "model-configuration": {
          "latency": {
            "inline-timeout-action": "block",
            "max-inline-latency": 10
          },
          "model-protection": [
            {"name": "prompt-injection", "action": "block"},
            {"name": "contextual-grounding", "action": "block"},
            {"name": "toxic-content", "action": "high:block, moderate:allow"}
          ],
          "agent-protection": [
            {"name": "agent-security", "action": "block"}
          ]
        }
      }
    ]
  },
  "created_by": "test@test.com",
  "updated_by": "none",
  "last_modified_ts": "2026-03-22T12:49:02Z"
}
```

!!! note "Update creates a new revision"
    The `profile_id` changes after update (`de02ba1f...` to `a5468b56...`) and `revision` bumps from 1 to 2. Use `GetByName` to always get the latest revision.

### Step 7: Force Delete

```go
resp, err := client.Profiles.ForceDelete(ctx, created.ProfileID, "sdk-example")
if err != nil {
    log.Fatal(err)
}
fmt.Println("Deleted successfully")
```

!!! note "ForceDelete response"
    The API returns a non-JSON response for successful deletes. The SDK handles this
    gracefully — `err` will be `nil` on success, but `resp.Message` may be empty.

## Valid Protection Names

Based on the live API, these are the valid names for each protection type:

### model-protection

| Name | Valid Actions |
|------|-------------|
| `prompt-injection` | `block`, `allow` |
| `contextual-grounding` | `block`, `allow` |
| `toxic-content` | `high:block, moderate:block`, `high:block, moderate:allow`, `high:allow, moderate:allow` |
| `topic-guardrails` | `block`, `allow` (with `topic-list` array) |

### agent-protection

| Name | Valid Actions |
|------|-------------|
| `agent-security` | `block` |

### app-protection

| Field | Type / Valid Values |
|-------|-------------------|
| `default-url-category` | `URLCategoryMember` — default URL categories (e.g., `["malicious"]`) |
| `url-detected-action` | `block`, `""` (disabled) |
| `malicious-code-protection` | object with `name` (`"malicious-code"`) and `action` (`"block"`) |
| `alert-url-category` | `URLCategoryMember` — URL categories for alerts |
| `block-url-category` | `URLCategoryMember` — URL categories to block |
| `allow-url-category` | `URLCategoryMember` — URL categories to allow |

### latency

| Field | Valid Values |
|-------|-------------|
| `inline-timeout-action` | `block`, `allow` |
| `max-inline-latency` | integer (seconds) |

### data-protection

| Name | Valid Actions |
|------|-------------|
| `data-leak-detection` | `block`, `""` (disabled) |
| `database-security-create` | `block`, `allow` |
| `database-security-read` | `block`, `allow` |
| `database-security-update` | `block`, `allow` |
| `database-security-delete` | `block`, `allow` |
