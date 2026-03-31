# SDK Update 002: Package Consolidation (Breaking)

**SDK:** `prisma-airs-go` v0.3.1 → v0.4.0
**PR:** #85
**Previous packages:** `aisec/management`, `aisec/scan`
**New package:** `aisec/runtime`

---

## What Changed

The `aisec/management` and `aisec/scan` packages were merged into a single `aisec/runtime` package. All types, functions, and constants are unchanged — only the package name and import path changed.

---

## Import Path Migration

```diff
- import "github.com/cdot65/prisma-airs-go/aisec/management"
- import "github.com/cdot65/prisma-airs-go/aisec/scan"
+ import "github.com/cdot65/prisma-airs-go/aisec/runtime"
```

---

## Type Prefix Migration

Every `management.` qualifier becomes `runtime.` and every `scan.` qualifier becomes `runtime.`.

### Management → Runtime

| Before | After |
|--------|-------|
| `management.NewClient(management.Opts{})` | `runtime.NewClient(runtime.Opts{})` |
| `management.Opts` | `runtime.Opts` |
| `management.ListOpts` | `runtime.ListOpts` |
| `management.CreateProfileRequest` | `runtime.CreateProfileRequest` |
| `management.UpdateProfileRequest` | `runtime.UpdateProfileRequest` |
| `management.ProfilePolicy` | `runtime.ProfilePolicy` |
| `management.AiSecurityProfileConfig` | `runtime.AiSecurityProfileConfig` |
| `management.ModelConfiguration` | `runtime.ModelConfiguration` |
| `management.LatencyConfig` | `runtime.LatencyConfig` |
| `management.ModelProtectionConfig` | `runtime.ModelProtectionConfig` |
| `management.AgentProtectionConfig` | `runtime.AgentProtectionConfig` |
| `management.AppProtectionConfig` | `runtime.AppProtectionConfig` |
| `management.DataProtectionConfig` | `runtime.DataProtectionConfig` |
| `management.DataLeakDetectionConfig` | `runtime.DataLeakDetectionConfig` |
| `management.DatabaseSecurityConfig` | `runtime.DatabaseSecurityConfig` |
| `management.MaliciousCodeProtectionConfig` | `runtime.MaliciousCodeProtectionConfig` |
| `management.URLCategoryMember` | `runtime.URLCategoryMember` |
| `management.ToxicCategoryConfig` | `runtime.ToxicCategoryConfig` |
| `management.TopicArrayConfig` | `runtime.TopicArrayConfig` |
| `management.TopicRef` | `runtime.TopicRef` |
| `management.DataLeakMember` | `runtime.DataLeakMember` |
| `management.SecurityProfile` | `runtime.SecurityProfile` |
| `management.SecurityProfileListResponse` | `runtime.SecurityProfileListResponse` |
| `management.CustomTopic` | `runtime.CustomTopic` |
| `management.CustomTopicListResponse` | `runtime.CustomTopicListResponse` |
| `management.ApiKey` | `runtime.ApiKey` |
| `management.CustomerApp` | `runtime.CustomerApp` |
| `management.DlpProfile` | `runtime.DlpProfile` |
| `management.DeploymentProfile` | `runtime.DeploymentProfile` |
| `management.ProfileActionAllow` | `runtime.ProfileActionAllow` |
| `management.ProfileActionBlock` | `runtime.ProfileActionBlock` |
| `management.ProfileActionAlert` | `runtime.ProfileActionAlert` |
| `management.ProfileActionDisabled` | `runtime.ProfileActionDisabled` |
| `management.ToxicContentHighBlockModerateAllow` | `runtime.ToxicContentHighBlockModerateAllow` |
| `management.ToxicContentHighBlockModerateBlock` | `runtime.ToxicContentHighBlockModerateBlock` |
| `management.ToxicContentHighAllowModerateAllow` | `runtime.ToxicContentHighAllowModerateAllow` |

### Scan → Runtime

| Before | After |
|--------|-------|
| `scan.NewScanner(cfg)` | `runtime.NewScanner(cfg)` |
| `scan.NewContent(scan.ContentOpts{})` | `runtime.NewContent(runtime.ContentOpts{})` |
| `scan.AiProfile` | `runtime.AiProfile` |
| `scan.SyncScanOpts` | `runtime.SyncScanOpts` |
| `scan.ContentOpts` | `runtime.ContentOpts` |
| `scan.Content` | `runtime.Content` |
| `scan.ScanRequest` | `runtime.ScanRequest` |
| `scan.ScanResponse` | `runtime.ScanResponse` |
| `scan.AsyncScanObject` | `runtime.AsyncScanObject` |
| `scan.AsyncScanResponse` | `runtime.AsyncScanResponse` |
| `scan.ContentInner` | `runtime.ContentInner` |
| `scan.Metadata` | `runtime.Metadata` |
| `scan.AgentMeta` | `runtime.AgentMeta` |
| `scan.ToolEvent` | `runtime.ToolEvent` |
| `scan.ThreatScanReport` | `runtime.ThreatScanReport` |
| `scan.ScanIDResult` | `runtime.ScanIDResult` |

---

## Terraform Provider Impact

### Required Changes

1. **Import path** — update all Go files importing the SDK:
   ```diff
   - "github.com/cdot65/prisma-airs-go/aisec/management"
   + "github.com/cdot65/prisma-airs-go/aisec/runtime"
   ```

2. **Type qualifiers** — find-and-replace across provider source:
   ```diff
   - management.
   + runtime.
   ```

3. **go.mod** — update SDK dependency:
   ```
   go get github.com/cdot65/prisma-airs-go@v0.4.0
   ```

### What Did NOT Change

- All struct field names, JSON tags, and field types are identical
- All method signatures are identical (`client.Profiles.Create`, `client.Profiles.List`, etc.)
- All sub-client names are identical (`Profiles`, `Topics`, `ApiKeys`, `CustomerApps`, etc.)
- All enum values are identical (`ProfileActionBlock`, `ToxicContentHighBlockModerateAllow`, etc.)
- Schema attributes, plan-to-SDK mapping, and state-from-SDK mapping logic remain the same
- OAuth2 auth flow and env var resolution are unchanged

### Automated Migration

For a Terraform provider codebase, this is a mechanical find-and-replace:

```bash
# Update import paths
find . -name '*.go' -exec sed -i '' 's|aisec/management|aisec/runtime|g' {} +
find . -name '*.go' -exec sed -i '' 's|aisec/scan|aisec/runtime|g' {} +

# Update type qualifiers
find . -name '*.go' -exec sed -i '' 's/management\./runtime./g' {} +
find . -name '*.go' -exec sed -i '' 's/scan\./runtime./g' {} +

# Update go.mod
go get github.com/cdot65/prisma-airs-go@v0.4.0
go mod tidy
```

---

## New Package Structure

```
aisec/runtime/        # AI Runtime Security (data plane + management plane)
  scanner.go          # NewScanner(cfg) — API Key auth, 4 scan methods
  client.go           # NewClient(opts) — OAuth2 auth, 8 sub-clients
  content.go          # Content type with byte-length validation
  scan_models.go      # Scan request/response types (~60 types)
  models.go           # Management model types (~50 types)
  doc.go              # Package documentation

aisec/modelsecurity/  # Model Security (unchanged)
aisec/redteam/        # Red Team (unchanged)
```
