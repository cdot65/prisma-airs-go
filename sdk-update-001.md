# SDK Update 001: Missing Management Model Fields

**SDK:** `prisma-airs-go` v0.3.1 → v0.3.2 (pending version bump)
**PRs:** #82, #83
**Package:** `github.com/cdot65/prisma-airs-go/aisec/runtime`
**File:** `aisec/runtime/models.go`

---

## New Structs

### MaliciousCodeProtectionConfig

```go
type MaliciousCodeProtectionConfig struct {
    Name   string `json:"name"`
    Action string `json:"action"`
}
```

- **JSON key (parent):** `malicious-code-protection`
- **Parent struct:** `AppProtectionConfig`
- **Pointer type:** `*MaliciousCodeProtectionConfig`
- **Known values:** `Name`: `"malicious-code"`, `Action`: `"block"`
- **Nullable:** yes (absent from some profiles)

### DatabaseSecurityConfig

```go
type DatabaseSecurityConfig struct {
    Name   string `json:"name"`
    Action string `json:"action"`
}
```

- **JSON key (parent):** `database-security`
- **Parent struct:** `DataProtectionConfig`
- **Slice type:** `[]DatabaseSecurityConfig`
- **Known entries (always 4 when present):**

| Name | Valid Actions |
|------|-------------|
| `database-security-create` | `block`, `allow` |
| `database-security-read` | `block`, `allow` |
| `database-security-update` | `block`, `allow` |
| `database-security-delete` | `block`, `allow` |

- **Nullable:** yes (`null` when unconfigured)

---

## Modified Structs

### AppProtectionConfig

**Path:** `model-configuration.app-protection`

```go
type AppProtectionConfig struct {
    AlertURLCategory        *URLCategoryMember             `json:"alert-url-category,omitempty"`
    BlockURLCategory        *URLCategoryMember             `json:"block-url-category,omitempty"`
    AllowURLCategory        *URLCategoryMember             `json:"allow-url-category,omitempty"`
    DefaultURLCategory      *URLCategoryMember             `json:"default-url-category,omitempty"`      // NEW
    UrlDetectedAction       string                         `json:"url-detected-action,omitempty"`       // NEW
    MaliciousCodeProtection *MaliciousCodeProtectionConfig `json:"malicious-code-protection,omitempty"` // NEW
}
```

#### New fields

| Go Field | JSON Key | Type | Terraform Schema Type | Notes |
|----------|----------|------|----------------------|-------|
| `DefaultURLCategory` | `default-url-category` | `*URLCategoryMember` | `list(string)` nested under object | Member array; often `["malicious"]`, can be `null` |
| `UrlDetectedAction` | `url-detected-action` | `string` | `string` | Values: `"block"`, `""` (disabled) |
| `MaliciousCodeProtection` | `malicious-code-protection` | `*MaliciousCodeProtectionConfig` | nested object (`name` + `action`) | Optional; absent from many profiles |

### DataProtectionConfig

**Path:** `model-configuration.data-protection`

```go
type DataProtectionConfig struct {
    DataLeakDetection *DataLeakDetectionConfig `json:"data-leak-detection,omitempty"`
    DatabaseSecurity  []DatabaseSecurityConfig  `json:"database-security,omitempty"` // NEW
}
```

#### New fields

| Go Field | JSON Key | Type | Terraform Schema Type | Notes |
|----------|----------|------|----------------------|-------|
| `DatabaseSecurity` | `database-security` | `[]DatabaseSecurityConfig` | `list(object({name, action}))` | 4 CRUD entries when populated, `null` when unconfigured |

---

## Terraform Provider TODO

For `resource_security_profile.go`:

### Schema additions

1. **`app_protection.default_url_category`** — `TypeList` of `TypeString`, Optional, Computed
2. **`app_protection.url_detected_action`** — `TypeString`, Optional, Computed, ValidateFunc: `"block"` or `""`
3. **`app_protection.malicious_code_protection`** — nested block, Optional
   - `name` — `TypeString`, Required (value: `"malicious-code"`)
   - `action` — `TypeString`, Required (value: `"block"`)
4. **`data_protection.database_security`** — `TypeList` of nested blocks, Optional
   - `name` — `TypeString`, Required
   - `action` — `TypeString`, Required, ValidateFunc: `"block"` or `"allow"`

### Plan-to-SDK mapping

```
app_protection.default_url_category  → AppProtectionConfig.DefaultURLCategory.Member
app_protection.url_detected_action   → AppProtectionConfig.UrlDetectedAction
app_protection.malicious_code_protection.name   → AppProtectionConfig.MaliciousCodeProtection.Name
app_protection.malicious_code_protection.action → AppProtectionConfig.MaliciousCodeProtection.Action
data_protection.database_security[].name   → DataProtectionConfig.DatabaseSecurity[].Name
data_protection.database_security[].action → DataProtectionConfig.DatabaseSecurity[].Action
```

### State-from-SDK mapping

Reverse of above. Handle `nil` pointers and `null` slices gracefully — set to empty in state rather than omitting.

---

## Real API Response Examples

### Full app-protection (from prod)

```json
"app-protection": {
  "allow-url-category": {"member": ["dynamic-dns","grayware"]},
  "block-url-category": {"member": []},
  "default-url-category": {"member": ["malicious"]},
  "malicious-code-protection": {"action": "block", "name": "malicious-code"},
  "url-detected-action": "block"
}
```

### Minimal app-protection (defaults only)

```json
"app-protection": {
  "default-url-category": {"member": ["malicious"]},
  "url-detected-action": "block"
}
```

### Full data-protection

```json
"data-protection": {
  "data-leak-detection": {"action": "block", "member": [{"text": "IP Addresses", "id": "11995029", "version": "1"}]},
  "database-security": [
    {"action": "block", "name": "database-security-create"},
    {"action": "allow", "name": "database-security-read"},
    {"action": "block", "name": "database-security-update"},
    {"action": "block", "name": "database-security-delete"}
  ]
}
```

### Unconfigured data-protection

```json
"data-protection": {
  "data-leak-detection": {"action": "", "member": null},
  "database-security": null
}
```
