# SDK Gaps: prisma-airs-go v0.3.1

Fields present in the AIRS Management API spec (`specs/mgmt_service_docs.yaml`) but missing from the Go SDK (`AppProtectionConfig`, `DataProtectionConfig`, `ModelConfiguration`).

## AppProtectionObject

**SDK struct:** `management.AppProtectionConfig` (models.go:82-86)

| API Field | JSON key | Type | SDK Status |
|---|---|---|---|
| alert-url-category | `alert-url-category` | `URLCategoryMember` | present |
| block-url-category | `block-url-category` | `URLCategoryMember` | present |
| allow-url-category | `allow-url-category` | `URLCategoryMember` | present |
| **default-url-category** | `default-url-category` | `{ member: []string }` | **MISSING** |
| **url-detected-action** | `url-detected-action` | `string` | **MISSING** |

### What the API returns

```json
"app-protection": {
  "allow-url-category": {},
  "block-url-category": {},
  "default-url-category": {
    "member": ["malicious"]
  },
  "url-detected-action": "block"
}
```

### Proposed SDK change

```go
type AppProtectionConfig struct {
    AlertURLCategory   *URLCategoryMember `json:"alert-url-category,omitempty"`
    BlockURLCategory   *URLCategoryMember `json:"block-url-category,omitempty"`
    AllowURLCategory   *URLCategoryMember `json:"allow-url-category,omitempty"`
    DefaultURLCategory *URLCategoryMember `json:"default-url-category,omitempty"` // NEW
    UrlDetectedAction  string             `json:"url-detected-action,omitempty"`  // NEW
}
```

---

## DataProtectionObject

**SDK struct:** `management.DataProtectionConfig` (models.go:72-74)

| API Field | JSON key | Type | SDK Status |
|---|---|---|---|
| data-leak-detection | `data-leak-detection` | `DataLeakDetectionConfig` | present |
| **database-security** | `database-security` | `[]{ name: string, action: string }` | **MISSING** |

### What the API returns

```json
"data-protection": {
  "data-leak-detection": { "action": "", "member": null },
  "database-security": null
}
```

### Proposed SDK change

```go
type DatabaseSecurityConfig struct {
    Name   string `json:"name"`
    Action string `json:"action"`
}

type DataProtectionConfig struct {
    DataLeakDetection *DataLeakDetectionConfig  `json:"data-leak-detection,omitempty"`
    DatabaseSecurity  []DatabaseSecurityConfig   `json:"database-security,omitempty"` // NEW
}
```

---

## AppProtectionObject (nested under model-configuration)

**SDK struct:** `management.ModelConfiguration` (models.go:103-110)

| API Field | JSON key | Type | SDK Status |
|---|---|---|---|
| **malicious-code-protection** | `malicious-code-protection` | `{ name: string, action: string }` | **MISSING** |

### What the API spec defines

```yaml
malicious-code-protection:
  type: object
  properties:
    name:
      type: string
    action:
      type: string
  required: [name, action]
```

### Proposed SDK change

```go
type MaliciousCodeProtectionConfig struct {
    Name   string `json:"name"`
    Action string `json:"action"`
}

type ModelConfiguration struct {
    MaskDataInStorage       bool                            `json:"mask-data-in-storage,omitempty"`
    Latency                 *LatencyConfig                  `json:"latency,omitempty"`
    DataProtection          *DataProtectionConfig           `json:"data-protection,omitempty"`
    AppProtection           *AppProtectionConfig            `json:"app-protection,omitempty"`
    ModelProtection         []ModelProtectionConfig         `json:"model-protection,omitempty"`
    AgentProtection         []AgentProtectionConfig         `json:"agent-protection,omitempty"`
    MaliciousCodeProtection *MaliciousCodeProtectionConfig  `json:"malicious-code-protection,omitempty"` // NEW
}
```

---

## Summary

| Missing Field | Parent Object | Priority | Reason |
|---|---|---|---|
| `default-url-category` | AppProtectionConfig | **High** | Seen in real profiles; needed to match prod config |
| `url-detected-action` | AppProtectionConfig | **High** | Paired with default-url-category |
| `database-security` | DataProtectionConfig | Medium | Returned by API but nullable |
| `malicious-code-protection` | ModelConfiguration | Medium | In spec, not yet observed in real profiles |

Once these are added to the SDK, the Terraform provider needs matching schema attributes, plan-to-SDK mapping, and state-from-SDK mapping in `resource_security_profile.go`.
