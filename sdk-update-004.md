# SDK Update 004: `bool` + `omitempty` Fix

**SDK:** `prisma-airs-go` v0.4.0 → v0.4.1
**PR:** #88
**Issue:** #87

---

## What Changed

Removed `omitempty` from all 33 plain `bool` JSON struct tags. Go's `encoding/json` treats `false` as the zero value — with `omitempty`, `false` was silently dropped from serialized JSON. The API never received the field.

This is a **patch-level** change. No API surface changes. No import changes. `go get -u` is sufficient.

---

## Impact on Terraform Provider

### Before (broken)

Setting a bool attribute to `false` in Terraform produced JSON missing that field entirely:

```hcl
resource "prismaairs_security_profile" "example" {
  mask_data_in_storage = false
}
```

```json
// SDK serialized → API received:
{"model-configuration": {"latency": {...}}}
// "mask-data-in-storage" is MISSING
```

On read-back the field was absent, creating perpetual plan diffs.

### After (fixed)

```json
{"model-configuration": {"mask-data-in-storage": false, "latency": {...}}}
```

`false` is always serialized. No more state drift.

---

## Affected Fields by Resource

### `runtime` package — Security Profiles

| Struct | Field | JSON Key | Terraform Attribute |
|--------|-------|----------|---------------------|
| `ModelConfiguration` | `MaskDataInStorage` | `mask-data-in-storage` | `mask_data_in_storage` |
| `DataLeakDetectionConfig` | `MaskDataInline` | `mask-data-inline` | `mask_data_inline` |
| `SecurityProfile` | `Active` | `active` | `active` |
| `CustomTopic` | `Active` | `active` | `active` |

### `runtime` package — API Keys

| Struct | Field | JSON Key | Terraform Attribute |
|--------|-------|----------|---------------------|
| `ApiKey` | `Revoked` | `revoked` | `revoked` |

### `runtime` package — Customer Apps

| Struct | Field | JSON Key | Terraform Attribute |
|--------|-------|----------|---------------------|
| `CustomerApp` | `AgentApp` | `agent_app` | `agent_app` |

### `runtime` package — Scan Logs (data source)

| Struct | Field | JSON Key | Terraform Attribute |
|--------|-------|----------|---------------------|
| `ScanLog` | `IsPrompt` | `is_prompt` | `is_prompt` |
| `ScanLog` | `IsResponse` | `is_response` | `is_response` |
| `ScanLog` | `ContentMasked` | `content_masked` | `content_masked` |

### `runtime` package — Scan Response (data source)

| Struct | Field | JSON Key | Terraform Attribute |
|--------|-------|----------|---------------------|
| `ToolDetectionFlags` | `Injection` | `injection` | `injection` |
| `ToolDetectionFlags` | `URLCats` | `url_cats` | `url_cats` |
| `ToolDetectionFlags` | `DLP` | `dlp` | `dlp` |
| `ToolDetectionFlags` | `DBSecurity` | `db_security` | `db_security` |
| `ToolDetectionFlags` | `ToxicContent` | `toxic_content` | `toxic_content` |
| `ToolDetectionFlags` | `MaliciousCode` | `malicious_code` | `malicious_code` |
| `ToolDetectionFlags` | `Agent` | `agent` | `agent` |
| `ToolDetectionFlags` | `TopicViolation` | `topic_violation` | `topic_violation` |

### `redteam` package — Targets

| Struct | Field | JSON Key | Terraform Attribute |
|--------|-------|----------|---------------------|
| `TargetCreateRequest` | `SessionSupported` | `session_supported` | `session_supported` |
| `TargetUpdateRequest` | `SessionSupported` | `session_supported` | `session_supported` |
| `TargetResponse` | `SessionSupported` | `session_supported` | `session_supported` |
| `TargetListItem` | `SessionSupported` | `session_supported` | `session_supported` |

### `redteam` package — Target Metadata

| Struct | Field | JSON Key | Terraform Attribute |
|--------|-------|----------|---------------------|
| `TargetMetadata` | `MultiTurn` | `multi_turn` | `multi_turn` |
| `TargetMetadata` | `RateLimitEnabled` | `rate_limit_enabled` | `rate_limit_enabled` |
| `TargetMetadata` | `ContentFilterEnabled` | `content_filter_enabled` | `content_filter_enabled` |

### `redteam` package — Custom Attacks

| Struct | Field | JSON Key | Terraform Attribute |
|--------|-------|----------|---------------------|
| `CustomPromptSetResponse` | `Active` | `active` | `active` |
| `CustomPromptSetResponse` | `Archive` | `archive` | `archive` |
| `CustomPromptSetReference` | `Active` | `active` | `active` |
| `CustomPromptResponse` | `UserDefinedGoal` | `user_defined_goal` | `user_defined_goal` |
| `CustomPromptResponse` | `Active` | `active` | `active` |

### `redteam` package — Attack/Goal Responses (data source)

| Struct | Field | JSON Key | Terraform Attribute |
|--------|-------|----------|---------------------|
| `AttackDetailResponse` | `MultiTurn` | `multi_turn` | `multi_turn` |
| `AttackMultiTurnDetailResponse` | `MultiTurn` | `multi_turn` | `multi_turn` |
| `Goal` | `CustomGoal` | `custom_goal` | `custom_goal` |

---

## Terraform Provider Action Items

1. **Bump SDK dependency** to `v0.4.1`
2. **Remove any workarounds** for the omitempty bug (e.g., custom JSON marshaling, pointer-based bool overrides, or manual field injection)
3. **Verify bool attributes** in schema use `types.Bool` (not `types.String`) — the SDK now handles `false` correctly
4. **No schema changes needed** — the fix is transparent to Terraform users
5. **Test plan diffs** — resources with `false` bool attributes should no longer show perpetual diffs

---

## `*bool` Fields — No Change

Fields already using `*bool` (pointer) were NOT affected and remain unchanged. These correctly support three-state semantics: `nil` (omit), `&false` (send false), `&true` (send true). Examples: `MarkedSafe`, `Threat`, `TargetProbeRequest.SessionSupported`.
