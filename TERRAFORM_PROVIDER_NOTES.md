# Terraform Provider — Go SDK Changes (v0.2.0 → v0.2.1)

Notes for the `terraform-provider-prisma-airs` on recent Go SDK changes that affect provider implementation.

## Breaking / Behavioral Changes

### ForceDelete now succeeds on non-JSON responses (v0.2.1)

`DoMgmtRequest` tolerates non-JSON 2xx responses by returning a zero-value response struct instead of erroring. This means:

- `Profiles.ForceDelete()` and `Topics.ForceDelete()` now return `nil` error on success
- `resp.Message` may be empty string (API returns plain text, not `{"message": "..."}`)
- Provider delete functions should check `err == nil` as the success indicator, not `resp.Message`

```go
// Before (broke with AISEC_SDK_ERROR:failed to parse response JSON)
resp, err := client.Profiles.ForceDelete(ctx, id, updatedBy)

// After (works — err is nil on success, resp.Message may be empty)
_, err := client.Profiles.ForceDelete(ctx, id, updatedBy)
if err != nil {
    return diag.FromErr(err)
}
```

## New Methods Available (v0.2.0)

### Profiles.GetByID

Client-side filter over `List()`. No dedicated API endpoint exists.

```go
profile, err := client.Profiles.GetByID(ctx, "profile-uuid")
```

- Returns `*SecurityProfile` or error if not found
- Lists up to 1000 profiles and filters by `ProfileID`
- Useful for Terraform `Read` functions

### Profiles.GetByName (fixed)

Now returns the highest revision when multiple revisions share the same name.

```go
profile, err := client.Profiles.GetByName(ctx, "my-profile")
```

- Previous behavior: returned first match (arbitrary revision)
- New behavior: returns match with highest `Revision` number

### Typed Action Enums

```go
// ProfileAction for model-protection, agent-protection, latency, data-protection
management.ProfileActionAllow    // "allow"
management.ProfileActionBlock    // "block"
management.ProfileActionAlert    // "alert"
management.ProfileActionDisabled // "" (disabled)

// ToxicContentAction for toxic-content model-protection (compound values)
management.ToxicContentHighBlockModerateAllow // "high:block, moderate:allow"
management.ToxicContentHighBlockModerateBlock // "high:block, moderate:block"
management.ToxicContentHighAllowModerateAllow // "high:allow, moderate:allow"
```

## Valid Protection Names (from live API)

Use these when building Terraform schema validation:

| Protection Type | Name | Valid Actions |
|----------------|------|--------------|
| model-protection | `prompt-injection` | `block`, `allow` |
| model-protection | `contextual-grounding` | `block`, `allow` |
| model-protection | `toxic-content` | compound ToxicContentAction values |
| model-protection | `topic-guardrails` | `block`, `allow` (requires `topic-list`) |
| agent-protection | `agent-security` | `block` only |
| data-protection | `data-leak-detection` | `block`, `""` |
| data-protection | `database-security-{create,read,update,delete}` | `block`, `allow` |

## Go Module Import

```
go get github.com/cdot65/prisma-airs-go@v0.2.1
```
