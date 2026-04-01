# SDK Update 003: `omitempty` on Bool Drops Explicit `false`

**SDK:** `prisma-airs-go` v0.4.0
**Package:** `github.com/cdot65/prisma-airs-go/aisec/runtime`
**File:** `aisec/runtime/models.go`

---

## Bug

`ModelConfiguration.MaskDataInStorage` uses `omitempty` on a `bool`:

```go
type ModelConfiguration struct {
    MaskDataInStorage bool `json:"mask-data-in-storage,omitempty"`
    // ...
}
```

Go's `encoding/json` treats `false` as the zero value for `bool`. With `omitempty`, `false` is **silently omitted** from the serialized JSON. The API never receives the field.

```go
// Setting false:
mc := &ModelConfiguration{MaskDataInStorage: false}

// Serializes to:
{}

// Expected:
{"mask-data-in-storage": false}
```

---

## Impact

The Terraform provider sets `mask_data_in_storage = false` but the field is dropped during JSON marshaling. The API never receives it, so the field is absent from the stored profile. On read-back, the profile lacks `mask-data-in-storage`, causing a mismatch between Terraform state and actual API state.

### Observed behavior

**Original profile** (created via UI):
```json
"model-configuration": {
  "mask-data-in-storage": false,
  "latency": { ... }
}
```

**Terraform-created profile** (same config):
```json
"model-configuration": {
  "latency": { ... }
}
```

`mask-data-in-storage` is missing entirely.

---

## Fix

Remove `omitempty` from the `MaskDataInStorage` JSON tag:

```diff
type ModelConfiguration struct {
-    MaskDataInStorage bool `json:"mask-data-in-storage,omitempty"`
+    MaskDataInStorage bool `json:"mask-data-in-storage"`
     // ...
}
```

This ensures `false` is always serialized. The field always exists on the API side so there's no risk of sending an unwanted default.

### Alternative: `*bool`

If "not set" vs "explicitly false" semantics are needed:

```diff
-    MaskDataInStorage bool  `json:"mask-data-in-storage,omitempty"`
+    MaskDataInStorage *bool `json:"mask-data-in-storage,omitempty"`
```

With `*bool`: `nil` = omit, `&false` = send `false`, `&true` = send `true`. This adds pointer handling complexity in consumers — only worth it if "absent" and "false" have different API semantics.

---

## Audit

Check all other `bool` fields with `omitempty` in the SDK for the same issue. Any `bool` + `omitempty` where the caller might need to send `false` explicitly has this bug.
