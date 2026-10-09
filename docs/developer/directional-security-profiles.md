# Directional security profiles and Terraform migration

Runtime profile models support the legacy `model-configuration` layout and the
observed directional layout. Legacy callers keep their direct field access and
keyed struct literals. Expanded structs require keyed literals; small profile
structs with extension maps can no longer be compared with `==`. Compare fields
or JSON semantics instead. No conversion is required. Custom JSON methods are promoted if a consumer
embeds these types: an outer struct may serialize only the embedded profile and
drop its own fields. Prefer a named field or define the outer JSON methods. `ModelConfiguration` retains
latency, storage masking, and legacy protections; its new
`EnableFullConversationInspection *bool` distinguishes omission from false.

`AiSecurityProfileConfig.ContentTypeMode` is an open-ended string.
`ContentTypeConfigurations` holds optional `Prompt`, `Response`, `ToolCall`, and
`ToolResponse` pointers to `ProtectionConfiguration`. Each direction reuses
`DataProtectionConfig`, `AppProtectionConfig`, `ModelProtectionConfig`, and
`AgentProtectionConfig`. See the [profile examples](../examples/profile-crud.md#directional-profiles)
for runnable legacy and directional construction and an offline edit.

The families include optional detector `Severity` strings, URL detection
`UrlDetectedSeverity`, `SeverityByConfidence` with `High` and `Moderate`, nested
category and topic severities, `SourceCodeDetectionConfig`, and raw detector
`Options`. Actions, severities, and mode strings accept future values. Optional
`DLPTenantID` metadata is available on response, create, and update models; retrieval
may omit it. `CspID` and `TsgID` also retain observed response metadata.

## Presence API

Every profile model embeds `ProfileJSON` and exposes these public APIs. Names
are exact wire names, including hyphens or underscores from the relevant model.

| API | Behavior |
| --- | --- |
| `HasField(name string) bool` | Recognizes a typed field or a stored extension key, even if the typed field is omitted |
| `FieldNames() []string` | Returns a fresh sorted list of all known typed wire names, including omitted fields; enumerate extensions separately |
| `FieldPresence(name string) JSONPresence` | Reports `JSONOmitted`, `JSONNull`, or `JSONPresent` from the current typed value and presence state |
| `SetFieldPresence(name string, state JSONPresence)` | Overrides serialization of a known field; does **not** assign or clear its typed value |
| `ResetFieldPresence(name string)` | Removes the field's presence state and infers serialization from its current typed value |
| `SetMaskDataInline(value bool)` | Assigns the DLP masking boolean and marks `mask-data-inline` present |
| `SetMaskDataInStorage(value bool)` | Assigns the model masking boolean and marks `mask-data-in-storage` present |
| `SetExtension(name string, value json.RawMessage) error` | Validates and copies an extension value; initializes storage and copies the map |
| `Extensions map[string]json.RawMessage` | Public nested extension storage; use `delete(model.Extensions, name)` to remove an extension |

Check `HasField(jsonName)` first:
it recognizes typed names even when omitted and stored extension names. This
detects typos such as `mask_data_inline`. Presence setters address typed fields
only. For a stored extension, use `SetExtension` to replace it or
`delete(model.Extensions, name)` to omit it; `HasField` does not make extension
keys valid presence-setter targets.
`SetExtension` accepts a colliding typed name but its bytes will never be emitted;
the typed field controls serialization even when omitted. Use `FieldNames()` to
identify typed names and assign those fields with the presence helpers instead.

`FieldPresence(jsonName)` returns
`JSONOmitted`, `JSONNull`, or `JSONPresent` for the current serialized field.
Present includes explicit false, zero, empty strings, empty objects, and empty
arrays. Use JSON names, such as `mask-data-inline` and `database-security`.

Decoding preserves these distinctions. Successful decoding into a reused model
replaces its fields, presence state, and extensions. It does not insert defaults
or copy protections between directions. Invalid known JSON types fail decoding;
within policy models, null is accepted only for `DataLeakDetectionConfig.member`,
`URLCategoryMember.member`, `DataProtectionConfig.database-security`, and
`TopicArrayConfig.topic`. The profile list envelope
also preserves its legacy nullable `ai_profiles` array and future sibling fields. Detector `Options` can contain arbitrary JSON values.

For caller-built values:

| Intended wire value | Construction |
| --- | --- |
| Optional boolean false or true | Set the new pointer boolean to `&flag` |
| Existing masking boolean false | Constructed bool literals still work. **For a decoded omitted bool, use `SetMaskDataInline(false)` / `SetMaskDataInStorage(false)`; assigning false alone leaves it omitted.** |
| Omitted existing masking boolean | `SetFieldPresence("mask-data-inline", JSONOmitted)` or the storage equivalent |
| Nil nullable array marked present | `JSONPresent` still emits null; assign a non-nil empty slice to send `[]` |
| Nil non-nullable pointer/map/slice marked present | Marshaling rejects it |
| Empty array | Assign a non-nil empty typed slice, such as `[]runtime.AgentProtectionConfig{}` |
| Null database-security | Leave the slice nil and use `SetFieldPresence("database-security", JSONNull)` |
| Empty optional member ID | Set `ID: ""` and `SetFieldPresence("id", JSONPresent)` |
| Omitted decoded scalar | `SetFieldPresence(jsonName, JSONOmitted)` |
| Explicit zero/empty optional scalar | Assign the value and use `SetFieldPresence(jsonName, JSONPresent)` |

Caller-built required nullable arrays report `JSONNull` when nil, matching the
serialized value. To deliberately emit `{}`, assign a pointer to an empty object,
such as `&runtime.AppProtectionConfig{}`, or a non-nil empty typed map.

### Editing decoded values

Existing constructed `MaskDataInline`, `MaskDataInStorage`, and response `Active`
booleans still serialize false. Decoded omitted booleans stay omitted until set
true or explicitly marked present, as shown in the table. New optional booleans
use pointers.

Direct assignment uses the current typed value; the SDK never caches and replays
known raw values. Without an explicit override, a decoded present scalar remains
present after assigning false or an empty string. An omitted scalar assigned its
zero value stays omitted; mark it present to emit that value. Assigning nil to a
decoded optional, non-nullable object or list removes it. A nullable list assigned
nil becomes null if it was present; use `JSONOmitted` to remove it. Assigning a
non-nil slice to a decoded null array emits that array, including an empty slice.

Explicit overrides take precedence. `JSONOmitted` suppresses a field even when it
has a nonzero value. `JSONPresent` on a nil non-nullable object/list fails encoding;
after explicitly marking it present, clear that override or mark it omitted when
removing it. `JSONNull` requires a nullable nil value; assigning a non-nil value
afterward emits the new value. For example:

```go
// response is a decoded *runtime.ProtectionConfiguration.
response.ModelProtection = []runtime.ModelProtectionConfig{} // Emit [].
response.SetFieldPresence("model-protection", runtime.JSONPresent)
response.ModelProtection = nil
response.SetFieldPresence("model-protection", runtime.JSONOmitted) // Remove the field.
```

`SetFieldPresence` never clears the exported field. `ResetFieldPresence` removes
both decoded presence state and explicit overrides, then infers from the current
value. On a decoded model, zero scalars become omitted; retained nonzero values
become present. To remove a field durably, clear its typed value and mark it
omitted. To remove one detector, replace the list with the retained typed entries;
use a non-nil empty slice when removing the last entry should emit `[]`.

### Validation and compatibility

Unknown presence names, invalid states, and null on non-nullable fields fail
marshaling. Create and update classify local encoding failures as
`*aisec.AISecSDKError` with `aisec.UserRequestPayloadError` before OAuth/API I/O.
The centralized transport already serializes before token acquisition. Profile
encoding adds the error classification and passes validated raw JSON onward,
without walking the full policy twice.

Go retains optional request `Policy` and server validation of timestamp format.
TypeScript requires a policy at submission and validates an offset timestamp
when supplied. This is a deliberate compatibility choice for the existing Go
API; providers should supply their complete policy and valid timestamp metadata.

`ModelProtectionConfig.Name` and `Action` now use optional wire tags, matching the
observed TypeScript contract. A constructed `{Name: "x"}` omits `action` where
older versions emitted `"action": ""`. Use `SetFieldPresence("action", JSONPresent)`
to send an empty action. Keyed literals remain source compatible.

Modeled objects now encode keys in sorted order. Compare decoded JSON trees
rather than request-body bytes; key order is not policy meaning.

## Preserve provider state

The Terraform adapter must inspect `FieldPresence` before mapping values into
state. A nil slice alone cannot distinguish omission from null. A bool alone
cannot distinguish omission from false. Non-nil empty slices represent empty
arrays. Retain these three states in the provider's own model; do not normalize
null/missing arrays to empty or default missing booleans to false.

Persist policy JSON bytes with `json.Marshal(policy)` and restore them in the next
process with `json.Unmarshal(bytes, &policy)`. Every nested model restores presence
and extensions from the wire. Preservation does not require the original SDK
object or a private presence cache. Serialization stores the effective wire
state, not private override flags or suppressed typed values: a field omitted
from those bytes reloads as omitted with a zero/nil typed value. JSON key ordering
or whitespace may change; values, presence, and raw numeric precision survive.

When building an update, keep the decoded policy and edit the owned detector,
or restore values using the table above. To change response models into request
models while preserving top-level metadata and extensions, marshal the response
and unmarshal into `UpdateProfileRequest`; then explicitly omit any audit metadata
the provider does not intend to submit. `SetFieldPresence` works on request audit
fields too. Preserve `Revision` from the retrieved revision when the consumer
uses it. `GetByID` still searches paginated lists; update can return a new profile
ID and revision, so retain the returned identity.

## Forward-compatible fields

`ProfileJSON.Extensions` is a `map[string]json.RawMessage` at each profile, policy,
direction, family, and nested detector/member level. Future direction keys live
on `ContentTypeConfigurations.Extensions`. Successful decoding initializes
writable extension maps, even when no unknown fields were returned. For a
constructed model, use `SetExtension(name, json.RawMessage(...))` or initialize
the map before assigning keys. `SetExtension` validates and copies the input
bytes and copies the map. Keep these maps in provider state and
restore them when rebuilding requests. Known typed fields always win: colliding
extensions are ignored even when the typed field is omitted. Put known fields
in their typed members and use presence helpers rather than extension keys.

Unknown JSON numbers remain raw, without float conversion. Existing DLP rule
maps use `json.Number` on decode for the same reason. Profiles, maps, slices, and
pointer members should belong to one editor; a shallow struct copy still shares
those objects. A JSON round-trip provides an independent editable copy.

For a rebuilt object, preserve its known typed values, enumerate
`source.FieldNames()` and transfer presence with
`target.SetFieldPresence(name, source.FieldPresence(name))`, then copy extensions
with `SetExtension` at **each rebuilt level**. Do not transfer only the top-level
extension map. Enumeration avoids maintaining a separate list of wire names. A
struct copy preserves every known typed value; replace its `ProfileJSON` with
fresh public presence/extension state and rebuild owned nested objects as needed.
Copies still share pointers, slices, and maps until you copy those separately.

Transferred presence is an **explicit override**. The decoded-object nil-removal
shortcut therefore does not apply to a rebuilt field marked `JSONPresent`:
after assigning nil, use `SetFieldPresence(name, JSONOmitted)` to remove it, or
`ResetFieldPresence(name)` to infer from its current value. Clear scalar values
too when resetting an omission should keep them absent. The consumer test covers
removing a rebuilt confidence object with this rule.
Likewise, assigning a value to a rebuilt field that was omitted in the source
requires `SetFieldPresence(name, JSONPresent)` or `ResetFieldPresence(name)`;
otherwise its transferred `JSONOmitted` override still suppresses the new value.
The SDK provides JSON round-tripping and these public state primitives; consumers
implement any selective rebuilding or deep copying they need.

This complete, offline example transfers an explicitly empty ID
and a future field without relying on private SDK state:

```go
package main

import (
    "encoding/json"
    "fmt"

    "github.com/cdot65/prisma-airs-go/aisec/runtime"
)

func main() {
    var source runtime.DataLeakMember
    if err := json.Unmarshal([]byte(`{"text":"sensitive","id":"","future":900719925474099312345}`), &source); err != nil {
        panic(err)
    }
    target := source
    target.ProfileJSON = runtime.ProfileJSON{}
    for _, name := range source.FieldNames() {
        target.SetFieldPresence(name, source.FieldPresence(name))
    }
    for name, raw := range source.Extensions {
        if err := target.SetExtension(name, raw); err != nil {
            panic(err)
        }
    }
    body, err := json.Marshal(target)
    if err != nil {
        panic(err)
    }
    fmt.Println(string(body))
}
```

The external-package `aisec/runtime/profile_consumer_test.go` applies those APIs
to the full directional fixture. Separate processes reload disk bytes, rebuild
all four direction containers and their data/app/model/agent branches, change only
response toxicity, remove a
managed detector, and reload again. It compares entire policies so unrelated
directions, nested extensions, future direction keys, and large raw numbers must
survive. In-test additions of topic references, toxicity categories, source-code
settings, and nested extensions exercise branches absent from the original
fixture; the checked-in fixture remains unchanged. DLP members from the fixture
are rebuilt too.
Each child process confirms that its requested operation actually ran. It also
tests caller-built create/update requests with explicit false,
empty strings, empty objects, and empty lists. Run it with:

```sh
go test -race ./aisec/runtime -run TestTerraformProfileConsumer -count=1
```

Terraform owns detector identity matching, merge rules, and field ownership. The
SDK exposes wire fidelity and mutation primitives; it does not select which
detectors an adapter manages.

## Evidence and release status

The TypeScript SDK's `src/models/mgmt-security-profile.ts`, directional regression
tests, sanitized fixture, and Management guide are the observed-contract
reference. Severity/source-code/category/topic extensions were documented there
on 2026-09-08; directionality was supplied on 2026-10-09. The copied
`aisec/runtime/testdata/directional-security-profile.json` is the complete
sanitized POST response. The adjacent `directional-profile-provenance.json`
records hashes for the four reference files and identifies their uncommitted
working-tree state separately from the checkout HEAD. The GET fixture shape
removes `dlp_tenant_id`.
The original create request was truncated; response replay as input establishes
offline compatibility, not reconstruction of that request or independent live
certification. Fixture replay includes all supplied audit metadata, profile ID,
and revision because neither request model removes them automatically; it does
not establish which fields an independent live create should omit. Consumers
can explicitly omit audit fields with the presence API. Frozen OpenAPI snapshots
and coverage denominators are unchanged.

Terraform currently requires `github.com/cdot65/prisma-airs-go v0.8.1`; that
requirement does not include this work. Release **v0.9.0** includes the tested
implementation commit
[`f3104745312eea9208098f0ef9eb6a093ce48f95`](https://github.com/cdot65/prisma-airs-go/commit/f3104745312eea9208098f0ef9eb6a093ce48f95)
and its recorded Claude Code consumer review (standards 9.5/10, spec 9.6/10,
documentation 9.5/10). Update the provider dependency with:

```sh
go get github.com/cdot65/prisma-airs-go@v0.9.0
```

Remove any development `replace` when switching to the published module. See
[release instructions](releases.md) for assets and checksums. The CLI can migrate
independently. Verification remains offline; release publication does not add
live-tenant evidence.
