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

Every profile model embeds `ProfileJSON`. Check `HasField(jsonName)` first:
it recognizes typed names even when omitted and stored extension names. This
detects typos such as `mask_data_inline`. Presence setters address typed fields
only. For a stored extension, use `SetExtension` to replace it or
`delete(model.Extensions, name)` to omit it; `HasField` does not make extension
keys valid presence-setter targets.

`FieldPresence(jsonName)` returns
`JSONOmitted`, `JSONNull`, or `JSONPresent` for the current serialized field.
Present includes explicit false, zero, empty strings, empty objects, and empty
arrays. Use JSON names, such as `mask-data-inline` and `database-security`.

Decoding preserves these distinctions. Successful decoding into a reused model
replaces its fields, presence state, and extensions. It does not insert defaults
or copy protections between directions. Invalid known JSON types fail decoding;
within policy models, null is accepted only for DLP/URL member arrays,
database-security arrays, and nullable topic buckets. The profile list envelope
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

### Editing decoded values

Existing constructed `MaskDataInline`, `MaskDataInStorage`, and response `Active`
booleans still serialize false. Decoded omitted booleans stay omitted until set
true or explicitly marked present, as shown in the table. New optional booleans
use pointers.

Assigning a non-nil slice to a decoded null array emits that array, including an
empty slice. `JSONOmitted` suppresses a field even when it has a value.
`ResetFieldPresence(jsonName)` removes a presence override; decoded zero scalars
then become omitted. Caller-built required nullable arrays report `JSONNull`
when nil, matching the serialized value.

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
requirement does not include this work. The next authorized release must tag a
commit containing these changes, update SDK version/reference metadata according
to [release instructions](releases.md), and publish the corresponding module.
Until then, use a local `replace` for development. The handoff reports the exact
implementation commit and review artifact; neither is a published version.
The CLI can migrate independently. This change does not perform live writes,
tagging, or publication.
