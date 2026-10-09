# Claude Code directional profile review: round 3

Actual Claude Code 2.1.270 output, session `5e6cbff2-369d-424b-9349-471a26f7ada0`.
Reviewed staged tree `42f85b5fef311558b872b776deeb62ffb125cc8c` against
`e23ad5d926afcf5b82e42de914802d27001236fa`. Round 2 was canceled during
corrections and supplied no completed score.

I've completed the independent review. Here are my findings.

## Verification performed

| Check | Result |
|---|---|
| `go test -race -count=1 ./aisec/runtime/` | pass (2.07s) |
| Focused `-run 'TestDirectionalProfile\|TestProfile'` verbose | all pass, including 9 validation subtests and ~28 malformed-field subtests |
| `go vet ./aisec/...` | clean |
| Provenance hashes (4 files) vs. `prisma-airs-sdk` working tree | all 4 match; `git rev-parse HEAD` = `4a80dbd…` as recorded |
| `testdata/directional-security-profile.json` vs. TS fixture | byte-identical (`diff -q`) |
| Host `make-check.log` / `docs-check.log` | gofmt/vet/golangci-lint/race all pass; 11 generated references in sync, **18 doc examples compiled**, build + 9 browser + 9 pixel tests pass |
| `git status --porcelain` | no unstaged residue, so `make check`'s `gofmt -s -w .` changed nothing |

`gofmt -l` and `sha256sum` were denied to me directly; the formatting evidence above is indirect (clean tree after a host `make check` that formats in place). The provenance hashes I verified myself — that closes the prior round's largest unverified item.

## Prior findings: all resolved

1. **nil `Extensions`** → `profile_json.go:257` always assigns the residual map (non-nil for any JSON object); pinned at `profile_json_test.go:283-284`.
2. **Embedding promotion** → documented, `directional-security-profiles.md:7-9`.
3. **`ModelProtectionConfig` `omitempty` wire change** → documented with the workaround, `:76-80`.
4. **`FieldPresence` lossy on unknown names** → `HasField` added (`profile_json.go:154`), on all 25 models; typo case pinned (`profile_json_test.go:285`).
5. **`JSONPresent` on nil nullable slice** → documented, `:63-64`.
6. **List envelope** → `SecurityProfileListResponse` gains all four methods; nullable `ai_profiles` emission preserved for constructed values and pinned (`profile_json_test.go:311-326`).
7. **Uncached reflection** → `sync.Map` keyed by `reflect.Type` (`:102-126`). The per-function `type plain X` declarations give ~100 distinct stable keys — bounded, no leak.
8. **Untyped double-marshal** → generic `profileRequest` constraint (`:314-324`); `DoMgmtRequest` only compacts the `json.RawMessage` (`mgmthttpclient.go:138-145`), so the policy is walked once; docs corrected at `:70-74` instead of overclaiming.
9. **Array-where-object** → `TestProfileRejectsArrayWhereObjectExpected`.
10. **feature-quality row** → section added, scores pending (see below).

I re-walked all 14 TS Zod schemas against `models.go` and confirm field and nullability parity, including `TopicArraySchema.topic` being nullable-but-required (Go: no `omitempty` + `profile:"nullable"`) and `options: z.array(z.unknown()).optional()` (Go: `[]json.RawMessage` + `omitempty`, so `null` is correctly rejected both sides). I traced the presence inference table by hand for every combination of override/nullable/nil/decoded and found no path that silently emits or swallows a value.

## New findings (all low, none blocking)

**1. `HasField` recognizes extension names but `SetFieldPresence` cannot address them.** `profile_json.go:209-213` fails marshal for any presence name outside the typed field set, while `profileHasField` (`:154-162`) returns true for stored extension keys, and the guide (`directional-security-profiles.md:29-31`) tells adapters to "Check `HasField(jsonName)` first." An adapter that gates `SetFieldPresence` on `HasField` gets a marshal-time `UserRequestPayloadError` for extension keys. The correct move is `delete(p.Extensions, name)`; the guide covers extensions separately but never connects the two. One sentence next to the `HasField` paragraph fixes it.

**2. Re-encoded key order is now alphabetical, undocumented.** `marshalProfileObject` returns `json.Marshal(map[string]json.RawMessage)` (`:222`); the stdlib sorts map keys, so `json.Marshal(profile)` no longer follows struct order. Semantically identical and every test compares trees, but it is visible to consumers who log, diff, or golden-test request bodies. Worth a line in the migration guide.

**3. The AST coverage check is one-directional.** `profile_json_coverage_test.go:72-78` requires the four methods on every type embedding `ProfileJSON`, but nothing requires a *new nested type reachable from `SecurityProfile`* to embed it. Such a type would quietly revert to stock `encoding/json` semantics (null→zero coercion, dropped unknowns) inside an otherwise strict tree, and `v.FieldByName("ProfileJSON").Set` (`profile_json.go:258`) panics on a wrapper written without the embed. All 25 reachable types are covered today — this is a guard gap, not a defect. A reachability walk from `SecurityProfile`/`CreateProfileRequest` in the same test would close it.

**4. Per-field double encoding remains.** Each field is `json.Marshal`ed (`:197`), then the assembled map is marshaled again (`:222`), re-scanning and HTML-escaping every fragment. With metadata now cached this is the residual per-detector cost on large `ListAll`. Performance only; acceptable for the fidelity gained.

**5. No local required-field validation, unlike TS.** `CreateSecurityProfileRequestSchema` requires `policy` and an offset-datetime `last_modified_ts`, and the TS client validates on the way out (`prisma-airs-sdk/src/management/profiles.ts:92,231`). Go's `marshalProfileRequest` only catches encoding/presence/extension faults, so `Create` with a nil policy reaches the server. This matches the Go repo's convention — targeted validation of UUIDs, bounds, and lengths rather than schema validation — and the brief scopes validation to "where runtime validation is required," so I would not change it. But it is a real TS-parity divergence that is recorded nowhere; one line in the guide would make it a stated choice.

**6. `docs/developer/feature-quality.md:60` still reads "The final independent review is pending."** Every other feature group carries a table row with scores; this section is prose only. It needs this review's scores before release.

Also noted, not a finding: `aisec/parity/testdata/operations.json` has no `runtime.ProfilesClient` rows (it covers the DLP management surface), so no parity pin exercises the new request encoding — pre-existing scope, and the new tests plus `client_test.go`/`alignment_test.go` cover it. `TestProfiles_CreatePreservesExplicitZeroAndFalse` (`alignment_test.go:143`) still passes, which is good independent evidence that the request path kept its explicit-zero/false behavior.

## Blockers

**None.** Nothing I found prevents merging.

Remaining pre-release steps: record the final scores in `feature-quality.md`, and tag/publish a module version containing this commit so Terraform can move off `v0.8.1` (intentionally pending separate authorization, correctly stated at `directional-security-profiles.md:136-143`).

## Scores

**Implementation standards — 9.2/10.** The presence/extension design held against every edge case I could construct: atomic re-decode into a fresh local, parent-level null rejection (the only way to catch `null` into a `*ProfilePolicy`, since `encoding/json` never calls `UnmarshalJSON` for it), extensions that cannot shadow typed fields even when omitted, value-receiver marshalers so slice elements work, copy-on-write presence and copy-on-set extensions, raw numbers preserved at four nesting depths, centralized OAuth transport untouched, stdlib-only, correct `aisec` error types. All eight code-level findings from round 1 are genuinely fixed, with tests pinning each, and I verified formatting/vet/lint externally rather than by inspection. The deductions are ergonomics and cost, not correctness: the `HasField`/`SetFieldPresence` asymmetry (#1), undocumented key reordering (#2), the one-directional coverage guard (#3), and per-field double encoding (#4). Above those sits a standing liability the requirement makes unavoidable — 704 lines of mechanical wrappers replacing `encoding/json`'s struct path for 25 types, where every future field depends on the `profile:"nullable"` tag and four hand-written methods being added correctly. The AST test now catches the common half of that; a reachability walk would catch the rest and is what I'd want before 9.5.

**Spec fulfillment — 9.4/10.** Every row of the contract table and all seven implementation items are satisfied, including the two the brief flagged as insufficient if skipped: presence is genuinely reachable by an adapter (`HasField`/`FieldPresence`/`SetFieldPresence`/`ResetFieldPresence`/`SetExtension`/`Extensions`, all in the generated reference), and local payload faults are classified as `UserRequestPayloadError` with `calls.Load() != 0` asserted across nine failure modes. Field parity with the TS model is exact, the fixture is byte-identical with hashes I verified, provenance is recorded separately from frozen pins, no GET-by-ID route was invented, and no snapshot churn. The two round-1 negative-case gaps and the list-envelope gap are closed. The deduction is for the TS-parity divergence in #5 and for an evidence ceiling that is inherent to the authorized material rather than a defect: `profile_client_test.go:40` asserts the create body equals the complete POST *response*, audit fields and `revision` and `profile_id` included. That is exactly the replay the brief authorized, and the guide (`:130-132`) and quality record now say so plainly — but it means there is still no evidence about which fields a real create omits, and the brief's "account separately for audit fields omitted deliberately by a request model" is satisfied only because no request model omits any.

**Documentation — 9.0/10.** All four previously-undocumented behaviors are now covered (embedding promotion, non-comparability, the `ModelProtectionConfig` wire change, `JSONPresent`-on-nil-nullable), and the most consequential rule — assigning `false` cannot express intent on a decoded omitted bool — is promoted into the construction table in bold. The runnable example compiles under the doc gate, the regenerated reference is in sync, and sidebar/nav/pixel checks pass. The evidence section is unusually honest: it separates observed contract from frozen OpenAPI, names the truncated create request, states that replay is not live certification, and spells out the release gap. The deductions: `directional-security-profiles.md:56-80` is a dense wall of rules for an audience that needs a decision table, the key-order change (#2) and the `HasField`→`SetFieldPresence` trap (#1) are unstated, and `feature-quality.md` carries a placeholder instead of a score row (#6). **This is below the owner's self-declared 9.1 documentation bar.** What closes it: the two missing sentences, the score row, and splitting the presence prose so the three-state Terraform rule is scannable. I'm reporting 9.0 rather than rounding up to the threshold — the gap is small and entirely additive.
