# Feature review scores

Independent standards/spec reviews assess correctness, tests, compatibility,
locality, and documentation. Required findings must be fixed before release.
Scores are review judgement, not production guarantees; consult
[live verification](live-verification.md) for exercised operations.

| Feature | Standards | Spec | Evidence |
|---|---:|---:|---|
| Response interpretation / text delete compatibility | 9/10 | 9.5/10 | Independent reviews; race tests; live JSON-string deletes |
| Runtime current spec alignment | 9.5/10 | 9.4/10 | Review of `44f6a90...7f803a9`; 21-operation payload/query/error matrix; live disposable CRUD/rotation |
| Model Security inventory/custom rules/history | 9.5/10 | 9.4/10 | Review of `7f803a9...83aa6ed`; 41-operation contracts plus seven precise alternatives; live inventory/lifecycle/assignment/cleanup |
| Red Team adapters and Network Broker | 9.5/10 | 9.4/10 | Review of `83aa6ed...02d02b2`; 12-operation contracts; live disposable draft CRUD/cleanup and broker reads |
| Red Team current reports, metadata and complete models | 9.2/10 | 9.3/10 | Review of `02d02b2...6f493c8`; all 94-operation public contracts; strict live reads/disposable CRUD; upstream metadata HTTP 422 documented |

| Shared Gateway foundation | 9.2/10 | 9/10 | Independent fixed review `6f493c8...f1512e9`; public HTTP contracts and operation-specific live evidence |
| Gateway configs | 9.3/10 | 9/10 | Independent fixed review `6f493c8...f1512e9`; public HTTP contracts and operation-specific live evidence |
| Gateway workspace guardrails | 9.3/10 | 9/10 | Independent fixed review `6f493c8...f1512e9`; public HTTP contracts and operation-specific live evidence |
| Gateway org guardrails | 9.3/10 | 9/10 | Independent fixed review `6f493c8...f1512e9`; public HTTP contracts and operation-specific live evidence |
| Gateway providers | 9.3/10 | 9/10 | Independent fixed review `6f493c8...f1512e9`; public HTTP contracts and operation-specific live evidence |
| Gateway integrations | 9.1/10 | 9/10 | Independent fixed review `6f493c8...f1512e9`; public HTTP contracts and operation-specific live evidence |
| Gateway MCP integrations | 9.1/10 | 9/10 | Independent fixed review `6f493c8...f1512e9`; public HTTP contracts and operation-specific live evidence |
| Gateway MCP servers | 9.2/10 | 9/10 | Independent fixed review `6f493c8...f1512e9`; public HTTP contracts and operation-specific live evidence |
| Gateway API keys | 9.3/10 | 9/10 | Independent fixed review `6f493c8...f1512e9`; public HTTP contracts and operation-specific live evidence |
| Gateway usage limits | 9.3/10 | 9/10 | Independent fixed review `6f493c8...f1512e9`; public HTTP contracts and operation-specific live evidence |
| Gateway rate limits | 9.4/10 | 9/10 | Independent fixed review `6f493c8...f1512e9`; public HTTP contracts and operation-specific live evidence |
| Gateway secret references | 9.3/10 | 9/10 | Independent fixed review `6f493c8...f1512e9`; public HTTP contracts and operation-specific live evidence |
| Gateway deployments | 9.3/10 | 9/10 | Independent fixed review `6f493c8...f1512e9`; public HTTP contracts and operation-specific live evidence |
| Legacy prompt-set Properties compatibility | 9.5/10 | 9/10 | Independent fixed review `6f493c8...f1512e9`; public HTTP contracts and operation-specific live evidence |
| Release preparation and example artifacts | 9.2/10 | 9/10 | Independent review of version, six-platform builder, flags, provenance, normalized Go environment, CI, and docs |

Each integration feature group must reach at least 9/10 on both review axes.

Final Gateway reviews found no required findings. Optional improvements concern
Gateway normalization locality, coordinated operation-wrapper/fixture
maintenance, and more direct typed helpers for flexible configuration documents.
These do not change recorded wire compatibility or the agreed release scope.

## v0.8.1 workspace clearing review

The owner requires at least **9.1/10 on both axes** for this integration.
The first actual Claude Code review identified evidence/coverage/documentation
gaps; corrections were independently re-reviewed through four rounds before publication.

| Feature | Standards | Spec | Evidence |
|---|---:|---:|---|
| Typed workspace settings clearing | 9.4/10 | 9.4/10 | Selective wire bodies, validation and typed HTTP errors |
| Workspace clearing tests and live verification | 9.2/10 | 9.5/10 | Per-field populated-to-cleared receipts and independent cleanup |
| v0.8.1 documentation and release preparation | 9.3/10 | 9.3/10 | Go checks, generated references, browser and pixel checks |


## Observed directional security profiles

The owner requires at least **9.1/10** for implementation and documentation.
Actual Claude Code review of the observed-profile change initially scored
implementation standards 8.5/10, spec fulfillment 9/10, and documentation 8.5/10.
Follow-up changes initialize extension maps, expose `HasField` and `SetExtension`,
cache scoped JSON metadata, check wrapper coverage, preserve list-envelope
extensions, encode policies once, and document embedding and legacy empty-action
wire behavior. Completed reviews are recorded below; subsequent corrections are
reviewed separately rather than assigning a score before the reviewer returns.

| Review snapshot | Standards | Spec | Documentation |
|---|---:|---:|---:|
| Initial implementation | 8.5/10 | 9/10 | 8.5/10 |
| Staged tree `42f85b5` after initial corrections | 9.2/10 | 9.4/10 | 9/10 |
| Final staged tree `a2468f3` | **9.4/10** | **9.5/10** | **9.4/10** |

The intermediate review found no blockers but placed documentation below the
required bar. Follow-up edits clarify extension removal, sorted JSON keys, and Go request
validation choices, and split presence rules into construction/editing/validation
sections. A separately reproduced caller-built nullable-array accessor issue is
corrected with regression tests; reachability checks now cover future nested
profile models as well as existing embedded models. The final actual Claude Code
review confirms all prior documentation concerns are resolved, exceeds the
9.1/10 target on all three axes, and reports no blockers. The verbatim receipt is
`plans/reviews/directional-security-profiles-claude-final.md`. Remaining nits concern
codec cost, guard allowlisting, and documentation placement; none changes the
recorded wire behavior.

Acceptance evidence is offline: complete sanitized POST and derived GET fixtures,
exact policy JSON comparisons, isolated edits, malformed-field validation, and
mocked OAuth create/list/GetByID/update. Audit fields are replayed because request
models retain them; no independent live create request was captured in full.
The TypeScript source hashes are recorded separately from frozen OpenAPI pins.
Go race/build/lint checks and documentation source/example/browser/pixel checks
pass; a tagged SDK version for Terraform consumption remains a separate release
step. Scores describe review judgement, not live tenant certification.
