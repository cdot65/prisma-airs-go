# October 2026 OpenAPI integration

## Agreed scope

Integrate the supplied Runtime Security, Model Security, Red Team, and AI Gateway
specifications in that order, in small endpoint groups. Include models and the
five Red Team Network Broker operations. Preserve existing public operations
omitted from newer specifications until removal is supported by evidence.

Gateway covers configs, workspace guardrails, org guardrails, providers,
integrations, MCP integrations, MCP servers, API keys, usage limit policies,
rate limit policies, secret references, and deployments, including lifecycle
helpers. Require an existing workspace. Inference, streaming, Realtime,
analytics, feedback, pricing, and workspace/IAM provisioning are out of scope.

## Interfaces and compatibility

Keep Go 1.22 and the stdlib-only dependency policy. Use the shared OAuth request
pipeline, context-first methods, injected HTTP clients, escaped identifiers,
and typed SDK errors. Changes are additive first. Preserve existing field types
and methods; expose richer contracts through new types/methods where needed.
Isolate unavoidable breaking changes and provide migration guidance.

SDK operations remain explicit. Create/read responses differ where credentials
are returned once. The Terraform provider owns refresh, reconciliation, timeouts,
and state. Document partial PUT semantics, whole-document config replacement,
binding ownership, and archival deletion without implicit read-after-write,
polling, secret synthesis, or ownership changes.

## Evidence and verification

Pin source commits and SHA-256 hashes; info.version alone is insufficient.
Preserve source artifacts exactly and record corrections/exceptions separately.
Every operation needs public-client HTTP contract coverage for verb, path,
plane, queries, payload, response, and errors. Exercise nullable/optional fields,
explicit false/zero/empty updates, malformed replies, and known delete exceptions.
Use targeted live checks for disputed routes, auth, shapes, and deletion results.
Distinguish mock-tested, recorded live evidence, and newly live-verified support.

Validate the existing Terraform provider against the local SDK through a
temporary dependency override; provider resource implementation is separate.
Update SDK docs, API exceptions, release notes, and knowledge-workspace coverage.

## Quality and release

Independent standards/spec reviews score each feature 1–10 against correctness,
contract coverage, compatibility, locality, and documentation. Address required
findings and iterate until each score is at least 9. Scores express review
judgement, not production guarantees; keep live evidence separately recorded.
Run make check, supported-toolchain tests, integration-build checks, and consumer
validation. Keep the v0.5.2 response hotfix in a separate commit. Cut the feature
release only after the above checks, provide module/source artifacts, example
binaries for supported platforms, checksums, and reproducible build instructions.
