# October 2026 live verification

Checks ran against an entitled tenant on 2026-10-01 using credentials loaded
externally through AIRS CLI configuration. Credentials, tokens, API-key material,
and deployment auth codes were not logged or saved. Only uniquely named
temporary resources are mutated, with cleanup assertions.

## Runtime Security

* Profile/topic/API-key listing: HTTP 200 using existing TSG-qualified routes.
* Supplied-spec routes `/v1/mgmt/profiles`, `/v1/mgmt/topics`, and
  `/v1/mgmt/apikeys`: HTTP 200 as well. Existing routes remain supported aliases.
* Topic create/list/update/delete: passed; temporary topic cleaned up.
* Profile create/list/lookup/update/force-delete: passed; all revisions cleaned up.
* Topic deletion and ordinary/force profile deletion return a JSON string with
  `Content-Type: application/json`, e.g. `"successfully deleted topicId: <id>"`.
  This confirms the string-or-object decoder is necessary.
* Old topic force URL `/v1/mgmt/topic/force/{id}` returned HTTP 403; supplied-spec
  `/v1/mgmt/topic/{id}/force` returned HTTP 200 and removed the temporary topic.
* Nonexistent-key regeneration reached the handler at supplied-spec
  `/v1/mgmt/apikey/regenerate/{id}` (HTTP 403, TsgID mismatch); reversed old route
  returned generic HTTP 403. Successful disposable-key creation/regeneration also
  reached the new route; rotation returns a replacement key ID.
* API-key deletion returns a JSON string (`"apikey and customer-app successfully
  deleted"`), rather than the documented message object. It remains strict JSON
  but accepts both shapes through the runtime-local adapter.
* Disposable API-key create/regenerate/delete and associated app cleanup passed.
  Creation requires a key name of at most 31 characters and valid customer-app
  metadata. Failed probes established those constraints before a successful run.
* Explicit `latest=false` and `unactivated=false` query checks passed.

## Verification categories

Mock contracts establish request construction, decoding, errors, and compatibility
against pinned inputs. Recorded tenant evidence and new live checks are separate:
an operation is not live-verified merely because another in its family succeeded.

### Model Security current-contract probe (2026-10-01)

The selected CLI production tenant authenticated but returned **No active
license found** for model inventory, custom-rule listing, custom-rule snapshot
history, and security-rule snapshot history. These live assertions failed; they
are not successful endpoint verification. No Model Security resources were
created or changed. An enabled tenant is needed to exercise live custom-rule
lifecycle/assignment and inventory details. The public-client mock matrix covers
all 41 pinned operations plus seven alternatives for precise nullable models.

The user supplied a second CLI tenant with Model Security enabled. On that
account the focused live suite passed: model list/get, model version list/get,
version file list, custom-rule list, custom-rule and PANW-rule snapshot histories,
plus disposable security-group creation/deletion and custom-rule create/get,
update, assignment (HTTP 207), assigned-instance read, assigned-group list,
rule-instance history, assignment removal, archive and unarchive. Cleanup
archived the disposable custom rule (there is no delete endpoint) and deleted
the disposable security group. No existing policies or rules were modified.
The race-enabled live run completed successfully in 5.858 seconds.

### Red Team adapters and Network Broker (2026-10-01)

On the selected production CLI tenant, adapter config and disposable DRAFT
create/get/search/update/delete passed, including an explicit description clear
and a subsequent read. The service returns JSON null for an empty description;
the SDK preserves that null. Every draft created during the probes was deleted.

Network Broker stats/list/get passed on its separate OAuth service base. No
existing channel was changed. Channel create/PATCH and adapter active execution
validation have public-client mock coverage; they were not exercised live. The
broker has no delete/archive endpoint, so this probe did not create a permanent
test channel. A connected broker and target fixture are required for executing
an adapter validation. The final focused race-enabled live run passed in 11.003
seconds. Earlier description assertions failed before the service's null
canonicalization was recorded and accommodated in the test.

### Red Team current-schema reads and disposable CRUD (2026-10-01)

Languages on both planes, goal categories, report status, ASR, v2 download
receipt, raw job error-log download and target-profile error-log reads passed.
The documented `/v1/scan/scan-metadata` returned HTTP 422 with
`code=validation_error`, `message=Request validation failed`. No undocumented
alias was found: `/v1/scan-metadata` and the trailing-slash form returned 403;
`/v1/scan/metadata` returned 422. No body details identifying a required parameter
were returned. The SDK retains the published path and surfaces the failure;
the metadata integration assertion remains strict and currently fails live.

The precise-model live suite passed quota, scan statistics, dashboard overview,
categories, target listing, prompt-set and active-set listing, property names,
job listing/detail, error logs, and available completed static/dynamic/custom
report and list reads. Disposable DRAFT target create/get/update/delete and
prompt-set create/get, prompt create/get/list/delete also passed. Cleanup archived
the disposable prompt set because no delete endpoint exists. These strict tests
passed with the race detector in 51.193 seconds. Regeneration, overrides,
profiling execution and Copilot consent flows were not performed against existing
resources. Every pinned operation has mock request/payload/response/error coverage.

### Gateway management (2026-10-01)

SCM OAuth plus `x-tsg-id` authenticated both bases. Existing-workspace discovery
was read-only. Listing passed for all twelve resource families; combined
`/api-keys` returned 403, while `/api-keys/service` and `/api-keys/user` passed.
Explicit service/user methods cover that deployment difference.

Disposable config create/get/update/version history/delete, workspace and org
guardrail create/get/update/delete, service-key create/get/update/rotate/delete,
usage/rate policy create/get/update/delete (and usage counter listing), deployment
create/get/update/archive, and AWS service-role secret-reference metadata
create/get/update/delete passed in an 80.757-second race run. No external secret
was fetched, no existing policy changed, and the conditions match only the unique
test metadata value. Archived test deployments remain archived by API design.

Org MCP integration create/get/update, workspace binding, metadata read, server
create/get/update, capability/connection/user-access listing and cleanup passed.
The fixture uses a public MCP URL with no external credentials. No tool execution
or inference request was sent. Org provider integration create/get/update,
model/workspace listing, workspace binding, provider create/get/update/delete and
integration cleanup passed in a focused 20.447-second race run.

Early workspace-scoped integration creates returned 403. Org creation plus
explicit binding worked. An early OpenAI name match selected Azure OpenAI and
returned validation error; exact provider catalog selection corrected the
fixture. Earlier creates that succeeded were cleaned up even when a later
assertion failed. Both linked graphs subsequently passed together in a 50.607-second race run.

All 88 source operations and ten explicit service/user route variants have HTTP
contracts. User-key creation requires a caller-owned user fixture; connectivity
execution, traffic-derived usage resets and production capability/access changes
remain mock-verified. Disposable CRUD does not prove every helper executed live.

### Existing Terraform consumer compatibility

The existing provider pinned v0.4.1 and still constructed the legacy prompt-set
`Properties` map. An earlier SDK revision had removed that field. It is restored
alongside `PropertyNames`, preserving its prior wire representation; the newer
contract does not guarantee service support for legacy `properties` metadata.
This change avoids a consumer compile break without inventing a conversion.
Provider verification uses an external temporary modfile with a local SDK
replacement and `TF_ACC=0`, leaving its tracked dependency configuration intact.
