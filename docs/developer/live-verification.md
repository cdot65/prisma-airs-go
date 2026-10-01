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
