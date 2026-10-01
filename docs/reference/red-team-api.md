
## Current-schema methods and helpers

All 47 data-plane, 42 management-plane and five Network Broker operations in
`specs/manifest.json` have public HTTP contract tests. Existing methods retain
source-compatible types. Their `Details` counterparts return complete models
from `aisec/redteam/schema`; for example `Scans.ListDetails`,
`Targets.CreateDetails`, `Targets.UpdateDetails`, `Reports.GetStaticReportDetails`,
`Reports.GetAttackDetails`, and `CustomAttacks.CreatePromptSetDetails`. Typed
requests precede optional query arguments, as in
`Targets.CreateDetails(ctx, request, false)`.

Nullable optional values use `aisec.Value(value)`, `aisec.Null[T]()` or an unset
`aisec.Optional[T]`. This preserves explicit false, zero, empty collections and
null separately from omission. New target adapter variables, language, profiling
status, report metadata and nullable counts are available without changing the
legacy model fields. Union models offer typed constructors and `As...` accessors.
For current report methods, unsupported legacy `Search` options are omitted;
legacy methods retain their previous query behavior.

Additional helpers expose languages and goal categories, scan metadata and
runtime-profile association, static/dynamic ASR, report status/regeneration,
nullable threat overrides, target profiling, Copilot token lifecycle and error
log reads/downloads. `Reports.GetDownload` returns the v2 filename/short-lived
URL receipt; `Reports.DownloadReport` retains v1 raw bytes. The SDK does not
follow the receipt's URL or expose it to logging automatically.

Profiling, report regeneration and threat overrides are explicit mutations.
Copilot authentication requires caller-managed Azure credentials and browser
consent. These mutations have mock contract verification; the live probe does
not change existing jobs or profiles. See [live verification](../developer/live-verification.md).
The documented scan-metadata route currently returns HTTP 422 on the tested
production tenant; the SDK preserves that typed error (see `API_ISSUES.md`).
