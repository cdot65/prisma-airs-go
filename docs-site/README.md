# Go SDK documentation

Docusaurus at https://cdot65.github.io/prisma-airs-go/.
The harness checkout is the exact design authority. Global CSS, Prism
palette, hero CSS, and DocItem layout are copied unchanged. Go guides live in
`../docs`. Private Node tooling does not change the SDK's stdlib-only Go module.
The navbar, homepage, and favicon use the owner-supplied Go SDK logo selected
on 2026-10-03. Its hash is pinned as an asset override in `design/harness/source.json`.

Use Node 24, Go 1.22+, and Python 3.12+ (CI uses Go 1.24.6):

```sh
npm ci
npx playwright install chromium
npm run check
```

`check` verifies source parity, generated API reference, complete Go example
compilation, TypeScript, strict links/anchors, production build, browser routes,
and pixel comparisons. `npm start` serves local development; `npm run serve`
serves the production build. On Alpine use system Chromium and
`CHROMIUM_PATH=/usr/bin/chromium npm run check`.

The pixel check builds an independent reference from
`design/harness/reference.tar.gz` using the harness’s own locked Docusaurus 3.10.1 dependencies and the explicit
Go text/link adaptations in
`copy.json` and the same owner-selected logo override. Homepage and article screenshots must match exactly at desktop,
tablet, and mobile sizes. Failures retain reference/actual/diff PNGs in
`test-results/`, which CI uploads. The temporary reference is removed afterward.

Regenerate method reference from the root with
`go run scripts/generate_api_reference.go`. `scripts/check_doc_examples.py`
compiles complete programs from the public guides; it makes no live API calls.

Existing `/services/`, `/reference/`, `/developer/`, and example URLs remain
published. The homepage is a full-width React page; the docs overview is
`/overview/`. Pages builds use `.github/workflows/deploy-docs.yml`.

Read `../docs/developer/design-parity.md` before changing design inputs.
`design/harness/source.json` records the source commit and hashes. Preserve the
applicable source notices in `NOTICE` and `THIRD_PARTY_NOTICES.md` and the full
Apache-2.0 license. The Go SDK remains MIT licensed.
