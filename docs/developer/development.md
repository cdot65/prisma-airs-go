# Development

The Go module and documentation tooling have separate dependencies. SDK code
uses the Go standard library and supports Go 1.22+. Docusaurus uses private Node
dependencies under `docs-site/`.

## Before you start

Use the SDK checkout and read its `AGENTS.md` for code conventions. The pinned
OpenAPI inputs live in `specs/manifest.json`; Gateway scope lives in
`specs/gateway_scope.json`. Service guides document public behavior, while live
verification records observed limits separately.

## 1. Validate Go changes

```sh
make check
```

This formats Go source, runs vet and lint, and executes race-enabled tests. The
current lint toolchain is Go 1.24.6 with golangci-lint v1.64.8. The CI test matrix
also covers Go 1.22 and 1.23. Use the toolchain matching the lint binary when a
newer local Go cannot read its export data.

```sh
GOTOOLCHAIN=go1.24.6 make check
```

HTTP tests use local mock token/API servers; they need no tenant credentials.
Live integration tests are separate and require explicitly selected service
credentials and disposable resources. Read [live verification](live-verification.md)
before running them.

## 2. Edit documentation

Use Node 24, matching the harness and CI:

```sh
make docs-install
cd docs-site
npx playwright install chromium
npm start
```

Edit guides in `docs/`, the landing page in `docs-site/src/pages/`, and navigation
in `docs-site/sidebars.ts`. Preserve published page paths. Examples labeled as
complete programs must include imports and `main`; snippets may assume a client
and context.

The harness checkout is the design authority. Its logo, global CSS, Prism theme,
hero CSS, and DocItem layout are copied unchanged. [Design parity](design-parity.md)
records the source and explains how to refresh and verify those files.

## 3. Regenerate reference after API changes

From the repository root:

```sh
go run scripts/generate_api_reference.go
go run scripts/generate_api_reference.go -check
python3 scripts/check_doc_examples.py
```

The reference includes every exported service method and package function,
with catalogs linking public models to their full versioned declaration. Edit
the Go declaration or comment and regenerate; generated pages are not the
source of truth.

## 4. Verify the site

```sh
make docs-check
```

Checks cover TypeScript, strict links/anchors, the production build, preserved
URLs, responsive navigation, code/Mermaid rendering, screenshots, and reference
style contracts. On Alpine, install system Chromium and pass
`CHROMIUM_PATH=/usr/bin/chromium`.

The independent render comparison builds the harness design in a temporary
fixture with the same Go copy, then compares screenshots. It isolates design
pixels from intentional product text differences. See [design parity](design-parity.md)
for the command and artifacts.

## 5. Publish documentation or a release

Documentation pull requests build and check the site. A successful main push
deploys to [GitHub Pages](https://cdot65.github.io/prisma-airs-go/). Verify the
public routes after publication with `DOCS_URL`:

```sh
cd docs-site
DOCS_URL=https://cdot65.github.io/prisma-airs-go/ npm run test:browser
```

SDK tags and binaries follow the separate [release guide](releases.md). A docs
update does not change a published Go module tag or release artifact.
