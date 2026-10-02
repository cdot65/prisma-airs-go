# Go SDK documentation

Docusaurus documentation at https://cdot65.github.io/prisma-airs-go/.
The site follows the AIRS SDK, CLI, and harness documentation structure. Go
guides remain in `../docs`; edit those files directly. Node dependencies are
private documentation tooling and do not change the SDK's stdlib-only Go module.

With Node 22 or later (CI uses Node 24):

```sh
npm ci
npm run typecheck
npm run build
npx playwright install chromium
npm run test:browser
```

On Alpine Linux, install the system Chromium package and run browser checks
with `CHROMIUM_PATH=/usr/bin/chromium npm run test:browser`.

Use `npm start` for local development. Builds fail on broken links and anchors.
Published page paths are preserved from the previous MkDocs site, including
`/services/`, `/reference/`, and `/developer/`. Deployment uses the existing
GitHub Pages Actions environment through `.github/workflows/deploy-docs.yml`.

The AIRS palette and Prism theme derive from the harness; the accessible,
collapsible on-page navigation derives from the CLI. Attribution and their
Apache-2.0 license are included in `THIRD_PARTY_NOTICES.md` and
`LICENSE-APACHE-2.0`. The Go SDK remains MIT licensed.
