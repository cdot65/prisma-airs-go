# Harness design parity

The owner selected Prisma AIRS Harness as the documentation design authority.
The Go site copies its brand logo, global CSS, Prism theme, hero CSS, and article
layout exactly. The landing-page structure and configuration are adapted only
for Go product text, links, routes, and Go syntax highlighting.

## Pinned source

The source is [Prisma AIRS Harness commit 1885e40](https://github.com/cdot65/prisma-airs-harness/tree/1885e40eb1dc493ad5b47757694d077011afa431/docs-site).
`docs-site/design/harness/source.json` records the full commit and SHA-256 hashes
for every input. The reference archive contains the original files and harness package lockfile. The logo
is the same image, including its existing artwork and text.

| Design surface | Source file |
| --- | --- |
| Color, fonts, navbar, sidebar, code, callouts, footer | `src/css/custom.css` |
| Code token colors | `src/css/prism-airs.ts` |
| Hero, paths, cards, responsive layout | `src/pages/index.module.css` |
| Article width and mobile contents navigation | `src/theme/DocItem/Layout/` |
| Brand image | `static/img/brand-logo.png` |
| Page structure | `src/pages/index.tsx` |

The source uses Inter and JetBrains Mono. Desktop articles have the harness's
wide reading column and no right-hand contents panel. Mobile articles retain
contents navigation. The homepage uses the same two-column hero, spectrum
artwork, pills, numbered path cards, and quick-links band.

## Verify source and rendering

From `docs-site/`:

```sh
python3 scripts/design_source.py
npm run test:parity
```

Source checks require the copied files to match their pinned hashes. The
landing page and config must match the reference after the explicit text/link
replacements in `design/harness/copy.json`.

The pixel check builds an independent site from the archived harness source,
using its own locked Docusaurus 3.10.1 dependencies, with the same Go copy and
navigation inputs. It compares homepage, getting
started, and provider-pattern pages at desktop, tablet, and mobile sizes using
the same browser. Every pixel must match. Both images and any diff are written
to `test-results/` and attached to the Playwright result.

Using identical copy isolates typography, spacing, layout, and artwork from the
intentional differences between Go documentation and harness product content.
The check does not assert that a Go guide has the same words or total page
height as an unrelated harness guide.

## Refresh the design deliberately

Read the owner-selected harness checkout's actual source. Copy its design files
unchanged, refresh the reference archive and hashes, and review the product-copy
replacement list. Inspect both rendered sites and run all documentation checks.
An upstream design change should be an explicit update, not an automatic drift.

Attribution is recorded in `docs-site/NOTICE` and `THIRD_PARTY_NOTICES.md`.
The Go SDK remains MIT licensed; the reused theme components are Apache-2.0.
