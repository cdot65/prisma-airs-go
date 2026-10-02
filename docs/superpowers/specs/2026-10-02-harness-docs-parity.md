# Harness documentation parity

The owner requests exact design parity with
`/home/cdot/development/cdot65/prisma-airs-harness`: the same logo, hero,
fonts, colors, spacing, article layout, and responsive behavior. That checkout
is the design authority; use its actual files, not the earlier CLI-derived layout.

Copy the brand asset, global CSS, Prism theme, hero CSS, and DocItem layout
unchanged. Reuse the landing-page structure, adapting product copy and links for
Go. Preserve the existing public guide paths. Retain accurate Go 1.22+/stdlib
and Gateway existing-workspace management scope.

Deliver a numbered getting-started walkthrough, credential guide, examples for
all four service domains, Gateway CRUD, provider update semantics, troubleshooting,
full public method reference, and contributor instructions. Complete Go examples
must compile. Reference generation must detect stale output.

Verify desktop, tablet, and mobile. Compare reference and Go renders with controlled
identical copy to isolate design pixels, and compare real page typography/geometry.
Record the harness commit and copied-file hashes. CI must run these checks, then
publish the site and verify live routes and navigation.
