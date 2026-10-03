# Release artifacts

Install the SDK in a Go application or Terraform provider:

```sh
go get github.com/cdot65/prisma-airs-go@v0.8.1
```

The GitHub release supplies the committed source, build provenance, SHA-256
checksums, and example executables for Linux, macOS, and Windows on amd64 and
arm64. Each platform archive contains all three executables:

| Executable | Purpose | Configuration |
|---|---|---|
| `gateway-read` | Read a configuration page count from an existing Gateway workspace | `PANW_AI_GW_*` or `PANW_MGMT_*`; `-workspace-id ID` |
| `basic-scan` | Submit sample synchronous and asynchronous scans | `PANW_AI_SEC_API_KEY`, `PANW_AI_SEC_PROFILE_NAME` |
| `profile-crud` | Create, read, update, and force-delete an example profile | `PANW_MGMT_*` |

Windows executables have an `.exe` suffix. Run `-version` to verify v0.8.1 or
`-help` for usage without making API requests. The scanning and profile examples
perform the operations listed above when invoked normally. Gateway output
contains only a page count; it does not print resource configuration or keys.
These examples exercise the SDK; they are not Terraform provider executables.
Provider resource implementation remains in the separate provider repository.

Download `SHA256SUMS` alongside the desired asset. For example, on Linux:

```sh
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf prisma-airs-go-v0.8.1_linux_amd64.tar.gz
./gateway-read -version
./gateway-read -workspace-id YOUR_EXISTING_WORKSPACE_ID
```

On macOS, verify the selected file using `shasum -a 256 FILE` against
`SHA256SUMS`. On Windows use `Get-FileHash FILE -Algorithm SHA256` and
`Expand-Archive` for the platform ZIP. Choose the archive matching the operating
system and architecture of the machine that will execute it.

## Reproduce a build

Use Python 3, Git, and Go 1.24.6. Start with a clean checkout of the release tag;
the output directory must be empty and outside the checkout.

```sh
git checkout v0.8.1
GOTOOLCHAIN=go1.24.6 python3 scripts/release_artifacts.py \
  --version v0.8.1 --output /tmp/prisma-airs-v0.8.1
```

The script validates the version and clean working tree, disables CGO, strips
absolute paths, embeds Go VCS metadata, and builds all six platform combinations.
Ambient Go flags, experiments, workspaces, and CPU tuning are normalized to
baseline amd64 v1 and arm64 v8.0. Archive timestamps and ownership are fixed;
the same commit, Go toolchain, and
compression implementation produce the same assets. `build-info.json` records
the commit, toolchain, platforms, and flags. The source archive comes from
`git archive HEAD`, so untracked credential files are excluded.

Release CI verifies formatting, vet, race tests, package builds, and tag/version
agreement before building and uploading assets. The Go module is distributed
through the normal Go proxy rather than an invented standalone SDK executable.

See [live verification](live-verification.md) for the exact exercised operations,
mock-only helpers, and the live Red Team scan-metadata HTTP 422 limitation. Review
scores in [feature reviews](feature-quality.md) express independent judgement,
not a guarantee about every tenant or upstream API response.
