"""Build the pinned harness reference and compare it with the Go site's pixels."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from design_source import SITE, reference_files, verify


def main():
    verify()
    _, files = reference_files()
    with tempfile.TemporaryDirectory(prefix="airs-harness-design-") as directory:
        reference = Path(directory)
        for relative, content in files.items():
            path = reference / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if relative == "docusaurus.config.ts":
                content = content.replace(b"path: '../docs'", b"path: './docs'")
            path.write_bytes(content)
        # Navigation and guide copy are shared inputs; renderers, CSS, and home
        # layout come independently from the pinned harness source archive.
        for relative in ["tsconfig.json", "sidebars.ts"]:
            shutil.copy2(SITE / relative, reference / relative)
        shutil.copytree(SITE.parent / "docs", reference / "docs")
        subprocess.run(["npm", "ci", "--registry=https://registry.npmjs.org/", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=reference, check=True)
        (reference / "static/img/logo.svg").write_bytes((SITE / "static/img/logo.svg").read_bytes())
        command = str(reference / "node_modules/@docusaurus/core/bin/docusaurus.mjs")
        subprocess.run(["node", command, "build"], cwd=reference, check=True)
        env = dict(os.environ, PARITY_REFERENCE_DIR=str(reference))
        subprocess.run([str(SITE / "node_modules/.bin/playwright"), "test", "--config", "playwright.parity.config.ts"], cwd=SITE, env=env, check=True)


if __name__ == "__main__":
    main()
