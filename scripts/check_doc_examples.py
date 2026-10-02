#!/usr/bin/env python3
"""Compile complete Go programs in public guides; snippets remain contextual."""

from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    count = 0
    with tempfile.TemporaryDirectory(prefix="prisma-airs-go-doc-examples-") as directory:
        for path in sorted((ROOT / "docs").rglob("*.md")):
            if {"agents", "superpowers", "generated"} & set(path.parts):
                continue
            for index, match in enumerate(re.finditer(r"^```go[^\n]*\n(.*?)^```", path.read_text(), re.M | re.S)):
                code = match.group(1)
                if not re.search(r"^package main\s*$", code, re.M):
                    continue
                source = Path(directory) / f"example-{count}.go"
                source.write_text(code)
                result = subprocess.run(
                    ["go", "build", "-o", str(Path(directory) / "example"), str(source)],
                    cwd=ROOT, capture_output=True, text=True,
                )
                if result.returncode:
                    raise SystemExit(f"{path.relative_to(ROOT)} code block {index + 1}:\n{result.stderr}")
                count += 1
    if count == 0:
        raise SystemExit("No complete Go examples found")
    print(f"Compiled {count} complete documentation examples.")


if __name__ == "__main__":
    main()
