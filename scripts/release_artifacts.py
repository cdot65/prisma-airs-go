#!/usr/bin/env python3
"""Build versioned example binaries and a source archive from a clean commit."""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zlib
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = [(system, arch) for system in ("linux", "darwin", "windows")
             for arch in ("amd64", "arm64")]
EXAMPLES = ("basic-scan", "profile-crud", "gateway-read")
BUILD_ENV = dict(GOENV="off", GOFLAGS="", GOEXPERIMENT="", GOAMD64="v1",
                 GOARM64="v8.0", GOWORK="off", CGO_ENABLED="0")


def command(*args, **kwargs):
    return subprocess.check_output(args, cwd=ROOT, **kwargs)


def tar_gz(path, entries):
    with path.open("wb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for name, content, mode in entries:
                    info = tarfile.TarInfo(name)
                    info.size, info.mode, info.mtime = len(content), mode, 0
                    archive.addfile(info, io.BytesIO(content))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="release tag, e.g. v0.6.0")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    version = re.search(r'\bVersion\s*=\s*"([^"]+)"', (ROOT / "aisec/constants.go").read_text()).group(1)
    if args.version != "v" + version:
        parser.error("release tag does not match aisec.Version")
    if command("git", "status", "--porcelain", "--untracked-files=normal").strip():
        parser.error("build from a clean committed checkout")
    output = args.output.resolve()
    if output == ROOT or ROOT in output.parents:
        parser.error("output must be outside the checkout")
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error("output directory must be empty")
    commit = command("git", "rev-parse", "HEAD", text=True).strip()
    build_env = dict(os.environ, **BUILD_ENV)
    toolchain = command("go", "version", text=True, env=build_env).strip()
    prefix = "prisma-airs-go-" + args.version
    source = command("git", "archive", "--format=tar", "--prefix=" + prefix + "/", "HEAD")
    with (output / (prefix + "-source.tar.gz")).open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            compressed.write(source)
    instructions = (ROOT / "docs/developer/releases.md").read_bytes()
    with tempfile.TemporaryDirectory(prefix="airs-release-build-") as temporary:
        for system, arch in PLATFORMS:
            entries = [("README.md", instructions, 0o644)]
            for example in EXAMPLES:
                filename = example + (".exe" if system == "windows" else "")
                binary = Path(temporary) / filename
                env = dict(build_env, GOOS=system, GOARCH=arch)
                subprocess.run(["go", "build", "-trimpath", "-buildvcs=true", "-ldflags=-s -w",
                                "-o", str(binary), "./examples/" + example], cwd=ROOT, env=env, check=True)
                entries.append((filename, binary.read_bytes(), 0o755))
            archive_path = output / (prefix + "_" + system + "_" + arch)
            if system == "windows":
                with zipfile.ZipFile(str(archive_path) + ".zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
                    for name, content, mode in entries:
                        info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                        info.create_system = 3
                        info.external_attr = mode << 16
                        info.compress_type = zipfile.ZIP_DEFLATED
                        archive.writestr(info, content)
            else:
                tar_gz(Path(str(archive_path) + ".tar.gz"), entries)
            print(system + "/" + arch + ": built " + ", ".join(EXAMPLES), flush=True)
    provenance = dict(version=args.version, commit=commit, toolchain=toolchain,
                      python=sys.version.split()[0], zlib=zlib.ZLIB_RUNTIME_VERSION,
                      build_environment=BUILD_ENV, platforms=[a + "/" + b for a, b in PLATFORMS],
                      examples=list(EXAMPLES), build_flags=["-trimpath", "-buildvcs=true", "-ldflags=-s -w"])
    (output / "build-info.json").write_text(json.dumps(provenance, indent=2) + "\n")
    (output / "README.md").write_bytes(instructions)
    files = sorted(path for path in output.iterdir() if path.is_file())
    checksums = "".join(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name + "\n" for path in files)
    (output / "SHA256SUMS").write_text(checksums)
    print("Release assets: " + str(output))


if __name__ == "__main__":
    main()
