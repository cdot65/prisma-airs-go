#!/usr/bin/env python3
"""Pin supplied OpenAPI artifacts and produce stdlib-readable JSON contracts.

Development tool only: run with Python 3 and PyYAML. No Go runtime dependencies.
Input checkouts are read-only. Run --check in CI against vendored inputs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

import yaml

ROOT = Path(__file__).resolve().parents[1]
INPUTS = [
    ("runtime-service.yaml", "runtime-data", "pan", "prisma-airs/scan/scan-service_latest.yaml"),
    ("runtime-mgmt.yaml", "runtime-mgmt", "pan", "prisma-airs/management/mgmt-service_latest.yaml"),
    ("model-service.yaml", "model-data", "pan", "prisma-airs-model-security/dataplane/data-plane.yml"),
    ("model-mgmt.yaml", "model-mgmt", "pan", "prisma-airs-model-security/management/mgmt-plane.yml"),
    ("redteam-service.yaml", "redteam-data", "pan", "prisma-airs-redteam/data-plane/dp-openapi.yaml"),
    ("redteam-mgmt.yaml", "redteam-mgmt", "pan", "prisma-airs-redteam/management/mp-openapi.yaml"),
    ("redteam-network-broker.yaml", "redteam-broker", "pan", "prisma-airs-redteam/network-broker/AIRS-Red-Teaming-Network-Broker.yaml"),
    ("gateway.yaml", "gateway", "gateway", "openapi.yaml"),
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(document):
    # OpenAPI status keys may be YAML integers; JSON normalizes them to strings.
    return (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pan", type=Path, help="pan.dev checkout")
    parser.add_argument("--gateway", type=Path, help="PaloAltoNetworks/openapi checkout")
    parser.add_argument("--agentguard", type=Path, help="supplied AgentGuard preview schema directory")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    manifest_path = ROOT / "specs/manifest.json"
    if args.check:
        manifest = json.loads(manifest_path.read_text())
        for entry in manifest["inputs"]:
            raw = (ROOT / "specs" / entry["file"]).read_bytes()
            if digest(raw) != entry["sha256"]:
                raise SystemExit("Input hash mismatch: " + entry["file"])
            normalized = canonical(yaml.safe_load(raw))
            if normalized != (ROOT / "specs/contracts" / entry["contract"]).read_bytes():
                raise SystemExit("Stale normalized contract: " + entry["contract"])
        print("All pinned inputs and normalized contracts match")
        return
    if not args.agentguard and (args.pan is None or args.gateway is None):
        parser.error("--pan and --gateway are required when refreshing")
    if (args.pan is None) != (args.gateway is None):
        parser.error("--pan and --gateway must be supplied together")
    checkouts = {key: path for key, path in {"pan": args.pan, "gateway": args.gateway}.items() if path is not None}
    commits = {key: subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()
               for key, path in checkouts.items()}
    repositories = {"pan": "https://github.com/PaloAltoNetworks/pan.dev",
                    "gateway": "https://github.com/PaloAltoNetworks/openapi"}
    (ROOT / "specs/contracts").mkdir(parents=True, exist_ok=True)
    existing = json.loads(manifest_path.read_text())
    entries = [entry for entry in existing["inputs"] if
               not (entry["file"] in {item[0] for item in INPUTS} and checkouts) and
               not (entry["file"].startswith("agentguard-") and args.agentguard)]
    for filename, label, checkout, relative in (INPUTS if checkouts else []):
        source = checkouts[checkout] / ("openapi-specs" if checkout == "pan" else "") / relative
        raw = source.read_bytes()
        doc = yaml.safe_load(raw)
        (ROOT / "specs" / filename).write_bytes(raw)
        (ROOT / "specs/contracts" / (label + ".json")).write_bytes(canonical(doc))
        operations = sum(method in {"get", "put", "post", "delete", "patch", "head", "options"}
                         for item in doc["paths"].values() for method in item)
        entries.append(dict(file=filename, contract=label + ".json", repository=repositories[checkout],
                            source=("openapi-specs/" if checkout == "pan" else "") + relative,
                            commit=commits[checkout], sha256=digest(raw), version=doc["info"]["version"],
                            operations=operations))
    if args.agentguard:
        for source_name, label in [("agentguard-data-plane.json", "agentguard-data"),
                                   ("agentguard-mgmt-plane.json", "agentguard-mgmt")]:
            source = args.agentguard / source_name
            raw = source.read_bytes()
            doc = json.loads(raw)
            (ROOT / "specs" / source_name).write_bytes(raw)
            (ROOT / "specs/contracts" / (label + ".json")).write_bytes(canonical(doc))
            operations = sum(method in {"get", "put", "post", "delete", "patch", "head", "options"}
                             for item in doc["paths"].values() for method in item)
            entries.append(dict(file=source_name, contract=label + ".json", source=str(source),
                                provenance="User-supplied public preview 08212026", captured="2026-10-03",
                                sha256=digest(raw), version=doc["info"]["version"], operations=operations))
    manifest_path.write_bytes(canonical({**existing, "inputs": entries}))
    # Retain the historical filename consumed by Red Team conformance checks.
    redteam = next(x for x in entries if x["file"] == "redteam-mgmt.yaml")
    (ROOT / "specs/redteam-mgmt.json").write_bytes((ROOT / "specs/contracts" / redteam["contract"]).read_bytes())
    print("Pinned", len(entries), "inputs with source provenance and SHA-256 hashes")


if __name__ == "__main__":
    main()
