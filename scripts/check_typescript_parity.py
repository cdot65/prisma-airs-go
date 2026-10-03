#!/usr/bin/env python3
"""Verify the pinned public-method map and recovered-contract mappings without a TS checkout."""
from pathlib import Path
import json,re,hashlib
ROOT=Path(__file__).resolve().parents[1]
methods=set()
for path in (ROOT/'aisec').rglob('*.go'):
 if path.name.endswith('_test.go') or 'schema' in path.parts:continue
 pkg=path.relative_to(ROOT/'aisec').parts[0]
 text=path.read_text()
 for receiver,method in re.findall(r'^func \(\w+ \*?(\w+)(?:\[[^\]]+\])?\) (\w+)\(',text,re.M):methods.add(f'{pkg}.{receiver}.{method}')
 for name in re.findall(r'^func (\w+)\(',text,re.M):methods.add(f'{pkg}.{name}')
rows=json.loads((ROOT/'specs/typescript-method-parity.json').read_text())
missing=[r['go'] for r in rows if r['go'] not in methods]
if missing:raise SystemExit('Missing mapped methods: '+', '.join(missing))
contracts=json.loads((ROOT/'specs/typescript-parity.json').read_text())
keys={(r['source'],r['className'],r['member']) for r in rows}
for op in contracts['operations']:
 if (op['source'],op['className'],op['member']) not in keys:raise SystemExit('Unmapped captured operation: '+str(op))
embedded=ROOT/'aisec/parity/schema/contracts.json'
if embedded.read_bytes()!=(ROOT/'specs/contracts/typescript-parity.json').read_bytes():raise SystemExit('Embedded contracts drifted')
for name,digest in json.loads((ROOT/'specs/typescript-fixtures.json').read_text()).items():
 if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=digest:raise SystemExit('Retained fixture changed: '+name)
print(f'{len(rows)} mapped methods and {len(contracts["operations"])} recovered calls verified offline; this is not a live-service verification.')
