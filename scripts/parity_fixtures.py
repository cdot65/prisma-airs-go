#!/usr/bin/env python3
"""Generate synthetic contract/routing test bodies from pinned TypeScript shapes; not live captures."""
import json,re
from pathlib import Path
root=Path(__file__).resolve().parents[1]
s=json.loads((root/'specs/contracts/typescript-parity.json').read_text())['components']['schemas']
def sample(shape,depth=0):
 if depth>25:return {}
 if '$ref' in shape:return sample(s[shape['$ref'].split('/')[-1]],depth+1)
 if 'const' in shape:return shape['const']
 if 'enum' in shape:return shape['enum'][0]
 for key in ['anyOf','oneOf']:
  if key in shape:return sample(next(x for x in shape[key] if x.get('type')!='null'),depth+1)
 if 'allOf' in shape:
  out={}
  for x in shape['allOf']:
   v=sample(x,depth+1)
   if isinstance(v,dict):out.update(v)
  return out
 typ=shape.get('type')
 if typ=='object':return {k:sample(shape['properties'][k],depth+1) for k in shape.get('required',[]) if k in shape.get('properties',{})}
 if typ=='array':return [sample(shape.get('items',{}),depth+1) for _ in range(int(shape.get('minItems',0)))]
 if typ in ['integer','number']:return max(1,shape.get('minimum',1))
 if typ=='boolean':return False
 if typ=='null':return None
 if typ=='string':
  if shape.get('format')=='uuid':return '550e8400-e29b-41d4-a716-446655440000'
  if shape.get('format')=='date-time':return '2026-10-01T00:00:00Z'
  if shape.get('format')=='email':return 'test@example.com'
  if shape.get('pattern'):return '123' if shape['pattern']=='^\\d+$' else 'ws_test'
  return 'test'
 return {}
ops=json.loads((root/'specs/typescript-parity.json').read_text())['operations'];mapping=json.loads((root/'specs/typescript-method-parity.json').read_text());bykey={(r['source'],r['className'],r['member']):r for r in mapping}
rows=[]
for op in ops:
 if op['source'].endswith(('inference-client.ts','runtime-resources-client.ts','model-pricing-client.ts','dictionaries.ts')):continue
 if op['member']=='provision':continue
 row=dict(op);row['go']=bykey[op['source'],op['className'],op['member']]['go']
 for field in ['requestSchema','responseSchema']:
  n=op.get(field,'');shape=s.get(n,{});row['body' if field=='requestSchema' else 'response']=sample(shape)
 if op['member']=='update' and op['className']=='AIGatewayWorkspacesClient':row['body']={'name':'updated'}
 rows.append(row)
(root/'aisec/parity/testdata').mkdir(parents=True,exist_ok=True)
output=json.dumps(rows,indent=2)+'\n'
path=root/'aisec/parity/testdata/operations.json'
import sys
if '--check' in sys.argv:
 if path.read_text()!=output:raise SystemExit('Stale synthetic parity fixtures')
else:path.write_text(output)
print(len(rows))

# Terminal Responses fixtures exercise all three typed stream terminators.
terminals={}
for shape in s['GatewayInferenceResponseStreamEventSchema']['anyOf']:
 name=shape.get('properties',{}).get('type',{}).get('enum',[None])[0]
 if name in ['response.completed','response.failed','response.incomplete']:terminals[name]=sample(shape)
terminal_output=json.dumps(terminals,indent=2)+'\n'
terminal_path=root/'aisec/gateway/testdata/response-terminal-events.json'
if '--check' in sys.argv:
 if terminal_path.read_text()!=terminal_output:raise SystemExit('Stale synthetic terminal fixtures')
else:terminal_path.write_text(terminal_output)

dashboard_output=json.dumps(sample(s['DashboardApplicationSchema']),indent=2)+'\n'
dashboard_path=root/'aisec/runtime/testdata/parity-dashboard.json'
if '--check' in sys.argv:
 if dashboard_path.read_text()!=dashboard_output:raise SystemExit('Stale synthetic dashboard fixture')
else:
 dashboard_path.parent.mkdir(exist_ok=True)
 dashboard_path.write_text(dashboard_output)
