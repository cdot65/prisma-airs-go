// Run with the TypeScript SDK tsx tool: <sdk>/node_modules/.bin/tsx scripts/export_typescript_parity.mts <sdk>
import { writeFileSync, readdirSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { resolve, dirname } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
const sdk=resolve(process.argv[2] ?? '../prisma-airs-sdk');
const go=resolve(dirname(fileURLToPath(import.meta.url)), '..');
const { zodToJsonSchema }=await import(pathToFileURL(sdk+'/node_modules/zod-to-json-schema/dist/esm/index.js').href);
const { collectCallSites }=await import(pathToFileURL(sdk+'/scripts/openapi/inventory.ts').href);
const calls=collectCallSites();

const picked=new Set(['iam/scopes-client.ts','ai-gateway/workspaces-client.ts','ai-gateway/organisations-client.ts','ai-gateway/plugins-client.ts','ai-gateway/audit-logs-client.ts','ai-gateway/log-exports-client.ts','ai-gateway/telemetry-client.ts','ai-gateway/guardrails-client.ts','ai-gateway/integrations-client.ts','ai-gateway/model-pricing-client.ts','ai-gateway/inference-client.ts','ai-gateway/runtime-resources-client.ts','management/dashboard.ts','management/dlp/data-filtering-profiles.ts','management/dlp/data-patterns.ts','management/dlp/data-profiles.ts','management/dlp/dictionaries.ts']);
const selected=calls.filter(c=>picked.has(c.source.replace(/^src\//,'')) && (!['src/ai-gateway/guardrails-client.ts','src/ai-gateway/integrations-client.ts'].includes(c.source)||['getCatalog','catalog'].includes(c.member)));
// The inventory represents the shared auth-settings path helper as an expression.
// Resolve the two calls against the retained helper without changing the source SDK.
for(const call of selected)if(call.className==='AIGatewayOrganisationsClient'&&['getAuthSettings','updateAuthSettings'].includes(call.member))call.path='/organisations/{tsgId}/auth-settings';
const needed=new Set(selected.flatMap(c=>[c.requestSchema,c.responseSchema]).flatMap(s=>s?.match(/[A-Za-z]\w*Schema/g)??[]));
// Workspace defaults and validation models are also public standalone types.
for(const c of selected)for(const p of c.parameters??[])if(/^[A-Za-z]\w*$/.test(p.type))needed.add(p.type+'Schema');
for(const s of ['GatewayInferenceCreateChatCompletionStreamResponseSchema','GatewayInferenceCreatePromptCompletionStreamResponseSchema','GatewayInferenceResponseStreamEventSchema','GatewayRealtimeConnectRequestSchema','GatewayRealtimeClientEventSchema','GatewayRealtimeServerEventSchema','DictionaryRequestSchema','DictionaryPatchRequestSchema','GatewayWorkspaceCreateRequestSchema','GatewayWorkspaceUpdateRequestSchema','GatewayWorkspaceDetailSchema','GatewayWorkspaceCreateResponseSchema','GatewayWorkspaceSchema','ListWorkspacesResponseSchema','IamScopeSchema','IamScopeListResponseSchema','IamScopeResourceSchema','IamScopeCreateRequestSchema','IamScopeUpdateRequestSchema']) needed.add(s);
const models={}; const origins={};
for (const f of readdirSync(sdk+'/src/models').filter(f=>f.endsWith('.ts')&&f!=='index.ts')) {
 const module=await import(sdk+'/src/models/'+f);
 for(const [n,v]of Object.entries(module)) if(needed.has(n)||f.startsWith('mgmt-dashboard')) {models[n]=v;origins[n]='src/models/'+f;}
}
const schemas={};
for (const [n,v]of Object.entries(models)) {
 const document=zodToJsonSchema(v,{name:n, $refStrategy:'root', target:'openApi3'});
 const root='#/definitions/'+n;
 const cache=new Map([[root,n]]);
 function deref(ref) { let node=document;for(const part of ref.slice(2).split('/')) node=node[part.replace(/~1/g,'/').replace(/~0/g,'~')];return node; }
 function walk(node) {
  if(Array.isArray(node))return node.map(walk);
  if(!node||typeof node!=='object')return node;
  if(node.$ref){
   const ref=node.$ref; let key=cache.get(ref);
   if(!key){key=n+'Ref'+cache.size;cache.set(ref,key); schemas[key]=walk(deref(ref));}
   return {...node,$ref:'#/components/schemas/'+key};
  }
  return Object.fromEntries(Object.entries(node).map(([k,v])=>[k,walk(v)]));
 }
 schemas[n]=walk(document.definitions[n]);
}
const paths={};
const metadata={source:'TypeScript SDK captured/typed contracts; not an official OpenAPI publication',repository:'https://github.com/cdot65/prisma-airs-sdk',commit:execFileSync('git',['rev-parse','HEAD'],{cwd:sdk,encoding:'utf8'}).trim(),version:JSON.parse(readFileSync(sdk+'/package.json','utf8')).version,files:Object.fromEntries([...new Set([...selected.map(c=>c.source),...Object.values(origins),"src/constants.ts","src/ai-gateway/secret-fields.ts"])].sort().map(f=>[f,createHash('sha256').update(readFileSync(sdk+'/'+f)).digest('hex')]))};
writeFileSync(go+'/specs/contracts/typescript-parity.json',JSON.stringify({info:metadata,components:{schemas},paths},null,2)+'\n');
writeFileSync(go+'/specs/typescript-parity.json',JSON.stringify({source:metadata,operations:selected},null,2)+'\n');
console.log(JSON.stringify({callSites:calls.length,selected:selected.length,neededSchemas:needed.size,exported:Object.keys(models).length,components:Object.keys(schemas).length,interfaceOrAliasNamesWithoutRuntimeSchema:[...needed].filter(s=>!models[s])}));

const { AI_GATEWAY_SECRET_FIELDS }=await import(pathToFileURL(sdk+'/src/ai-gateway/secret-fields.ts').href);
writeFileSync(go+'/aisec/gateway/secret-fields.json',JSON.stringify(AI_GATEWAY_SECRET_FIELDS,null,2)+'\n');
