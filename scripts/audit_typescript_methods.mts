
import {readFileSync,readdirSync,writeFileSync} from 'node:fs';
import{join,resolve,dirname}from'node:path';
import{pathToFileURL,fileURLToPath}from'node:url';
const sdk=resolve(process.argv[2]??'../prisma-airs-sdk'),go=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const {default:ts}=await import(pathToFileURL(sdk+'/node_modules/typescript/lib/typescript.js').href);
function files(root,suffix){return readdirSync(root,{withFileTypes:true}).flatMap(e=>e.isDirectory()?files(join(root,e.name),suffix):e.name.endsWith(suffix)?[join(root,e.name)]:[])}
const goMethods=new Set();for(const f of files(go+'/aisec','.go').filter(f=>!f.endsWith('_test.go')&&!f.includes('/schema/'))){const pkg=f.slice((go+'/aisec/').length).split('/')[0];for(const m of readFileSync(f,'utf8').matchAll(/^func \(\w+ \*?(\w+)(?:\[[^\]]+\])?\) (\w+)\(/gm))goMethods.add(pkg+'.'+m[1]+'.'+m[2]);}
function methodName(n){const initialisms=['id','uuid','api','url','uri','http','json','csv','tsg','sdk','asr','mcp','pypi'];return n.replace(/([a-z0-9])([A-Z])/g,'$1_$2').split('_').map(p=>initialisms.includes(p.toLowerCase())?p.toUpperCase():p[0]?.toUpperCase()+p.slice(1)).join('')}
const aliases={
 'agentguard.AgentGuardClient.ListScans':'agentguard.ScansClient.List', 'agentguard.AgentGuardClient.GetScanStats':'agentguard.StatisticsClient.Scans', 'agentguard.AgentGuardClient.ListScanVulnerabilities':'agentguard.ScansClient.ListVulnerabilities', 'agentguard.AgentGuardClient.ListRules':'agentguard.RulesClient.List',
 'runtime.ProfilesClient.Get':'runtime.ProfilesClient.GetByID','runtime.TopicsClient.ForceDeleteWithAudit':'runtime.TopicsClient.ForceDelete','runtime.OAuthManagementClient.GetAccessToken':'runtime.OAuthManagementClient.GetToken',
 'modelsecurity.ModelsClient.ListModels':'modelsecurity.ModelsClient.List','modelsecurity.ModelsClient.ListAllModels':'modelsecurity.ModelsClient.ListAll','modelsecurity.ModelsClient.GetModel':'modelsecurity.ModelsClient.Get','modelsecurity.ModelsClient.ListModelVersions':'modelsecurity.ModelsClient.ListVersions','modelsecurity.ModelsClient.ListAllModelVersions':'modelsecurity.ModelsClient.ListAllVersions','modelsecurity.ModelsClient.GetModelVersion':'modelsecurity.ModelVersionsClient.Get','modelsecurity.ModelsClient.ListModelVersionFiles':'modelsecurity.ModelVersionsClient.ListFiles','modelsecurity.ModelsClient.ListAllModelVersionFiles':'modelsecurity.ModelVersionsClient.ListAllFiles',
 'redteam.Client.GetQuotaSummary':'redteam.Client.GetQuota','redteam.Client.GetManagementLanguages':'redteam.TargetsClient.GetLanguages','redteam.InstancesClient.CreateInstance':'redteam.InstancesClient.Create','redteam.InstancesClient.GetInstance':'redteam.InstancesClient.Get','redteam.InstancesClient.UpdateInstance':'redteam.InstancesClient.Update','redteam.InstancesClient.DeleteInstance':'redteam.InstancesClient.Delete','redteam.InstancesClient.CreateDevices':'redteam.InstancesClient.CreateDevice','redteam.InstancesClient.UpdateDevices':'redteam.InstancesClient.UpdateDevice','redteam.InstancesClient.DeleteDevices':'redteam.InstancesClient.DeleteDevice','redteam.InstancesClient.GetRegistryCredentials':'redteam.Client.GetRegistryCredentials',
 'redteam.NetworkBrokerClient.ListChannels':'redteam.NetworkBrokerClient.List','redteam.NetworkBrokerClient.CreateChannel':'redteam.NetworkBrokerClient.Create','redteam.NetworkBrokerClient.GetChannel':'redteam.NetworkBrokerClient.Get','redteam.NetworkBrokerClient.UpdateChannel':'redteam.NetworkBrokerClient.Update','redteam.NetworkBrokerClient.GetChannelStats':'redteam.NetworkBrokerClient.GetStats',
 'redteam.TargetsClient.GetTargetMetadata':'redteam.Client.GetTargetMetadata','redteam.TargetsClient.GetTargetTemplates':'redteam.Client.GetTargetTemplates',
 'runtime.ScanLogsClient.Query':'runtime.ScanLogsClient.List', 'runtime.Content.FromJSON':'runtime.ContentFromJSON', 'runtime.Content.FromJSONFile':'runtime.ContentFromJSONFile', 'redteam.CustomAttacksClient.UploadPromptsCSV':'redteam.CustomAttacksClient.UploadPromptsCsv', 'runtime.OAuthManagementClient.InvalidateToken':'runtime.OAuthManagementClient.InvalidateTokenForApp', 'runtime.Scanner.QueryByScanIds':'runtime.Scanner.QueryByScanIDs','runtime.Scanner.QueryByReportIds':'runtime.Scanner.QueryByReportIDs',
};
for(const f of files(go+'/aisec','.go').filter(f=>!f.endsWith('_test.go')&&!f.includes('/schema/'))){const pkg=f.slice((go+'/aisec/').length).split('/')[0];for(const m of readFileSync(f,'utf8').matchAll(/^func (\w+)\(/gm))goMethods.add(pkg+'.'+m[1]);}
const rows=[];
for(const f of files(sdk+'/src','.ts')){
 const src=f.slice((sdk+'/').length);if(!/^src\/(scan|management|model-security|red-team|ai-gateway|iam|agentguard)\//.test(src)||/scope-name|nested-values|types|window|secret-fields|runtime-wire/.test(src))continue;
 let pkg=src.includes('management/')||src.includes('/scan/')?'runtime':src.includes('model-security/')?'modelsecurity':src.includes('red-team/')?'redteam':src.includes('agentguard/')?'agentguard':'gateway';
 const tree=ts.createSourceFile(f,readFileSync(f,'utf8'),ts.ScriptTarget.Latest,true);
 for(const cls of tree.statements.filter(ts.isClassDeclaration)){
  let receiver=cls.name?.text.replace(/^AIGateway/,'').replace(/^ModelSecurity(?=.+Client)/,'').replace(/^RedTeam(?=.+Client)/,'').replace(/^Iam/,'IAM');if(['ManagementClient','ModelSecurityClient','RedTeamClient'].includes(receiver))receiver='Client';if(pkg=='modelsecurity'&&receiver=='GroupsClient')receiver='SecurityGroupsClient';if(pkg=='modelsecurity'&&receiver=='RulesClient')receiver='SecurityRulesClient';if(receiver=='InferenceClient'||receiver=='RuntimeResourcesClient')receiver='InferenceClient';if(receiver=='AdminGuardrailsClient')receiver='OrgGuardrailsClient';receiver=receiver.replace(/^Mcp/,'MCP');if(pkg=='gateway')receiver=receiver.replace(/^Api/,'API');
  for(const method of cls.members.filter(ts.isMethodDeclaration)){
   if(!method.body)continue;
   if(method.modifiers?.some(m=>[ts.SyntaxKind.PrivateKeyword,ts.SyntaxKind.ProtectedKeyword].includes(m.kind)))continue;
   const member=method.name.getText(tree),target=pkg+'.'+receiver+'.'+methodName(member);let actual=aliases[target]??target;
   if(pkg=='gateway'){
    actual=actual.replace(/\.GetMCPServers$/,'.ListMCPServers').replace(/\.SyncMCPServers$/,'.SetMCPServers').replace(/\.GetModels$/,'.ListModels').replace(/\.GetWorkspaces$/,'.ListWorkspaces').replace(/\.GetCapabilities$/,'.ListCapabilities').replace(/\.UpdateCapabilities$/,'.SetCapabilities').replace(/\.GetUserAccess$/,'.ListUserAccess').replace(/\.UpdateUserAccess$/,'.SetUserAccess').replace(/\.GetConnections$/,'.ListConnections');
    if(receiver=='APIKeysClient'){if(/^List(Service|User)$/.test(methodName(member)))actual='gateway.APIKeysClient.ListForKind';else if(/^(Get|Update|Delete|Rotate)(Service|User)$/.test(methodName(member)))actual='gateway.APIKeysClient.'+methodName(member).replace(/(Service|User)$/,'ForKind');else if(/^Create(Service|User)$/.test(methodName(member)))actual='gateway.APIKeysClient.Create';}
   }
   rows.push({source:src,className:cls.name?.text,member,go:actual,implemented:goMethods.has(actual)});
  }
 }
}
writeFileSync(go+'/specs/typescript-method-parity.json',JSON.stringify(rows,null,2)+'\n');
console.log(JSON.stringify({total:rows.length,matched:rows.filter(r=>r.implemented).length,missing:rows.filter(r=>!r.implemented).map(r=>r.source+' '+r.className+'.'+r.member+' -> '+r.go)},null,2));

if(rows.some(r=>!r.implemented))process.exitCode=1;
