"""Resolve the reviewed Gateway CRUD selection against the pinned source.

The manifest records selection/routing/names only. Models and test inputs always
come from the original contract. Config listing's SCM workspace query is the
recorded exception to the supplied generic Portkey-shaped contract.
"""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def operations(document):
    selected=json.loads((ROOT/'specs/gateway_scope.json').read_text())
    result=[]
    for row in selected:
        path=document['paths'][row['path']]
        operation=path[row['verb'].lower()]
        parameters=[]
        for parameter in path.get('parameters',[])+operation.get('parameters',[]):
            if '$ref' in parameter:
                parameter=document['components']['parameters'][parameter['$ref'].rsplit('/',1)[-1]]
            parameters.append(parameter)
        query=[p for p in parameters if p.get('in')=='query']
        if row['key']=='ConfigsList':
            query=[dict(name='workspace_id',**{'in':'query'},required=True,schema={'type':'string'})]
        status,response=next((k,v)for k,v in operation['responses'].items()if k.startswith('2'))
        request=operation.get('requestBody',{}).get('content',{}).get('application/json',{}).get('schema')
        reply=response.get('content',{}).get('application/json',{}).get('schema')
        result.append(dict(row,request=request,reply=reply,query=query,status=int(status)))
    return result
