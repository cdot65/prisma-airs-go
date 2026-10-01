#!/usr/bin/env python3
"""Generate current-schema models from pinned JSON contracts (Python stdlib only).

Legacy package models stay source-compatible. Current models live in a schema
subpackage and distinguish optional nullable fields through aisec.Optional.
Only fields explicitly declared free-form remain maps; unions retain raw JSON
and expose typed constructors/accessors rather than dropping alternatives.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
DOMAINS = {"modelsecurity": ["model-data", "model-mgmt"],
           "redteam": ["redteam-data", "redteam-mgmt", "redteam-broker"]}
INITIALISMS = {x: x.upper() for x in ["id", "uuid", "api", "url", "uri", "http", "https", "json", "csv", "tsg", "sdk", "asr", "mcp", "sha256", "pypi", "aws", "gcp", "ms", "llm", "dp", "ip", "kb"]}


def name(value):
    value = re.sub(r"Schema$", "", value)
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    parts = re.findall(r"[A-Za-z0-9]+", value)
    result = "".join(INITIALISMS.get(x.lower(), x.capitalize() if x.isupper() else x[0].upper() + x[1:]) for x in parts)
    if not result or result[0].isdigit():
        result = "Value" + result
    return result


class Generator:
    def __init__(self, labels):
        self.schemas = {}
        self.names = {}
        for label in labels:
            document = json.loads((ROOT / "specs/contracts" / (label + ".json")).read_text())
            for key, schema in document["components"]["schemas"].items():
                if key in self.schemas and self.schemas[key] != schema:
                    raise ValueError("Conflicting component: " + key)
                self.schemas[key] = schema
                self.names[key] = name(key)
        # Preserve the source Schema suffix when dropping it would collapse two
        # distinct components (for example PropertyAssignment[Schema]).
        duplicates = {v for v in self.names.values() if list(self.names.values()).count(v) > 1}
        for key, value in list(self.names.items()):
            if value in duplicates and key.endswith("Schema"):
                self.names[key] = value + "Schema"
        if len(set(self.names.values())) != len(self.names):
            raise ValueError("Go component name collision")
        self.pending = {self.names[k]: v for k, v in self.schemas.items()}
        self.definitions = {}
        self.imports = set()

    def register(self, hint, schema):
        if hint in self.pending and self.pending[hint] != schema:
            raise ValueError("Inline component name collision: " + hint)
        self.pending[hint] = schema
        return hint

    def nullable(self, schema):
        nullable = schema.get("nullable", False)
        if schema.get("type") == "null":
            return {}, True
        if isinstance(schema.get("type"), list):
            types = [x for x in schema["type"] if x != "null"]
            if len(types) == 1:
                return {**schema, "type": types[0]}, "null" in schema["type"]
        for key in ["anyOf", "oneOf"]:
            if key in schema:
                nonnull = [x for x in schema[key] if x.get("type") != "null"]
                nullable = nullable or len(nonnull) != len(schema[key])
                if len(nonnull) == 1:
                    return {**{k:v for k,v in schema.items() if k not in [key,"nullable"]}, **nonnull[0]}, nullable
                # An enum-or-string schema is an open string enum in Go: a
                # named string already accepts future values without a union.
                resolved = [self.schemas[x["$ref"].rsplit("/",1)[-1]] if "$ref" in x else x for x in nonnull]
                if resolved and all(x.get("type")=="string" for x in resolved):
                    preferred=next((x for x in nonnull if "$ref" in x),{"type":"string"})
                    return preferred,nullable
                return {**schema, key: nonnull}, nullable
        return schema, nullable

    def flatten(self, schema):
        if "allOf" not in schema:
            return schema
        properties = dict(schema.get("properties", {}))
        required = set(schema.get("required", []))
        for item in schema["allOf"]:
            if "$ref" in item:
                item = self.schemas[item["$ref"].rsplit("/",1)[-1]]
            item = self.flatten(item)
            for key, value in item.get("properties", {}).items():
                if key in properties and properties[key] != value:
                    raise ValueError("Conflicting allOf property: " + key)
                properties[key] = value
            required.update(item.get("required", []))
        return {**schema,"type":"object","properties":properties,"required":sorted(required)}

    def type(self, schema, hint):
        schema, nullable = self.nullable(schema)
        if "$ref" in schema:
            return self.names[schema["$ref"].rsplit("/", 1)[-1]], nullable
        schema = self.flatten(schema)
        if "oneOf" in schema or "anyOf" in schema or schema.get("properties"):
            return self.register(hint, schema), nullable
        kind = schema.get("type")
        if kind == "array":
            if "items" not in schema:
                raise ValueError("Array without items: " + hint)
            item, item_nullable = self.type(schema["items"], hint + "Item")
            return "[]" + ("*" if item_nullable else "") + item, nullable
        if kind == "object" or "additionalProperties" in schema:
            extra = schema.get("additionalProperties", True)
            if isinstance(extra, dict):
                value, value_nullable = self.type(extra, hint + "Value")
                return "map[string]" + ("*" if value_nullable else "") + value, nullable
            return "map[string]any", nullable
        return {"string":"string", "integer":"int64", "number":"float64", "boolean":"bool"}.get(kind,"any"), nullable

    def comment(self, text):
        return "\n".join("// " + line for line in str(text).replace("\r", "").splitlines())

    def definition(self, typename, original):
        schema, nullable = self.nullable(original)
        schema = self.flatten(schema)
        description = self.comment(typename + " represents " + (original.get("description") or original.get("title") or typename) + ".")
        variants = schema.get("oneOf", schema.get("anyOf"))
        if variants:
            self.imports.update(["bytes", "encoding/json", "fmt"])
            lines = [description, "type " + typename + " json.RawMessage",
                     f"func (x {typename}) MarshalJSON() ([]byte,error) {{ return json.RawMessage(x).MarshalJSON() }}",
                     f"func (x *{typename}) UnmarshalJSON(data []byte) error {{ if !json.Valid(data) {{ return fmt.Errorf(\"invalid {typename} JSON\") }}; *x=append((*x)[:0],data...); return nil }}"]
            used = set()
            checks=[]
            for i, variant in enumerate(variants):
                typ, _ = self.type(variant, typename + "Alternative" + str(i+1))
                suffix = name(typ.replace("[]", "Slice").replace("*", "Nullable").replace("map[string]", "Map"))
                if suffix in used:
                    continue
                used.add(suffix)
                guard = ""
                if "$ref" in variant:
                    target = self.schemas[variant["$ref"].rsplit("/",1)[-1]]
                    target = self.flatten(target)
                    required = target.get("required", [])
                    if required:
                        guard += 'var fields map[string]json.RawMessage; if err:=json.Unmarshal(x,&fields);err!=nil {return nil,err}; '
                        for field in required:
                            guard += f'if _,ok:=fields[{json.dumps(field)}];!ok {{return nil,fmt.Errorf("missing {typename} alternative field: {field}")}}; '
                    for field, prop in target.get("properties", {}).items():
                        constant = prop.get("const", prop.get("enum", [None])[0] if len(prop.get("enum", [])) == 1 else None)
                        if isinstance(constant,str):
                            guard += f'if value.{name(field)} != {json.dumps(constant)} {{ return nil, fmt.Errorf("expected {typename} {field}=%s", {json.dumps(constant)}) }}; '
                lines.extend([
                    f"// As{suffix} decodes this union as {typ}; tagged variants verify their tag.",
                    f"func (x {typename}) As{suffix}() (*{typ},error) {{ if bytes.Equal(bytes.TrimSpace(x),[]byte(\"null\")) {{return nil,fmt.Errorf(\"null {typename} alternative\")}}; var value {typ}; if err:=json.Unmarshal(x,&value);err!=nil {{ return nil,err }}; {guard}return &value,nil }}",
                    f"// New{typename}From{suffix} encodes the typed union alternative.",
                    f"func New{typename}From{suffix}(value {typ}) ({typename},error) {{ b,err:=json.Marshal(value);return {typename}(b),err }}"])
                checks.append(f"if _,err:=candidate.As{suffix}();err==nil {{valid=true}}")
            lines[3]=f"func (x *{typename}) UnmarshalJSON(data []byte) error {{ if !json.Valid(data) {{return fmt.Errorf(\"invalid {typename} JSON\")}}; candidate:={typename}(data);valid:=false;"+";".join(checks)+f";if !valid {{return fmt.Errorf(\"no matching {typename} alternative\")}};*x=append((*x)[:0],data...);return nil }}"
            return "\n".join(lines)
        if schema.get("properties"):
            fields=[]; optional=False; used=set()
            required=set(schema.get("required",[]))
            for key, value in schema["properties"].items():
                field=name(key)
                if field in used: raise ValueError("Field collision: " + typename+"."+field)
                used.add(field)
                typ, null = self.type(value, typename+field)
                tag=key
                if key not in required:
                    tag+=",omitempty"
                    if null:
                        self.imports.add("github.com/cdot65/prisma-airs-go/aisec")
                        typ="aisec.Optional["+typ+"]"; optional=True
                    else: typ="*"+typ
                elif null: typ="*"+typ
                if value.get("description"): fields.append(self.comment(value["description"]))
                fields.append(field+" "+typ+" `json:"+json.dumps(tag)+"`")
            lines=[description,"type "+typename+" struct {","\n".join(fields),"}"]
            if optional:
                self.imports.add("github.com/cdot65/prisma-airs-go/aisec/internal")
                lines.append(f"func (x {typename}) MarshalJSON() ([]byte,error) {{ type alias {typename};return internal.MarshalOptionalFields(alias(x)) }}")
            return "\n".join(lines)
        typ,_ = self.type(schema,typename+"Value")
        if nullable: typ="*"+typ
        lines=[description,"type "+typename+" "+typ]
        if schema.get("enum") and typ=="string":
            constants=[]; used=set()
            for enum in schema["enum"]:
                if not isinstance(enum,str):continue
                constant=typename+name(enum)
                if constant in used:raise ValueError("Enum collision: "+constant)
                used.add(constant)
                constants.append(constant+" "+typename+" = "+json.dumps(enum))
            if constants:lines.extend(["const (","\n".join(constants),")"])
        return "\n".join(lines)

    def generate(self):
        while any(k not in self.definitions for k in self.pending):
            for key in sorted(list(self.pending)):
                if key not in self.definitions:
                    self.definitions[key]=self.definition(key,self.pending[key])
        builtin=[x for x in sorted(self.imports) if "/" not in x]
        external=[x for x in sorted(self.imports) if "/" in x]
        imports="\n\n".join("\n".join(json.dumps(x) for x in group) for group in [builtin,external] if group)
        return ("// Code generated by scripts/schema_models.py from specs/contracts; DO NOT EDIT.\n"
                "\npackage schema\n\n" + ("import (\n"+imports+"\n)\n\n" if imports else "") +
                "\n\n".join(self.definitions[k] for k in sorted(self.definitions))+"\n")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("domains",nargs="*",choices=list(DOMAINS))
    parser.add_argument("--check",action="store_true")
    args=parser.parse_args()
    for domain in args.domains or DOMAINS:
        output=Generator(DOMAINS[domain]).generate()
        output=subprocess.check_output(["gofmt"],input=output,text=True)
        path=ROOT/"aisec"/domain/"schema/models_gen.go"
        if args.check:
            if not path.exists() or path.read_text()!=output:raise SystemExit("Stale schema models: "+domain)
        else:
            path.parent.mkdir(parents=True,exist_ok=True);path.write_text(output)
        print(domain+": "+str(output.count("\ntype "))+" current-schema types")


if __name__=="__main__":main()
