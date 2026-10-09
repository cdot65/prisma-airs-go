package runtime

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"
)

// Profile models require all four scoped JSON/presence methods. Detect a future
// embedded model that forgets wrappers before it can silently lose wire fields.
func TestProfileJSONMethodCoverage(t *testing.T) {
	packages, err := parser.ParseDir(token.NewFileSet(), ".", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	models := map[string]bool{}
	methods := map[string]map[string]bool{}
	for name, pkg := range packages {
		if name != "runtime" {
			continue
		}
		for path, file := range pkg.Files {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			for _, decl := range file.Decls {
				switch node := decl.(type) {
				case *ast.GenDecl:
					for _, spec := range node.Specs {
						typ, ok := spec.(*ast.TypeSpec)
						if !ok {
							continue
						}
						st, ok := typ.Type.(*ast.StructType)
						if !ok {
							continue
						}
						for _, field := range st.Fields.List {
							if len(field.Names) != 0 {
								continue
							}
							if id, ok := field.Type.(*ast.Ident); ok && id.Name == "ProfileJSON" {
								models[typ.Name.Name] = true
							}
						}
					}
				case *ast.FuncDecl:
					if node.Recv == nil {
						continue
					}
					receiver := node.Recv.List[0].Type
					if ptr, ok := receiver.(*ast.StarExpr); ok {
						receiver = ptr.X
					}
					id, ok := receiver.(*ast.Ident)
					if !ok {
						continue
					}
					if methods[id.Name] == nil {
						methods[id.Name] = map[string]bool{}
					}
					methods[id.Name][node.Name.Name] = true
				}
			}
		}
	}
	if len(models) == 0 {
		t.Fatal("no scoped profile models found")
	}
	for name := range models {
		for _, method := range []string{"MarshalJSON", "UnmarshalJSON", "FieldPresence", "HasField"} {
			if !methods[name][method] {
				t.Errorf("%s embeds ProfileJSON but lacks %s", name, method)
			}
		}
	}
}

// Every typed object reachable through profile wire fields must retain the scoped
// codec. This also detects a future nested struct that forgets ProfileJSON itself.
func TestProfileJSONReachableModelCoverage(t *testing.T) {
	type profileEncoder interface {
		json.Marshaler
		FieldPresence(string) JSONPresence
		HasField(string) bool
	}
	encoder := reflect.TypeOf((*profileEncoder)(nil)).Elem()
	decoder := reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	state := reflect.TypeOf(ProfileJSON{})
	seen := map[reflect.Type]bool{}
	var visit func(reflect.Type)
	visit = func(typ reflect.Type) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array || typ.Kind() == reflect.Map {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || typ == state || seen[typ] {
			return
		}
		seen[typ] = true
		if field, ok := typ.FieldByName("ProfileJSON"); !ok || field.Type != state {
			t.Errorf("reachable wire model %s lacks ProfileJSON", typ)
		}
		if !typ.Implements(encoder) || !reflect.PointerTo(typ).Implements(decoder) {
			t.Errorf("reachable wire model %s lacks complete JSON/presence methods", typ)
		}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if field.PkgPath != "" || field.Tag.Get("json") == "-" {
				continue
			}
			visit(field.Type)
		}
	}
	for _, root := range []any{SecurityProfile{}, CreateProfileRequest{}, UpdateProfileRequest{}, SecurityProfileListResponse{}} {
		visit(reflect.TypeOf(root))
	}
	if len(seen) == 0 {
		t.Fatal("no reachable profile objects checked")
	}
}
