package parity_test

import (
	"context"
	"encoding/json"
	"github.com/cdot65/prisma-airs-go/aisec/gateway"
	"github.com/cdot65/prisma-airs-go/aisec/runtime"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// These synthetic bodies exercise the pinned TypeScript contracts and Go routing. They are not live captures.
func TestRecoveredManagementOperations(t *testing.T) {
	raw, err := os.ReadFile("testdata/operations.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Method, Path, Source, Member, Go string
		Parameters                       []struct{ Name, Type string }
		Body, Response                   json.RawMessage
	}
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		t.Run(row.Go, func(t *testing.T) {
			admin := strings.Contains(row.Go, ".OrganisationsClient.") || strings.Contains(row.Go, ".PluginsClient.") || strings.Contains(row.Go, ".AuditLogsClient.") || strings.Contains(row.Go, ".GuardrailsClient.GetCatalog") || strings.Contains(row.Go, ".IntegrationsClient.Catalog") || (strings.Contains(row.Go, ".WorkspacesClient.") && row.Method != "GET")
			base := "/data"
			if admin {
				base = "/admin"
			}
			if strings.Contains(row.Go, ".IAMScopesClient.") {
				base = "/iam"
			}
			if strings.HasPrefix(row.Go, "runtime.") {
				base = "/runtime"
				if strings.Contains(row.Source, "/dlp/") {
					base = "/dlp"
				}
			}
			reached := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/token" {
					_, _ = io.WriteString(w, `{"access_token":"token","expires_in":3600}`)
					return
				}
				reached = true
				expected := regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(row.Path, "550e8400-e29b-41d4-a716-446655440000")
				if strings.Contains(row.Go, ".OrganisationsClient.") {
					expected = regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(row.Path, "123")
				}
				if strings.Contains(row.Go, ".TelemetryClient.GroupBy") {
					expected = strings.ReplaceAll(row.Path, "{dimension}", "model")
				}
				if strings.Contains(row.Go, ".IAMScopesClient.") {
					expected = regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(row.Path, "ws_test")
				}
				if r.Method != row.Method || r.URL.Path != base+expected {
					t.Errorf("route=%s %s want=%s %s", r.Method, r.URL.Path, row.Method, base+expected)
				}
				if r.Header.Get("Authorization") != "Bearer token" {
					t.Error("OAuth missing")
				}
				if !strings.HasPrefix(row.Go, "runtime.") && r.Header.Get("X-Tsg-Id") != "123" {
					t.Error("tenant header missing")
				}
				_, _ = w.Write(row.Response)
			}))
			defer server.Close()
			gw, e := gateway.NewClient(gateway.Opts{ClientID: "id", ClientSecret: "secret", TsgID: "123", TokenEndpoint: server.URL + "/token", DataEndpoint: server.URL + "/data", AdminEndpoint: server.URL + "/admin", IAMEndpoint: server.URL + "/iam"})
			if e != nil {
				t.Fatal(e)
			}
			rt, e := runtime.NewClient(runtime.Opts{ClientID: "id", ClientSecret: "secret", TsgID: "123", TokenEndpoint: server.URL + "/token", APIEndpoint: server.URL + "/runtime", DLPEndpoint: server.URL + "/dlp"})
			if e != nil {
				t.Fatal(e)
			}
			parts := strings.Split(row.Go, ".")
			var receiver reflect.Value
			if parts[0] == "gateway" {
				receiver = reflect.ValueOf(gw).Elem().FieldByName(strings.TrimSuffix(parts[1], "Client"))
			} else {
				receiver = reflect.ValueOf(rt).Elem().FieldByName(strings.TrimSuffix(parts[1], "Client"))
				if !receiver.IsValid() {
					receiver = reflect.ValueOf(rt.DLP).Elem().FieldByName(strings.TrimSuffix(parts[1], "Client"))
				}
			}
			if !receiver.IsValid() {
				t.Fatal("missing receiver:", row.Go)
			}
			method := receiver.MethodByName(parts[2])
			if !method.IsValid() {
				t.Fatal("missing method:", row.Go)
			}
			args := []reflect.Value{reflect.ValueOf(context.Background())}
			for i := 1; i < method.Type().NumIn(); i++ {
				typ := method.Type().In(i)
				v := reflect.New(typ)
				if typ.Kind() == reflect.String {
					val := "550e8400-e29b-41d4-a716-446655440000"
					if strings.Contains(row.Go, ".OrganisationsClient.") {
						val = "123"
					}
					if strings.Contains(row.Go, ".TelemetryClient.GroupBy") {
						val = "model"
					}
					if strings.Contains(row.Go, ".IAMScopesClient.") {
						val = "ws_test"
					}
					v.Elem().SetString(val)
				} else {
					if i-1 < len(row.Parameters) && (row.Parameters[i-1].Name == "body" || row.Parameters[i-1].Name == "input") {
						if e = json.Unmarshal(row.Body, v.Interface()); e != nil {
							t.Fatal(e)
						}
					}
					fillOptions(v.Elem())
				}
				args = append(args, v.Elem())
			}
			result := method.Call(args)
			last := result[len(result)-1]
			if !last.IsNil() {
				t.Fatal(last.Interface())
			}
			if !reached {
				t.Fatal("operation never reached API")
			}
		})
	}
}
func fillOptions(v reflect.Value) {
	if v.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if !f.CanSet() {
			continue
		}
		name := v.Type().Field(i).Name
		if f.Kind() == reflect.Struct {
			fillOptions(f)
		}
		if f.Kind() == reflect.String && f.String() == "" {
			switch name {
			case "WorkspaceSlug":
				f.SetString("ws-test")
			case "Name":
				f.SetString("ws_test")
			case "AppID", "AppName", "SessionID", "ScanID":
				f.SetString("test")
			}
		}
		if f.Type() == reflect.TypeOf(time.Time{}) {
			f.Set(reflect.ValueOf(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)))
		}
	}
}
