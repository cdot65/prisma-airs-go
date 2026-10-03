package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/cdot65/prisma-airs-go/aisec"
)

func TestWorkspaceProvisionWireOrderAndBinding(t *testing.T) {
	var calls []string
	var tokens int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			tokens++
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer token" || r.Header.Get("X-Tsg-Id") != "tenant" {
			t.Error("missing shared OAuth/tenant headers")
		}
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch r.Method + " " + r.URL.Path {
		case "POST /iam/scopes":
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b["name"] != "ws_test_abcdef" || b["description"] != "" || !reflect.DeepEqual(b["resources"], []any{}) {
				t.Errorf("scope create body: %#v", b)
			}
			_, _ = w.Write([]byte(`{"name":"ws_test_abcdef","description":"","resources":[],"tsg_id":"tenant","id":"ws_test_abcdef:tenant"}`))
		case "POST /admin/workspaces":
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b["name"] != "Test" || b["scope_name"] != "ws_test_abcdef" {
				t.Errorf("workspace create body: %#v", b)
			}
			_, _ = w.Write([]byte(`{"id":"uuid","name":"Test","slug":"ws-test-abc123","scope_name":"ws_test_abcdef","description":null,"created_at":"now","last_updated_at":"now","object":"workspace"}`))
		case "GET /iam/scopes/ws_test_abcdef":
			_, _ = w.Write([]byte(`{"name":"ws_test_abcdef","description":"keep","resources":[{"resource_type":"workspace","resource_id":"ws-existing","metadata":["keep"]}],"tsg_id":"tenant","id":"ws_test_abcdef:tenant"}`))
		case "PUT /iam/scopes/ws_test_abcdef":
			var b struct {
				Name        string             `json:"name"`
				Description string             `json:"description"`
				Resources   []IAMScopeResource `json:"resources"`
			}
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b.Name != "ws_test_abcdef" || b.Description != "keep" || len(b.Resources) != 2 || b.Resources[0].ResourceID != "ws-existing" || b.Resources[1].ResourceID != "ws-test-abc123" || b.Resources[1].Metadata == nil {
				t.Errorf("binding must preserve existing resources and use slug: %#v", b)
			}
			_ = json.NewEncoder(w).Encode(IAMScope{Name: b.Name, Description: b.Description, Resources: b.Resources, TSGID: "tenant", ID: b.Name + ":tenant"})
		default:
			t.Errorf("unexpected request: %s", calls[len(calls)-1])
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	c, err := NewClient(Opts{ClientID: "id", ClientSecret: "secret", TsgID: "tenant", DataEndpoint: server.URL + "/data", AdminEndpoint: server.URL + "/admin", IAMEndpoint: server.URL + "/iam", TokenEndpoint: server.URL + "/token"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.Workspaces.Provision(context.Background(), WorkspaceCreateRequest{Name: "Test", ScopeName: "ws_test_abcdef"}, WorkspaceProvisionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Workspace.Slug != "ws-test-abc123" || !result.ScopeCreated || tokens != 1 {
		t.Fatalf("result=%#v tokens=%d", result, tokens)
	}
	want := []string{"POST /iam/scopes", "POST /admin/workspaces", "GET /iam/scopes/ws_test_abcdef", "PUT /iam/scopes/ws_test_abcdef"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls=%v want=%v", calls, want)
	}
}

func TestWorkspaceProvisionFailureRetainsOwnedIdentities(t *testing.T) {
	for _, stage := range []string{"rejected", "ambiguous", "bind"} {
		t.Run(stage, func(t *testing.T) {
			var deleted bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/token" {
					_, _ = w.Write([]byte(`{"access_token":"t","expires_in":3600}`))
					return
				}
				if r.Method == http.MethodDelete {
					deleted = true
					w.WriteHeader(405)
					return
				}
				if r.URL.Path == "/admin/workspaces" {
					if stage == "rejected" {
						w.WriteHeader(400)
						_, _ = w.Write([]byte(`{"message":"rejected"}`))
						return
					}
					if stage == "ambiguous" {
						w.WriteHeader(500)
						_, _ = w.Write([]byte(`{"message":"uncertain"}`))
						return
					}
					_, _ = w.Write([]byte(`{"id":"uuid","slug":"ws-owned","name":"Test","scope_name":"ws_test","description":null,"created_at":"now","last_updated_at":"now","object":"workspace"}`))
					return
				}
				if r.Method == http.MethodPut {
					w.WriteHeader(403)
					_, _ = w.Write([]byte(`{"message":"denied"}`))
					return
				}
				_, _ = w.Write([]byte(`{"name":"ws_test","description":"","resources":[],"tsg_id":"tenant","id":"ws_test:tenant"}`))
			}))
			defer server.Close()
			c, err := NewClient(Opts{ClientID: "id", ClientSecret: "secret", TsgID: "tenant", DataEndpoint: server.URL + "/data", AdminEndpoint: server.URL + "/admin", IAMEndpoint: server.URL + "/iam", TokenEndpoint: server.URL + "/token"})
			if err != nil {
				t.Fatal(err)
			}
			result, err := c.Workspaces.Provision(context.Background(), WorkspaceCreateRequest{Name: "Test", ScopeName: "ws_test"}, WorkspaceProvisionOptions{})
			var provisionErr *WorkspaceProvisionError
			if !errors.As(err, &provisionErr) || result == nil || result.ScopeName != "ws_test" || !result.ScopeCreated {
				t.Fatalf("lost partial result: %#v %v", result, err)
			}
			if deleted != (stage == "rejected") {
				t.Fatalf("unsafe cleanup at stage %s: %v", stage, deleted)
			}
			if stage == "rejected" && (provisionErr.CleanupError == nil || !provisionErr.CleanupAttempted) {
				t.Fatal("unverified DELETE failure hidden")
			}
			if stage == "bind" && (!errors.Is(err, aisec.ErrForbidden) || result.Workspace == nil || result.Workspace.Slug != "ws-owned") {
				t.Fatal("binding failure lost workspace or HTTP error")
			}
		})
	}
}

func TestWorkspaceValidationBeforeOAuth(t *testing.T) {
	c, err := NewClient(Opts{ClientID: "id", ClientSecret: "secret", TsgID: "tenant", TokenEndpoint: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Workspaces.Provision(context.Background(), WorkspaceCreateRequest{Name: ""}, WorkspaceProvisionOptions{})
	var sdkErr *aisec.AISecSDKError
	if !errors.As(err, &sdkErr) || sdkErr.ErrorType != aisec.UserRequestPayloadError {
		t.Fatalf("must validate before OAuth: %v", err)
	}
	_, err = c.IAMScopes.Get(context.Background(), "name:tenant")
	if !errors.As(err, &sdkErr) || sdkErr.ErrorType != aisec.UserRequestPayloadError {
		t.Fatalf("composite scope ID accepted: %v", err)
	}
}

func TestWorkspacePlanesAndArchiveEnvelope(t *testing.T) {
	calls := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
			return
		}
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Method == "GET" && r.URL.Path == "/admin/workspaces" {
			if r.URL.Query().Get("status") != "archived" {
				t.Error("archive filter missing")
			}
			_, _ = w.Write([]byte(`{"data":[],"object":"list","total":5,"has_more":true}`))
			return
		}
		if r.Method == "GET" {
			_, _ = w.Write([]byte(`{"id":"uuid","name":"Test","slug":"ws-test","scope_name":"ws_test","description":null,"created_at":"now","last_updated_at":"now","object":"workspace","status":"active","is_default":0,"icon":null,"defaults":null,"usage_limits":null,"rate_limits":null}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	c, err := NewClient(Opts{ClientID: "id", ClientSecret: "secret", TsgID: "123", DataEndpoint: server.URL + "/data", AdminEndpoint: server.URL + "/admin", IAMEndpoint: server.URL + "/iam", TokenEndpoint: server.URL + "/token"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err = c.Workspaces.Get(ctx, "ws-test", WorkspaceGetOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Workspaces.Get(ctx, "ws-test", WorkspaceGetOptions{Plane: WorkspaceAdmin}); err != nil {
		t.Fatal(err)
	}
	result, err := c.Workspaces.List(ctx, WorkspaceListOptions{Plane: WorkspaceAdmin, Status: "archived"})
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(result)
	var fields map[string]any
	_ = json.Unmarshal(wire, &fields)
	if fields["has_more"] != true || fields["total"] != float64(5) {
		t.Fatalf("paging envelope lost: %s", wire)
	}
	name := "updated"
	if err = c.Workspaces.Update(ctx, "ws-test", WorkspaceUpdateRequest{Name: &name}); err != nil {
		t.Fatal(err)
	}
	if err = c.Workspaces.Delete(ctx, "ws-test"); err != nil {
		t.Fatal(err)
	}
	want := []string{"GET /data/workspaces/ws-test", "GET /admin/workspaces/ws-test", "GET /admin/workspaces", "PUT /admin/workspaces/ws-test", "DELETE /admin/workspaces/ws-test"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatal(calls)
	}
}

func TestWorkspaceListPassesThroughFutureStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
			return
		}
		if r.Method != "GET" || r.URL.Path != "/workspaces" || r.URL.Query().Get("status") != "future-status" {
			t.Error(r.URL)
		}
		_, _ = w.Write([]byte(`{"data":[],"object":"list","total":0,"has_more":false}`))
	}))
	defer server.Close()
	c, err := NewClient(Opts{ClientID: "id", ClientSecret: "secret", TsgID: "123", DataEndpoint: server.URL, AdminEndpoint: server.URL, IAMEndpoint: server.URL, TokenEndpoint: server.URL + "/token"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Workspaces.List(context.Background(), WorkspaceListOptions{Status: "future-status"}); err != nil {
		t.Fatal(err)
	}
}
