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

func TestWorkspaceClearSettingsUsesVerifiedNullAndEmptyBodies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_, _ = w.Write([]byte(`{"access_token":"fixture","expires_in":3600}`))
			return
		}
		if r.Method != http.MethodPut || r.URL.Path != "/admin/workspaces/ws-uuid" || r.Header.Get("x-tsg-id") != "tenant" || r.Header.Get("Authorization") != "Bearer fixture" {
			t.Error("wrong method, plane, identity or shared credentials")
		}
		var body map[string]any
		if e := json.NewDecoder(r.Body).Decode(&body); e != nil {
			t.Error(e)
		}
		want := map[string]any{"defaults": map[string]any{"config_id": nil, "metadata": map[string]any{}}, "usage_limits": nil, "rate_limits": []any{}, "icon": ""}
		if !reflect.DeepEqual(body, want) {
			t.Errorf("clear request %#v does not match verified wire contract", body)
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	c, e := NewClient(Opts{ClientID: "id", ClientSecret: "secret", TsgID: "tenant", TokenEndpoint: server.URL + "/token", DataEndpoint: server.URL + "/data", AdminEndpoint: server.URL + "/admin"})
	if e != nil {
		t.Fatal(e)
	}
	if e = c.Workspaces.ClearSettings(context.Background(), "ws-uuid", WorkspaceClearSettingsRequest{Defaults: true, UsageLimits: true, RateLimits: true, Icon: true}); e != nil {
		t.Fatal(e)
	}
}
func TestWorkspaceClearSettingsRejectsEmptyOrInvalidReferenceBeforeRequests(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(500) }))
	defer server.Close()
	c, e := NewClient(Opts{ClientID: "id", ClientSecret: "secret", TsgID: "tenant", TokenEndpoint: server.URL, DataEndpoint: server.URL, AdminEndpoint: server.URL})
	if e != nil {
		t.Fatal(e)
	}
	for _, test := range []struct {
		ref   string
		input WorkspaceClearSettingsRequest
	}{{"ws", WorkspaceClearSettingsRequest{}}, {"../other", WorkspaceClearSettingsRequest{Defaults: true}}} {
		var typed *aisec.AISecSDKError
		e = c.Workspaces.ClearSettings(context.Background(), test.ref, test.input)
		if !errors.As(e, &typed) || typed.ErrorType != aisec.UserRequestPayloadError {
			t.Fatal("expected typed input rejection", e)
		}
	}
	if calls != 0 {
		t.Fatal("invalid clear settings reached transport")
	}
}

func TestWorkspaceClearSettingsSelectsUsageOnlyAndPreservesTypedErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_, _ = w.Write([]byte(`{"access_token":"fixture","expires_in":3600}`))
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(body, map[string]any{"usage_limits": nil}) {
			t.Error("an unselected workspace setting was included", body)
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"workspace not found"}`))
	}))
	defer server.Close()
	c, err := NewClient(Opts{ClientID: "id", ClientSecret: "secret", TsgID: "tenant", TokenEndpoint: server.URL + "/token", DataEndpoint: server.URL + "/data", AdminEndpoint: server.URL + "/admin"})
	if err != nil {
		t.Fatal(err)
	}
	err = c.Workspaces.ClearSettings(context.Background(), "ws-uuid", WorkspaceClearSettingsRequest{UsageLimits: true})
	if !aisec.IsNotFound(err) {
		t.Fatal("HTTP error identity was lost", err)
	}
}
