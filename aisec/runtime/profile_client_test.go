package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/cdot65/prisma-airs-go/aisec"
)

func TestDirectionalProfileCRUD(t *testing.T) {
	post := profileFixture(t)
	tree := jsonTree(t, post).(map[string]any)
	delete(tree, "dlp_tenant_id")
	get, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	var expectedUpdate []byte
	var calls []string
	token, api := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPost:
			if r.URL.Path != aisec.MgmtProfilePath {
				t.Errorf("create path = %s", r.URL.Path)
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			assertProfileJSON(t, post, json.RawMessage(body))
			_, _ = w.Write(post)
		case http.MethodGet:
			if r.URL.Path != aisec.MgmtProfilesTsgPath+"/123" {
				t.Errorf("list path = %s", r.URL.Path)
			}
			if r.URL.Query().Get("offset") != "0" {
				t.Errorf("offset = %s", r.URL.Query().Get("offset"))
			}
			_, _ = w.Write(append(append([]byte(`{"ai_profiles":[`), get...), []byte(`]}`)...))
		case http.MethodPut:
			if r.URL.Path != aisec.MgmtProfilePath+"/uuid/550e8400-e29b-41d4-a716-446655440000" {
				t.Errorf("update path = %s", r.URL.Path)
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			assertProfileJSON(t, expectedUpdate, json.RawMessage(body))
			response := jsonTree(t, expectedUpdate).(map[string]any)
			response["revision"] = json.Number("2")
			response["profile_id"] = "new-revision-id"
			_ = json.NewEncoder(w).Encode(response)
		default:
			t.Errorf("unexpected method %s", r.Method)
			w.WriteHeader(500)
		}
	})
	defer token.Close()
	defer api.Close()
	client := newTestClient(t, token.URL, api.URL)
	var create CreateProfileRequest
	if err = json.Unmarshal(post, &create); err != nil {
		t.Fatal(err)
	}
	created, err := client.Profiles.Create(context.Background(), create)
	if err != nil {
		t.Fatal(err)
	}
	assertProfileJSON(t, post, created)
	listed, err := client.Profiles.List(context.Background(), ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Items) != 1 {
		t.Fatal("missing profile")
	}
	assertProfileJSON(t, get, listed.Items[0])
	retrieved, err := client.Profiles.GetByID(context.Background(), created.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	assertProfileJSON(t, get, retrieved)
	retrieved.Policy.AiSecurityProfiles[0].ContentTypeConfigurations.Response.ModelProtection[0].Severity = "custom-severity"
	dirs := tree["policy"].(map[string]any)["ai-security-profiles"].([]any)[0].(map[string]any)["content-type-configurations"].(map[string]any)
	dirs["response"].(map[string]any)["model-protection"].([]any)[0].(map[string]any)["severity"] = "custom-severity"
	expectedUpdate, err = json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(retrieved)
	if err != nil {
		t.Fatal(err)
	}
	var update UpdateProfileRequest
	if err = json.Unmarshal(body, &update); err != nil {
		t.Fatal(err)
	}
	updated, err := client.Profiles.Update(context.Background(), created.ProfileID, update)
	if err != nil {
		t.Fatal(err)
	}
	tree["revision"] = json.Number("2")
	tree["profile_id"] = "new-revision-id"
	expected, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	assertProfileJSON(t, expected, updated)
	if len(calls) != 4 {
		t.Fatalf("calls = %v", calls)
	}
}

func TestProfileRequestValidationBeforeIO(t *testing.T) {
	var calls atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) })
	token := httptest.NewServer(handler)
	defer token.Close()
	api := httptest.NewServer(handler)
	defer api.Close()
	client := newTestClient(t, token.URL, api.URL)
	for _, kind := range []string{"invalid-extension", "invalid-rule-action", "invalid-null", "invalid-present-nil-array", "invalid-present-nil-object", "invalid-nonzero-null", "invalid-presence", "unknown-presence", "invalid-detector-options"} {
		t.Run(kind, func(t *testing.T) {
			profile := CreateProfileRequest{ProfileName: "invalid", Policy: &ProfilePolicy{}}
			switch kind {
			case "invalid-extension":
				profile.Extensions = map[string]json.RawMessage{"future": json.RawMessage(`{`)}
			case "invalid-rule-action":
				profile.Policy.DlpDataProfiles = []DLPDataProfileConfig{{Rule1: map[string]any{"action": 123}}}
			case "invalid-null":
				profile.Policy.SetFieldPresence("ai-security-profiles", JSONNull)
			case "invalid-present-nil-array":
				profile.Policy.SetFieldPresence("ai-security-profiles", JSONPresent)
			case "invalid-present-nil-object":
				profile.Policy = nil
				profile.SetFieldPresence("policy", JSONPresent)
			case "invalid-nonzero-null":
				profile.SetFieldPresence("profile_name", JSONNull)
			case "invalid-presence":
				profile.Policy.SetFieldPresence("ai-security-profiles", JSONPresence(99))
			case "unknown-presence":
				profile.Policy.SetFieldPresence("unknown", JSONPresent)
			case "invalid-detector-options":
				profile.Policy.AiSecurityProfiles = []AiSecurityProfileConfig{{ContentTypeConfigurations: &ContentTypeConfigurations{Response: &ProtectionConfiguration{ModelProtection: []ModelProtectionConfig{{Options: []json.RawMessage{json.RawMessage(`{`)}}}}}}}
			}
			_, err := client.Profiles.Create(context.Background(), profile)
			var sdk *aisec.AISecSDKError
			if !errors.As(err, &sdk) || sdk.ErrorType != aisec.UserRequestPayloadError {
				t.Fatalf("create error = %v", err)
			}
			update := UpdateProfileRequest{ProfileName: profile.ProfileName, Policy: profile.Policy, ProfileJSON: profile.ProfileJSON}
			_, err = client.Profiles.Update(context.Background(), "id", update)
			if !errors.As(err, &sdk) || sdk.ErrorType != aisec.UserRequestPayloadError {
				t.Fatalf("update error = %v", err)
			}
			if calls.Load() != 0 {
				t.Fatalf("made %d token/API calls", calls.Load())
			}
		})
	}
}
