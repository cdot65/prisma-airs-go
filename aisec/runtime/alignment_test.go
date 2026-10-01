package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestProfiles_ListWithOptionsIncludesExplicitFalse(t *testing.T) {
	token, api := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/mgmt/profiles/tsg/123" || r.URL.Query().Get("latest") != "false" || r.URL.Query().Get("offset") != "3" {
			t.Errorf("unexpected profile listing: %s", r.URL)
		}
		_, _ = w.Write([]byte(`{"ai_profiles":[],"next_offset":0}`))
	})
	t.Cleanup(token.Close)
	t.Cleanup(api.Close)
	latest := false
	_, err := newTestClient(t, token.URL, api.URL).Profiles.ListWithOptions(context.Background(), ProfileListOpts{ListOpts: ListOpts{Offset: 3, Limit: 5}, Latest: &latest})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeploymentProfiles_ListWithOptionsIncludesExplicitFalse(t *testing.T) {
	token, api := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/mgmt/deploymentprofiles" || r.URL.Query().Get("unactivated") != "false" {
			t.Errorf("unexpected deployment listing: %s", r.URL)
		}
		_, _ = w.Write([]byte(`{"deployment_profiles":[]}`))
	})
	t.Cleanup(token.Close)
	t.Cleanup(api.Close)
	unactivated := false
	_, err := newTestClient(t, token.URL, api.URL).DeploymentProfiles.ListWithOptions(context.Background(), DeploymentProfileListOpts{Unactivated: &unactivated})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTopics_UpdateFieldsPreservesEmptyDescriptionAndExamples(t *testing.T) {
	token, api := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" || r.URL.EscapedPath() != "/v1/mgmt/topic/uuid/id%2Fsegment" {
			t.Errorf("unexpected update: %s %s", r.Method, r.URL)
		}
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if string(body["description"]) != `""` || string(body["examples"]) != `[]` {
			t.Errorf("lost explicit empty values: %v", body)
		}
		if _, ok := body["active"]; ok {
			t.Error("absent active must be omitted")
		}
		_, _ = w.Write([]byte(`{"topic_id":"id/segment","description":"","examples":[]}`))
	})
	t.Cleanup(token.Close)
	t.Cleanup(api.Close)
	empty := ""
	examples := []string{}
	_, err := newTestClient(t, token.URL, api.URL).Topics.UpdateFields(context.Background(), "id/segment", UpdateTopicFieldsRequest{Description: &empty, Examples: &examples})
	if err != nil {
		t.Fatal(err)
	}
}

func TestProfiles_ForceDeletePreservesPolicyPayload(t *testing.T) {
	token, api := newTestMgmtServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"message":"deleted","payload":[{"policy_id":"policy-1","policy_name":"policy","priority":0}]}`))
	})
	t.Cleanup(token.Close)
	t.Cleanup(api.Close)
	r, err := newTestClient(t, token.URL, api.URL).Profiles.ForceDelete(context.Background(), "id", "tester")
	if err != nil || r == nil || len(r.Payload) != 1 || r.Payload[0].PolicyID != "policy-1" {
		t.Fatalf("result=%+v error=%v", r, err)
	}
}

func TestTopics_DeletePreservesProfilePayload(t *testing.T) {
	token, api := newTestMgmtServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"message":"deleted","payload":[{"profile_id":"profile-1","profile_name":"profile","revision":0}]}`))
	})
	t.Cleanup(token.Close)
	t.Cleanup(api.Close)
	r, err := newTestClient(t, token.URL, api.URL).Topics.Delete(context.Background(), "id")
	if err != nil || r == nil || len(r.Payload) != 1 || r.Payload[0].ProfileID != "profile-1" {
		t.Fatalf("result=%+v error=%v", r, err)
	}
}

func TestOAuth_GetTokenWithTTL(t *testing.T) {
	token, api := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("tokenTtlInterval") != "0" || r.URL.Query().Get("tokenTtlUnit") != "minute" {
			t.Errorf("TTL query=%s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"access_token":"test"}`))
	})
	t.Cleanup(token.Close)
	t.Cleanup(api.Close)
	zero := int64(0)
	_, err := newTestClient(t, token.URL, api.URL).OAuth.GetTokenWithTTL(context.Background(), OAuthTokenRequest{ClientID: "app"}, TokenTTLOpts{Interval: &zero, Unit: "minute"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestApiKeys_DeleteAcceptsLiveJSONString(t *testing.T) {
	token, api := newTestMgmtServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`"apikey and customer-app successfully deleted"`))
	})
	t.Cleanup(token.Close)
	t.Cleanup(api.Close)
	r, err := newTestClient(t, token.URL, api.URL).ApiKeys.Delete(context.Background(), "key", "tester")
	if err != nil || r == nil || r.Message != "apikey and customer-app successfully deleted" {
		t.Fatalf("result=%+v error=%v", r, err)
	}
}

func TestProfiles_OrdinaryDeleteAcceptsLiveJSONString(t *testing.T) {
	token, api := newTestMgmtServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`"successfully deleted profileId: id"`))
	})
	t.Cleanup(token.Close)
	t.Cleanup(api.Close)
	r, err := newTestClient(t, token.URL, api.URL).Profiles.Delete(context.Background(), "id")
	if err != nil || r == nil || r.Message != "successfully deleted profileId: id" {
		t.Fatalf("result=%+v error=%v", r, err)
	}
}

func TestProfiles_CreatePreservesExplicitZeroAndFalse(t *testing.T) {
	token, api := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		var b map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			t.Error(err)
		}
		if string(b["revision"]) != "0" || string(b["active"]) != "false" {
			t.Errorf("request lost zero/false: %v", b)
		}
		_, _ = w.Write([]byte(`{"profile_id":"p"}`))
	})
	t.Cleanup(token.Close)
	t.Cleanup(api.Close)
	zero := int32(0)
	inactive := false
	if _, err := newTestClient(t, token.URL, api.URL).Profiles.Create(context.Background(), CreateProfileRequest{ProfileName: "test", Revision: &zero, Active: &inactive}); err != nil {
		t.Fatal(err)
	}
}

func TestCustomerApps_DeletePreservesReturnedMetadata(t *testing.T) {
	token, api := newTestMgmtServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"customer_appId":"app-1","app_name":"test","status":"deleted"}`))
	})
	t.Cleanup(token.Close)
	t.Cleanup(api.Close)
	r, err := newTestClient(t, token.URL, api.URL).CustomerApps.Delete(context.Background(), "test", "tester")
	if err != nil || r == nil || r.CustomerAppID != "app-1" || r.Status != "deleted" {
		t.Fatalf("result=%+v error=%v", r, err)
	}
}
