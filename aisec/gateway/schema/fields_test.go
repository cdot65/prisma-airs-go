package schema

import (
	"encoding/json"
	"github.com/cdot65/prisma-airs-go/aisec"
	"reflect"
	"testing"
)

func TestJSONDocumentWireForms(t *testing.T) {
	for _, raw := range []string{`{"provider":"@test","nested":{"extra":false}}`, `"{\"provider\":\"@test\",\"nested\":{\"extra\":false}}"`} {
		var doc JSONDocument
		if err := json.Unmarshal([]byte(raw), &doc); err != nil {
			t.Fatal(err)
		}
		var value struct{ Provider string }
		if err := doc.Decode(&value); err != nil || value.Provider != "@test" {
			t.Fatal("object decode failed")
		}
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		var a, c any
		_ = json.Unmarshal([]byte(raw), &a)
		_ = json.Unmarshal(b, &c)
		if !reflect.DeepEqual(a, c) {
			t.Fatal("wire shape changed")
		}
	}
	for _, raw := range []string{`null`, `[]`, `"bad"`, `"[]"`, `42`, `{"broken":`} {
		var doc JSONDocument
		if err := json.Unmarshal([]byte(raw), &doc); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}

func TestCurrentConfigReadPreservesWireFormsAndFutureFields(t *testing.T) {
	raw := []byte(`{"id":"id","config":"{\"provider\":\"@test\"}","future_field":{"version":0}}`)
	var value ConfigsGetResponse
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	if value.ID == nil || *value.ID != "id" || value.Config == nil {
		t.Fatal("flat record fields omitted")
	}
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var a, c any
	_ = json.Unmarshal(raw, &a)
	_ = json.Unmarshal(b, &c)
	if !reflect.DeepEqual(a, c) {
		t.Fatal("read fields changed")
	}
	value.AdditionalFields["id"] = json.RawMessage(`"spoofed"`)
	b, err = json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result ConfigsGetResponse
	if err := json.Unmarshal(b, &result); err != nil || result.ID == nil || *result.ID != "id" {
		t.Fatal("extra field overrode typed identity")
	}
}

func TestOptionalUpdateIntent(t *testing.T) {
	no := false
	empty := []string{}
	value := UpdateDeploymentRequest{IsDefault: &no, RotateAuth: &no, OverrideExisting: &no, DeploymentConfig: aisec.Null[map[string]any](), AuthSettings: &UpdateDeploymentRequestAuthSettings{WorkspacesAllowed: &empty}}
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"is_default", "rotate_auth", "override_existing"} {
		if string(got[key]) != "false" {
			t.Errorf("%s false lost", key)
		}
	}
	if string(got["deployment_config"]) != "null" {
		t.Fatal("explicit null lost")
	}
	if _, ok := got["name"]; ok {
		t.Fatal("unset name emitted")
	}
	var settings map[string]json.RawMessage
	_ = json.Unmarshal(got["auth_settings"], &settings)
	if string(settings["workspaces_allowed"]) != "[]" {
		t.Fatal("empty binding list lost")
	}
}
func TestMalformedConfigurationProducesNoPartialValue(t *testing.T) {
	var value ConfigsGetResponse
	if err := json.Unmarshal([]byte(`{"id":"created","config":"bad"}`), &value); err == nil {
		t.Fatal("malformed configuration accepted")
	}
	if value.ID != nil || value.Config != nil {
		t.Fatal("partial configuration exposed")
	}
}
