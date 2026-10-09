package runtime

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func profileFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/directional-security-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func jsonTree(t *testing.T, b []byte) any {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func assertProfileJSON(t *testing.T, want []byte, value any) {
	t.Helper()
	got, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(jsonTree(t, want), jsonTree(t, got)) {
		t.Fatalf("JSON changed\nwant: %s\ngot: %s", want, got)
	}
}

func TestDirectionalProfileFixtureRoundTrip(t *testing.T) {
	post := profileFixture(t)
	get := jsonTree(t, post).(map[string]any)
	delete(get, "dlp_tenant_id")
	getBytes, err := json.Marshal(get)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{post, getBytes} {
		var profile SecurityProfile
		if err := json.Unmarshal(body, &profile); err != nil {
			t.Fatal(err)
		}
		assertProfileJSON(t, body, profile)
		var create CreateProfileRequest
		if err := json.Unmarshal(body, &create); err != nil {
			t.Fatal(err)
		}
		assertProfileJSON(t, body, create)
		var update UpdateProfileRequest
		if err := json.Unmarshal(body, &update); err != nil {
			t.Fatal(err)
		}
		assertProfileJSON(t, body, update)
	}
}

func TestProfilePresenceAndConstruction(t *testing.T) {
	for _, body := range []string{`{}`, `{"member":null}`, `{"member":[]}`, `{"member":["malicious"]}`} {
		var category URLCategoryMember
		if err := json.Unmarshal([]byte(body), &category); err != nil {
			t.Fatal(err)
		}
		assertProfileJSON(t, []byte(body), category)
		want := JSONOmitted
		switch body {
		case `{"member":null}`:
			want = JSONNull
		case `{"member":[]}`, `{"member":["malicious"]}`:
			want = JSONPresent
		}
		if category.FieldPresence("member") != want {
			t.Fatalf("presence for %s = %d", body, category.FieldPresence("member"))
		}
	}
	for _, body := range []string{`{}`, `{"mask-data-inline":false}`, `{"mask-data-inline":true}`} {
		var dlp DataLeakDetectionConfig
		if err := json.Unmarshal([]byte(body), &dlp); err != nil {
			t.Fatal(err)
		}
		assertProfileJSON(t, []byte(body), dlp)
		want := JSONPresent
		if body == `{}` {
			want = JSONOmitted
		}
		if dlp.FieldPresence("mask-data-inline") != want {
			t.Fatal("masking presence lost")
		}
	}
	for _, body := range []string{`{}`, `{"enable-full-conversation-inspection":false}`, `{"enable-full-conversation-inspection":true}`} {
		var model ModelConfiguration
		if err := json.Unmarshal([]byte(body), &model); err != nil {
			t.Fatal(err)
		}
		assertProfileJSON(t, []byte(body), model)
	}
	member := DataLeakMember{Text: "sensitive", ID: ""}
	member.SetFieldPresence("id", JSONPresent)
	dlp := DataLeakDetectionConfig{Member: []DataLeakMember{member}, Action: ProfileActionBlock}
	dlp.SetMaskDataInline(false)
	assertProfileJSON(t, []byte(`{"member":[{"text":"sensitive","id":""}],"action":"block","mask-data-inline":false}`), dlp)
	dlp.SetFieldPresence("mask-data-inline", JSONOmitted)
	assertProfileJSON(t, []byte(`{"member":[{"text":"sensitive","id":""}],"action":"block"}`), dlp)
	dlp.ResetFieldPresence("mask-data-inline")
	if dlp.FieldPresence("mask-data-inline") != JSONPresent {
		t.Fatal("constructed bool compatibility changed")
	}
	data := DataProtectionConfig{}
	data.SetFieldPresence("database-security", JSONNull)
	assertProfileJSON(t, []byte(`{"database-security":null}`), data)
	data.DatabaseSecurity = []DatabaseSecurityConfig{}
	assertProfileJSON(t, []byte(`{"database-security":[]}`), data)
	policy := ProfilePolicy{DlpDataProfiles: []DLPDataProfileConfig{}, AiSecurityProfiles: []AiSecurityProfileConfig{}}
	assertProfileJSON(t, []byte(`{"dlp-data-profiles":[],"ai-security-profiles":[]}`), policy)
	protect := ProtectionConfiguration{ModelProtection: []ModelProtectionConfig{}, AgentProtection: []AgentProtectionConfig{}}
	assertProfileJSON(t, []byte(`{"model-protection":[],"agent-protection":[]}`), protect)
	model := ModelConfiguration{}
	model.SetFieldPresence("mask-data-in-storage", JSONOmitted)
	assertProfileJSON(t, []byte(`{}`), model)
	var decoded DataLeakDetectionConfig
	if err := json.Unmarshal([]byte(`{}`), &decoded); err != nil {
		t.Fatal(err)
	}
	decoded.SetMaskDataInline(false)
	assertProfileJSON(t, []byte(`{"mask-data-inline":false}`), decoded)
	flag := false
	assertProfileJSON(t, []byte(`{"mask-data-in-storage":false,"enable-full-conversation-inspection":false}`), ModelConfiguration{EnableFullConversationInspection: &flag})
}

func TestProfileFutureFieldsAndIsolatedEdit(t *testing.T) {
	tree := jsonTree(t, profileFixture(t)).(map[string]any)
	tree["future-profile"] = map[string]any{"large": json.Number("900719925474099312345")}
	policy := tree["policy"].(map[string]any)
	policy["future-policy"] = []any{nil, map[string]any{}}
	ai := policy["ai-security-profiles"].([]any)[0].(map[string]any)
	ai["future-ai"] = true
	dirs := ai["content-type-configurations"].(map[string]any)
	dirs["future-direction"] = map[string]any{"future": json.Number("9007199254740993")}
	response := dirs["response"].(map[string]any)
	response["future-direction-setting"] = "keep"
	detector := response["model-protection"].([]any)[0].(map[string]any)
	detector["future-detector"] = map[string]any{"value": json.Number("123456789012345678901")}
	body, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	var profile SecurityProfile
	if err = json.Unmarshal(body, &profile); err != nil {
		t.Fatal(err)
	}
	assertProfileJSON(t, body, profile)
	typedDetector := &profile.Policy.AiSecurityProfiles[0].ContentTypeConfigurations.Response.ModelProtection[0]
	typedDetector.Action = ProfileActionAlert
	detector["action"] = "alert"
	expected, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	assertProfileJSON(t, expected, profile)
	// Typed values win over colliding extension keys, including omitted ones.
	typedDetector.Extensions["action"] = json.RawMessage(`123`)
	typedDetector.Extensions["severity"] = json.RawMessage(`123`)
	assertProfileJSON(t, expected, profile)
	profile.Extensions["dlp_tenant_id"] = json.RawMessage(`false`)
	profile.SetFieldPresence("dlp_tenant_id", JSONOmitted)
	delete(tree, "dlp_tenant_id")
	expected, err = json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	assertProfileJSON(t, expected, profile)
}

func TestProfileNestedExtensionsAndLegacy(t *testing.T) {
	body := []byte(`{"future":1,"ai-security-profiles":[{"model-configuration":{"latency":{"max-inline-latency":0,"inline-timeout-action":"","future":9007199254740993123},"data-protection":{"source-code-detection":{"action":"alert","severity":"custom","future":{}},"database-security":[],"data-leak-detection":{"member":null,"action":"","future":null}},"app-protection":{"url-detected-action":"","future":[],"default-url-category":{"member":null}},"model-protection":[{"name":"toxic-content","severity":"custom","severity-by-confidence":{"high":"","future":2},"toxic-category-list":[{"category":"custom","action":"high:block, moderate:allow","severity-by-confidence":{"moderate":"low","future":true},"future":[]}],"topic-list":[{"action":"allow","topic":null},{"action":"block","topic":[{"topic_name":"test","topic_id":"t1","revision":1,"severity":"custom","future":{}}]}],"options":[null,90071992547409931234,{}],"future":false}],"agent-protection":[{"name":"agent-security","action":"block","severity":"high","future":null}]} }],"dlp-data-profiles":[{"name":"d","uuid":"u","id":"","description":"","rule1":{"action":"","large":90071992547409931234},"rule2":{},"future":[]} ]}`)
	var policy ProfilePolicy
	if err := json.Unmarshal(body, &policy); err != nil {
		t.Fatal(err)
	}
	assertProfileJSON(t, body, policy)
	model := policy.AiSecurityProfiles[0].ModelConfiguration
	if model.DataProtection.SourceCodeDetection.Severity != "custom" || model.ModelProtection[0].ToxicCategoryList[0].SeverityByConfidence.Moderate != "low" || model.ModelProtection[0].TopicList[1].Topic[0].Severity != "custom" || model.AgentProtection[0].Severity != "high" {
		t.Fatal("extensions are not typed")
	}
	legacy := ModelConfiguration{MaskDataInStorage: false, ModelProtection: []ModelProtectionConfig{{Name: "prompt-injection", Action: ProfileActionBlock}}}
	assertProfileJSON(t, []byte(`{"mask-data-in-storage":false,"model-protection":[{"name":"prompt-injection","action":"block"}]}`), legacy)
}

func TestProfileRepeatedDecodingClearsFields(t *testing.T) {
	var profile SecurityProfile
	if err := json.Unmarshal(profileFixture(t), &profile); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"profile_name":"replacement"}`), &profile); err != nil {
		t.Fatal(err)
	}
	assertProfileJSON(t, []byte(`{"profile_name":"replacement"}`), profile)
	if profile.Policy != nil || profile.DLPTenantID != "" || profile.FieldPresence("active") != JSONOmitted {
		t.Fatal("obsolete fields retained")
	}
	var directions ContentTypeConfigurations
	if err := json.Unmarshal([]byte(`{"prompt":{},"future":{}}`), &directions); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"response":{}}`), &directions); err != nil {
		t.Fatal(err)
	}
	assertProfileJSON(t, []byte(`{"response":{}}`), directions)
}

func TestProfileRejectsMalformedKnownFields(t *testing.T) {
	bodies := []string{
		`null`, `[]`, `{"active":null}`, `{"dlp_tenant_id":123}`, `{"revision":1.5}`, `{"policy":null}`,
		`{"policy":{"ai-security-profiles":null}}`,
		`{"policy":{"ai-security-profiles":[null]}}`,
		`{"policy":{"ai-security-profiles":[{"content-type-mode":true}]}}`,
		`{"policy":{"ai-security-profiles":[{"model-configuration":{"mask-data-in-storage":null}}]}}`,
		`{"policy":{"ai-security-profiles":[{"model-configuration":{"enable-full-conversation-inspection":"false"}}]}}`,
		`{"policy":{"ai-security-profiles":[{"content-type-configurations":{"prompt":null}}]}}`,
		`{"policy":{"ai-security-profiles":[{"content-type-configurations":{"response":{"model-protection":null}}}]}}`,
		`{"policy":{"ai-security-profiles":[{"content-type-configurations":{"tool-call":{"model-protection":[{"severity":123}]}}}]}}`,
		`{"policy":{"ai-security-profiles":[{"content-type-configurations":{"tool-response":{"model-protection":[{"severity-by-confidence":{"high":123}}]}}}]}}`,
		`{"policy":{"ai-security-profiles":[{"model-configuration":{"app-protection":{"default-url-category":{"member":[null]}}}}]}}`,
		`{"policy":{"dlp-data-profiles":[{"rule1":{"action":123}}]}}`,
	}
	for _, body := range bodies {
		t.Run(body, func(t *testing.T) {
			var profile SecurityProfile
			if err := json.Unmarshal([]byte(body), &profile); err == nil {
				t.Fatal("invalid known field accepted")
			}
		})
	}
	// Exercise every protection/detector type through all four directions.
	for _, direction := range []string{"prompt", "response", "tool-call", "tool-response"} {
		for _, protection := range []string{
			`{"data-protection":{"database-security":[{"severity":123}]}}`,
			`{"data-protection":{"data-leak-detection":{"mask-data-inline":null}}}`,
			`{"data-protection":{"data-leak-detection":{"member":[{"id":false}]}}}`,
			`{"data-protection":{"source-code-detection":{"severity":[]}}}`,
			`{"app-protection":{"malicious-code-protection":{"severity":false}}}`,
			`{"app-protection":{"url-detected-severity":123}}`,
			`{"model-protection":[{"severity-by-confidence":{"moderate":null}}]}`,
			`{"model-protection":[{"toxic-category-list":[{"severity-by-confidence":{"high":{}}}]}]}`,
			`{"model-protection":[{"topic-list":[{"topic":[{"severity":123}]}]}]}`,
			`{"agent-protection":[{"severity":123}]}`,
			`{"model-protection":[{"options":{}}]}`,
		} {
			body := []byte(`{"` + direction + `":` + protection + `}`)
			var dirs ContentTypeConfigurations
			if err := json.Unmarshal(body, &dirs); err == nil {
				t.Fatalf("accepted %s", body)
			}
		}
	}
}

func TestProfileExtensionPresence(t *testing.T) {
	profile := SecurityProfile{ProfileJSON: ProfileJSON{Extensions: map[string]json.RawMessage{
		"future-null": json.RawMessage(`null`), "future-empty": json.RawMessage(`[]`),
	}}}
	if profile.FieldPresence("future-null") != JSONNull || profile.FieldPresence("future-empty") != JSONPresent || profile.FieldPresence("missing") != JSONOmitted {
		t.Fatal("extension presence changed")
	}
}

func TestProfileExtensionMutationAndFieldNames(t *testing.T) {
	var profile SecurityProfile
	if err := json.Unmarshal([]byte(`{"profile_name":"test"}`), &profile); err != nil {
		t.Fatal(err)
	}
	// A decoded object without unknown fields must provide writable storage.
	profile.Extensions["new-field"] = json.RawMessage(`90071992547409931234`)
	if !profile.HasField("active") || !profile.HasField("new-field") || profile.HasField("mask_data_inline") {
		t.Fatal("field-name recognition failed")
	}
	if profile.FieldPresence("active") != JSONOmitted {
		t.Fatal("omitted known field changed")
	}
	assertProfileJSON(t, []byte(`{"profile_name":"test","new-field":90071992547409931234}`), profile)
	constructed := SecurityProfile{}
	raw := json.RawMessage(`{"large":90071992547409931234}`)
	if err := constructed.SetExtension("future", raw); err != nil {
		t.Fatal(err)
	}
	raw[0] = '['
	copy := constructed
	if err := copy.SetExtension("future-copy", json.RawMessage(`null`)); err != nil {
		t.Fatal(err)
	}
	if constructed.HasField("future-copy") {
		t.Fatal("setter mutated copied extension map")
	}
	if err := constructed.SetExtension("invalid", json.RawMessage(`{`)); err == nil {
		t.Fatal("accepted invalid extension")
	}
	assertProfileJSON(t, []byte(`{"active":false,"future":{"large":90071992547409931234}}`), constructed)
}

func TestProfileListEnvelopeExtensions(t *testing.T) {
	assertProfileJSON(t, []byte(`{"ai_profiles":null}`), SecurityProfileListResponse{})
	var response SecurityProfileListResponse
	body := []byte(`{"ai_profiles":[],"next_offset":0,"future":{"count":90071992547409931234}}`)
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	assertProfileJSON(t, body, response)
	if !response.HasField("ai_profiles") || response.FieldPresence("next_offset") != JSONPresent {
		t.Fatal("list presence changed")
	}
	if err := json.Unmarshal([]byte(`{"ai_profiles":[]}`), &response); err != nil {
		t.Fatal(err)
	}
	assertProfileJSON(t, []byte(`{"ai_profiles":[]}`), response)
}

func TestProfileRejectsArrayWhereObjectExpected(t *testing.T) {
	for _, body := range []string{
		`{"content-type-configurations":[]}`,
		`{"content-type-configurations":{"response":[]}}`,
	} {
		var ai AiSecurityProfileConfig
		if err := json.Unmarshal([]byte(body), &ai); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
}

func TestProfileConstructedNullPresence(t *testing.T) {
	for _, tc := range []struct {
		value interface{ FieldPresence(string) JSONPresence }
		field string
		body  string
	}{
		{DataLeakDetectionConfig{Action: ProfileActionBlock}, "member", `{"action":"block","mask-data-inline":false,"member":null}`},
		{TopicArrayConfig{Action: ProfileActionAllow}, "topic", `{"action":"allow","topic":null}`},
		{SecurityProfileListResponse{}, "ai_profiles", `{"ai_profiles":null}`},
	} {
		if tc.value.FieldPresence(tc.field) != JSONNull {
			t.Fatalf("%T.%s: presence should match serialized null", tc.value, tc.field)
		}
		assertProfileJSON(t, []byte(tc.body), tc.value)
	}
	category := URLCategoryMember{}
	if category.FieldPresence("member") != JSONOmitted {
		t.Fatal("nil optional array should remain omitted")
	}
	category.SetFieldPresence("member", JSONPresent)
	if category.FieldPresence("member") != JSONNull {
		t.Fatal("present nil nullable array should report null")
	}
	assertProfileJSON(t, []byte(`{"member":null}`), category)
}
