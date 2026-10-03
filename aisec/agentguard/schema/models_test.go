package schema

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/cdot65/prisma-airs-go/aisec"
)

func TestUploadOptionalIntent(t *testing.T) {
	for _, tc := range []struct {
		name string
		git  aisec.Optional[string]
		want string
	}{
		{"omitted", aisec.Optional[string]{}, `{"name":"skill"}`},
		{"null", aisec.Null[string](), `{"name":"skill","git_url":null}`},
		{"empty", aisec.Value(""), `{"name":"skill","git_url":""}`},
		{"value", aisec.Value("https://example.com/repo"), `{"name":"skill","git_url":"https://example.com/repo"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(AgentGuardUploadCompleteRequest{Name: "skill", GitURL: tc.git})
			if err != nil {
				t.Fatal(err)
			}
			equalJSON(t, b, []byte(tc.want))
			var decoded AgentGuardUploadCompleteRequest
			if err := json.Unmarshal(b, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.GitURL.IsSet() != tc.git.IsSet() || decoded.GitURL.IsNull() != tc.git.IsNull() {
				t.Error("optional intent changed")
			}
		})
	}
}

func TestInstanceExtensibilityAndFalse(t *testing.T) {
	payload := []byte(`{"tsg_id":"tsg","tenant_id":"tenant","created_by":"user","support_account_id":"support","iam_controlled":false,"entitlements":[{"kind":"preview"}],"extra":{"custom":7},"preview_extension":{"enabled":false}}`)
	var value InstanceCreateModel
	if err := json.Unmarshal(payload, &value); err != nil {
		t.Fatal(err)
	}
	controlled, ok := value.IamControlled.Get()
	if !ok || controlled {
		t.Error("explicit false lost")
	}
	value.AdditionalFields["tenant_id"] = json.RawMessage(`"incorrect"`)
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	equalJSON(t, b, payload)
	// Reusing a target must clear extension fields absent in its next payload.
	if err := json.Unmarshal([]byte(`{"tenant_id":"next"}`), &value); err != nil {
		t.Fatal(err)
	}
	if len(value.AdditionalFields) != 0 || value.IamControlled.IsSet() {
		t.Error("old fields retained")
	}
}

func TestRequiredNullAndOpenEnums(t *testing.T) {
	payload := []byte(`{"total_rule_violations":{"count":0,"percent_change":null},"total_enabled_rules":null,"most_violated_rules":null}`)
	var stats AgentGuardSkillStatsResponse
	if err := json.Unmarshal(payload, &stats); err != nil {
		t.Fatal(err)
	}
	if stats.TotalEnabledRules != nil || !stats.MostViolatedRules.IsNull() {
		t.Error("null lost")
	}
	b, err := json.Marshal(stats)
	if err != nil {
		t.Fatal(err)
	}
	equalJSON(t, b, payload)
	var rule SkillSecurityRuleResponse
	if err := json.Unmarshal([]byte(`{"default_state":"FUTURE_STATE"}`), &rule); err != nil {
		t.Fatal(err)
	}
	if rule.DefaultState != RuleState("FUTURE_STATE") {
		t.Error("open enum lost")
	}
	receipt, err := json.Marshal(InstanceResponseModel{TenantID: "tenant", IsSuccess: false})
	if err != nil {
		t.Fatal(err)
	}
	equalJSON(t, receipt, []byte(`{"tenant_id":"tenant","is_success":false}`))
}

func equalJSON(t *testing.T, got, want []byte) {
	t.Helper()
	var a, b any
	if err := json.Unmarshal(got, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want, &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("JSON %s want %s", got, want)
	}
}
