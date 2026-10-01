package schema_test

import (
	"encoding/json"
	"testing"

	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/modelsecurity/schema"
)

func TestGroupUpdateDistinguishesOmittedNullAndEmpty(t *testing.T) {
	cases := []struct {
		name string
		req  schema.ModelSecurityGroupUpdateRequest
		want string
	}{
		{"omitted", schema.ModelSecurityGroupUpdateRequest{}, `{}`},
		{"clear", schema.ModelSecurityGroupUpdateRequest{Description: aisec.Value("")}, `{"description":""}`},
		{"null", schema.ModelSecurityGroupUpdateRequest{Description: aisec.Null[string]()}, `{"description":null}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.req)
			if err != nil {
				t.Fatal(err)
			}
			if string(b) != tc.want {
				t.Fatalf("body=%s; want %s", b, tc.want)
			}
			var decoded schema.ModelSecurityGroupUpdateRequest
			if err := json.Unmarshal(b, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.Description.IsSet() != tc.req.Description.IsSet() || decoded.Description.IsNull() != tc.req.Description.IsNull() {
				t.Error("presence/null information lost")
			}
		})
	}
}

func TestHistoricalRuleInstancePreservesNullAndZero(t *testing.T) {
	var response schema.ModelSecurityRuleInstanceResponse
	if err := json.Unmarshal([]byte(`{"uuid":"r","security_group_uuid":"g","tsg_id":"t","state":"FUTURE_STATE","security_rule_uuid":null,"custom_rule_uuid":"c","created_at":null,"field_values":{"limit":0}}`), &response); err != nil {
		t.Fatal(err)
	}
	if !response.SecurityRuleUUID.IsNull() || !response.CreatedAt.IsNull() {
		t.Error("historical nulls lost")
	}
	if response.UpdatedAt.IsSet() {
		t.Error("missing timestamp became a value")
	}
	if id, ok := response.CustomRuleUUID.Get(); !ok || id != "c" {
		t.Error("custom rule reference lost")
	}
	if string(response.State) != "FUTURE_STATE" {
		t.Error("open string enum rejected future value")
	}
}

func TestCustomRuleConditionRetainsTypedRecursiveTree(t *testing.T) {
	leaf, err := schema.NewConditionGroupInputConditionsItemFromLabelCondition(schema.LabelCondition{Type: "label", Key: "stage", Operator: "equals", Value: aisec.Value("prod")})
	if err != nil {
		t.Fatal(err)
	}
	tree := schema.ConditionGroupInput{Operator: "and", Conditions: []schema.ConditionGroupInputConditionsItem{leaf, leaf}}
	condition, err := schema.NewCustomRuleCreateRequestConditionFromConditionGroupInput(tree)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(condition)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"conditions":[{"key":"stage","operator":"equals","type":"label","value":"prod"},{"key":"stage","operator":"equals","type":"label","value":"prod"}],"operator":"and"}`
	if string(b) != want {
		t.Fatalf("condition=%s; want %s", b, want)
	}
	decoded, err := condition.AsConditionGroupInput()
	if err != nil || len(decoded.Conditions) != 2 {
		t.Fatalf("tree=%+v error=%v", decoded, err)
	}
	label, err := decoded.Conditions[0].AsLabelCondition()
	if err != nil || label.Key != "stage" {
		t.Fatalf("leaf=%+v error=%v", label, err)
	}
}

func TestCustomRuleUnionRejectsWrongAlternative(t *testing.T) {
	leaf, err := schema.NewCustomRuleCreateRequestConditionFromLabelCondition(schema.LabelCondition{Type: "label", Key: "stage", Operator: "exists"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.AsConditionGroupInput(); err == nil {
		t.Fatal("label condition was silently decoded as an empty group")
	}
	for _, body := range []string{`"not a condition"`, `null`, `{"type":"rule_result","key":"stage","operator":"equals"}`} {
		var condition schema.CustomRuleCreateRequestCondition
		if err := json.Unmarshal([]byte(body), &condition); err == nil {
			t.Errorf("invalid union accepted: %s", body)
		}
	}
}
