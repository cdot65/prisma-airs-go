package modelsecurity

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/modelsecurity/schema"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
)

func modelContractResult[T any](value T, err error) (any, error) { return value, err }

type modelContractFixture struct {
	Query    string                     `json:"query"`
	Request  json.RawMessage            `json:"request"`
	Response json.RawMessage            `json:"response"`
	Fields   map[string]json.RawMessage `json:"fields"`
	Status   int                        `json:"status"`
}

func fixtureRequest[T any](t *testing.T, body []byte) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatal(err)
	}
	return value
}
func modelJSONEqual(t *testing.T, got, want []byte) {
	t.Helper()
	var actual, expected any
	if err := json.Unmarshal(got, &actual); err != nil {
		t.Fatalf("actual JSON %q: %v", got, err)
	}
	if err := json.Unmarshal(want, &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("JSON=%s; want %s", got, want)
	}
}
func TestModelSecurity_AllPinnedOperations(t *testing.T) {
	ctx := context.Background()
	const id = "550e8400-e29b-41d4-a716-446655440000"
	inactive := false
	zero := int64(0)
	var fixtures map[string]modelContractFixture
	raw, err := os.ReadFile("testdata/contracts.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, plane, method, template, path string
		call                                func(*Client, modelContractFixture) (any, error)
	}{
		{"POST /v1/scans", "data", "POST", "/v1/scans", "/v1/scans", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.Scans.Create(ctx, fixtureRequest[ScanCreateRequest](t, fixture.Request)))
		}},
		{"GET /v1/scans", "data", "GET", "/v1/scans", "/v1/scans", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.Scans.List(ctx, ScanListOpts{Limit: 5, Skip: 2, ModelVersionUUID: id, SourceTypes: []string{"LOCAL", "S3"}, EvalOutcomes: []string{"ALLOWED", "BLOCKED"}}))
		}},
		{"GET /v1/scans/{uuid}", "data", "GET", "/v1/scans/{uuid}", "/v1/scans/550e8400-e29b-41d4-a716-446655440000", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.Scans.Get(ctx, id))
		}},
		{"GET /v1/scans/{scan_uuid}/evaluations", "data", "GET", "/v1/scans/{scan_uuid}/evaluations", "/v1/scans/550e8400-e29b-41d4-a716-446655440000/evaluations", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.Scans.GetEvaluations(ctx, id, EvaluationListOpts{Limit: 5, Skip: 2, Result: "PASSED"}))
		}},
		{"GET /v1/evaluations/{uuid}", "data", "GET", "/v1/evaluations/{uuid}", "/v1/evaluations/550e8400-e29b-41d4-a716-446655440000", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.Scans.GetEvaluation(ctx, id))
		}},
		{"GET /v1/scans/{scan_uuid}/files", "data", "GET", "/v1/scans/{scan_uuid}/files", "/v1/scans/550e8400-e29b-41d4-a716-446655440000/files", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.Scans.GetFiles(ctx, id, FileListOpts{Limit: 5, Skip: 2, QueryPath: "/nested", Recursive: &inactive}))
		}},
		{"GET /v1/scans/{scan_uuid}/rule-violations", "data", "GET", "/v1/scans/{scan_uuid}/rule-violations", "/v1/scans/550e8400-e29b-41d4-a716-446655440000/rule-violations", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.Scans.GetViolations(ctx, id, ViolationListOpts{Limit: 5, Skip: 2}))
		}},
		{"GET /v1/violations/{uuid}", "data", "GET", "/v1/violations/{uuid}", "/v1/violations/550e8400-e29b-41d4-a716-446655440000", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.Scans.GetViolation(ctx, id))
		}},
		{"POST /v1/scans/{scan_uuid}/labels", "data", "POST", "/v1/scans/{scan_uuid}/labels", "/v1/scans/550e8400-e29b-41d4-a716-446655440000/labels", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.Scans.AddLabels(ctx, id, fixtureRequest[LabelsCreateRequest](t, fixture.Request)))
		}},
		{"PUT /v1/scans/{scan_uuid}/labels", "data", "PUT", "/v1/scans/{scan_uuid}/labels", "/v1/scans/550e8400-e29b-41d4-a716-446655440000/labels", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.Scans.SetLabels(ctx, id, fixtureRequest[LabelsCreateRequest](t, fixture.Request)))
		}},
		{"DELETE /v1/scans/{scan_uuid}/labels", "data", "DELETE", "/v1/scans/{scan_uuid}/labels", "/v1/scans/550e8400-e29b-41d4-a716-446655440000/labels", func(c *Client, fixture modelContractFixture) (any, error) {
			return nil, c.Scans.DeleteLabels(ctx, id, []string{"one", "two"})
		}},
		{"GET /v1/scans/label-keys", "data", "GET", "/v1/scans/label-keys", "/v1/scans/label-keys", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.Scans.GetLabelKeys(ctx, LabelListOpts{Limit: 5, Skip: 2, Search: "test"}))
		}},
		{"GET /v1/scans/label-keys/{key}/values", "data", "GET", "/v1/scans/label-keys/{key}/values", "/v1/scans/label-keys/label%2Fpart/values", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.Scans.GetLabelValues(ctx, "label/part", LabelListOpts{Limit: 5}))
		}},
		{"GET /v1/models", "data", "GET", "/v1/models", "/v1/models", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.Models.List(ctx, ModelListOpts{Limit: 5, Skip: 2, SearchQuery: "test", SortField: "updated_at", SortOrder: "asc", LatestVersionOutcomes: []string{"ALLOWED", "BLOCKED"}, LatestVersionFormats: []string{"onnx", "gguf"}, LatestVersionSourceTypes: []string{"LOCAL", "S3"}, LatestVersionScanTimeBefore: "before", StartTime: "start", EndTime: "end"}))
		}},
		{"GET /v1/models/{uuid}", "data", "GET", "/v1/models/{uuid}", "/v1/models/550e8400-e29b-41d4-a716-446655440000", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.Models.Get(ctx, id))
		}},
		{"GET /v1/models/{uuid}/model-versions", "data", "GET", "/v1/models/{uuid}/model-versions", "/v1/models/550e8400-e29b-41d4-a716-446655440000/model-versions", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.Models.ListVersions(ctx, id, ModelVersionListOpts{Limit: 5, Skip: 2, SortOrder: "asc"}))
		}},
		{"GET /v1/model-versions/{uuid}", "data", "GET", "/v1/model-versions/{uuid}", "/v1/model-versions/550e8400-e29b-41d4-a716-446655440000", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.ModelVersions.Get(ctx, id))
		}},
		{"GET /v1/model-versions/{uuid}/files", "data", "GET", "/v1/model-versions/{uuid}/files", "/v1/model-versions/550e8400-e29b-41d4-a716-446655440000/files", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.ModelVersions.ListFiles(ctx, id, PageOpts{Limit: 5, Skip: 2}))
		}},
		{"GET /v1/pypi/authenticate", "mgmt", "GET", "/v1/pypi/authenticate", "/v1/pypi/authenticate", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.GetPyPIAuth(ctx))
		}},
		{"POST /v1/security-groups", "mgmt", "POST", "/v1/security-groups", "/v1/security-groups", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.SecurityGroups.Create(ctx, fixtureRequest[ModelSecurityGroupCreateRequest](t, fixture.Request)))
		}},
		{"GET /v1/security-groups", "mgmt", "GET", "/v1/security-groups", "/v1/security-groups", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.SecurityGroups.List(ctx, GroupListOpts{Limit: 5, Skip: 2, SourceTypes: []string{"LOCAL", "S3"}, EnabledRules: []string{id, "other"}}))
		}},
		{"GET /v1/security-groups/{uuid}", "mgmt", "GET", "/v1/security-groups/{uuid}", "/v1/security-groups/550e8400-e29b-41d4-a716-446655440000", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.SecurityGroups.Get(ctx, id))
		}},
		{"PUT /v1/security-groups/{uuid}", "mgmt", "PUT", "/v1/security-groups/{uuid}", "/v1/security-groups/550e8400-e29b-41d4-a716-446655440000", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.SecurityGroups.Update(ctx, id, fixtureRequest[ModelSecurityGroupUpdateRequest](t, fixture.Request)))
		}},
		{"DELETE /v1/security-groups/{uuid}", "mgmt", "DELETE", "/v1/security-groups/{uuid}", "/v1/security-groups/550e8400-e29b-41d4-a716-446655440000", func(c *Client, fixture modelContractFixture) (any, error) {
			return nil, c.SecurityGroups.Delete(ctx, id)
		}},
		{"GET /v1/security-groups/{security_group_uuid}/rule-instances", "mgmt", "GET", "/v1/security-groups/{security_group_uuid}/rule-instances", "/v1/security-groups/550e8400-e29b-41d4-a716-446655440000/rule-instances", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.SecurityGroups.ListRuleInstances(ctx, id, RuleInstanceListOpts{Limit: 5, Skip: 2, IsCustom: &inactive, Generation: &zero}))
		}},
		{"GET /v1/security-groups/{security_group_uuid}/rule-instances/{rule_instance_uuid}", "mgmt", "GET", "/v1/security-groups/{security_group_uuid}/rule-instances/{rule_instance_uuid}", "/v1/security-groups/550e8400-e29b-41d4-a716-446655440000/rule-instances/550e8400-e29b-41d4-a716-446655440000", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.SecurityGroups.GetRuleInstance(ctx, id, id))
		}},
		{"PUT /v1/security-groups/{security_group_uuid}/rule-instances/{rule_instance_uuid}", "mgmt", "PUT", "/v1/security-groups/{security_group_uuid}/rule-instances/{rule_instance_uuid}", "/v1/security-groups/550e8400-e29b-41d4-a716-446655440000/rule-instances/550e8400-e29b-41d4-a716-446655440000", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.SecurityGroups.UpdateRuleInstance(ctx, id, id, fixtureRequest[ModelSecurityRuleInstanceUpdateRequest](t, fixture.Request)))
		}},
		{"GET /v1/security-rules", "mgmt", "GET", "/v1/security-rules", "/v1/security-rules", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.SecurityRules.List(ctx, RuleListOpts{Limit: 5, Skip: 2, Generation: &zero}))
		}},
		{"GET /v1/security-rules/{uuid}", "mgmt", "GET", "/v1/security-rules/{uuid}", "/v1/security-rules/550e8400-e29b-41d4-a716-446655440000", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.SecurityRules.Get(ctx, id))
		}},
		{"POST /v1/custom-rules", "mgmt", "POST", "/v1/custom-rules", "/v1/custom-rules", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.CustomRules.Create(ctx, fixtureRequest[schema.CustomRuleCreateRequest](t, fixture.Request)))
		}},
		{"GET /v1/custom-rules", "mgmt", "GET", "/v1/custom-rules", "/v1/custom-rules", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.CustomRules.List(ctx, CustomRuleListOpts{Limit: 5, Skip: 2, IsArchived: &inactive, Generation: &zero, SourceTypes: []string{"LOCAL", "S3"}, SearchQuery: "test", SortField: "created_at", SortDir: "asc"}))
		}},
		{"GET /v1/custom-rules/{custom_rule_uuid}", "mgmt", "GET", "/v1/custom-rules/{custom_rule_uuid}", "/v1/custom-rules/550e8400-e29b-41d4-a716-446655440000", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.CustomRules.Get(ctx, id))
		}},
		{"PUT /v1/custom-rules/{custom_rule_uuid}", "mgmt", "PUT", "/v1/custom-rules/{custom_rule_uuid}", "/v1/custom-rules/550e8400-e29b-41d4-a716-446655440000", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.CustomRules.Update(ctx, id, fixtureRequest[schema.CustomRuleUpdateRequest](t, fixture.Request)))
		}},
		{"POST /v1/custom-rules/{custom_rule_uuid}/archive", "mgmt", "POST", "/v1/custom-rules/{custom_rule_uuid}/archive", "/v1/custom-rules/550e8400-e29b-41d4-a716-446655440000/archive", func(c *Client, fixture modelContractFixture) (any, error) { return nil, c.CustomRules.Archive(ctx, id) }},
		{"POST /v1/custom-rules/{custom_rule_uuid}/unarchive", "mgmt", "POST", "/v1/custom-rules/{custom_rule_uuid}/unarchive", "/v1/custom-rules/550e8400-e29b-41d4-a716-446655440000/unarchive", func(c *Client, fixture modelContractFixture) (any, error) {
			return nil, c.CustomRules.Unarchive(ctx, id)
		}},
		{"GET /v1/custom-rules/{custom_rule_uuid}/security-groups", "mgmt", "GET", "/v1/custom-rules/{custom_rule_uuid}/security-groups", "/v1/custom-rules/550e8400-e29b-41d4-a716-446655440000/security-groups", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.CustomRules.ListSecurityGroups(ctx, id, PageOpts{Limit: 5, Skip: 2}))
		}},
		{"POST /v1/custom-rules/{custom_rule_uuid}/security-groups", "mgmt", "POST", "/v1/custom-rules/{custom_rule_uuid}/security-groups", "/v1/custom-rules/550e8400-e29b-41d4-a716-446655440000/security-groups", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.CustomRules.AssignSecurityGroups(ctx, id, fixtureRequest[schema.BatchAssignCustomRuleRequest](t, fixture.Request)))
		}},
		{"DELETE /v1/custom-rules/{custom_rule_uuid}/security-groups/{sg_uuid}", "mgmt", "DELETE", "/v1/custom-rules/{custom_rule_uuid}/security-groups/{sg_uuid}", "/v1/custom-rules/550e8400-e29b-41d4-a716-446655440000/security-groups/550e8400-e29b-41d4-a716-446655440000", func(c *Client, fixture modelContractFixture) (any, error) {
			return nil, c.CustomRules.RemoveAssignment(ctx, id, id)
		}},
		{"GET /v1/custom-rules/versions", "mgmt", "GET", "/v1/custom-rules/versions", "/v1/custom-rules/versions", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.CustomRules.ListVersions(ctx, SnapshotListOpts{Limit: 5, NextToken: "next"}))
		}},
		{"GET /v1/security-rules/versions", "mgmt", "GET", "/v1/security-rules/versions", "/v1/security-rules/versions", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.SecurityRules.ListVersions(ctx, SnapshotListOpts{Limit: 5, NextToken: "next"}))
		}},
		{"GET /v1/security-groups/{security_group_uuid}/rule-instances/versions", "mgmt", "GET", "/v1/security-groups/{security_group_uuid}/rule-instances/versions", "/v1/security-groups/550e8400-e29b-41d4-a716-446655440000/rule-instances/versions", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.SecurityGroups.ListRuleInstanceVersions(ctx, id, SnapshotListOpts{Limit: 5, NextToken: "next"}))
		}},
		{"CreateDetails", "data", "POST", "/v1/scans", "/v1/scans", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.Scans.CreateDetails(ctx, fixtureRequest[schema.ScanCreateRequest](t, fixture.Request)))
		}},
		{"GetDetails", "data", "GET", "/v1/scans/{uuid}", "/v1/scans/550e8400-e29b-41d4-a716-446655440000", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.Scans.GetDetails(ctx, id))
		}},
		{"ListDetails", "data", "GET", "/v1/scans", "/v1/scans", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.Scans.ListDetails(ctx, ScanListOpts{Limit: 5}))
		}},
		{"UpdateFields", "mgmt", "PUT", "/v1/security-groups/{uuid}", "/v1/security-groups/550e8400-e29b-41d4-a716-446655440000", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.SecurityGroups.UpdateFields(ctx, id, fixtureRequest[schema.ModelSecurityGroupUpdateRequest](t, fixture.Request)))
		}},
		{"GetRuleInstanceDetails", "mgmt", "GET", "/v1/security-groups/{security_group_uuid}/rule-instances/{rule_instance_uuid}", "/v1/security-groups/550e8400-e29b-41d4-a716-446655440000/rule-instances/550e8400-e29b-41d4-a716-446655440000", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.SecurityGroups.GetRuleInstanceDetails(ctx, id, id))
		}},
		{"ListRuleInstanceDetails", "mgmt", "GET", "/v1/security-groups/{security_group_uuid}/rule-instances", "/v1/security-groups/550e8400-e29b-41d4-a716-446655440000/rule-instances", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.SecurityGroups.ListRuleInstanceDetails(ctx, id, RuleInstanceListOpts{Limit: 5, Generation: &zero}))
		}},
		{"UpdateRuleInstanceFields", "mgmt", "PUT", "/v1/security-groups/{security_group_uuid}/rule-instances/{rule_instance_uuid}", "/v1/security-groups/550e8400-e29b-41d4-a716-446655440000/rule-instances/550e8400-e29b-41d4-a716-446655440000", func(c *Client, fixture modelContractFixture) (any, error) {
			return modelContractResult(c.SecurityGroups.UpdateRuleInstanceFields(ctx, id, id, fixtureRequest[schema.ModelSecurityRuleInstanceUpdateRequest](t, fixture.Request)))
		}},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture, ok := fixtures[tc.name]
			if !ok {
				t.Fatal("missing fixture")
			}
			seen[tc.plane+" "+tc.method+" "+tc.template] = true
			for _, mode := range []string{"success", "not_found", "malformed"} {
				t.Run(mode, func(t *testing.T) {
					token, unusedAPI := newTestServers(t, func(http.ResponseWriter, *http.Request) { t.Error("unexpected API") })
					t.Cleanup(token.Close)
					t.Cleanup(unusedAPI.Close)
					handler := func(plane string) http.HandlerFunc {
						return func(w http.ResponseWriter, r *http.Request) {
							if plane != tc.plane || r.Method != tc.method || r.URL.EscapedPath() != tc.path {
								t.Errorf("got %s %s %s;want %s %s %s", plane, r.Method, r.URL, tc.plane, tc.method, tc.path)
							}
							if r.Header.Get("Authorization") != "Bearer test-token" {
								t.Error("missing OAuth")
							}
							query, err := url.ParseQuery(fixture.Query)
							if err != nil {
								t.Error(err)
							}
							if !reflect.DeepEqual(query, r.URL.Query()) {
								t.Errorf("query=%v;want %v", r.URL.Query(), query)
							}
							body, err := io.ReadAll(r.Body)
							if err != nil {
								t.Error(err)
							}
							if len(fixture.Request) == 0 {
								if len(body) != 0 {
									t.Errorf("unexpected body: %s", body)
								}
							} else {
								modelJSONEqual(t, body, fixture.Request)
							}
							if mode == "not_found" {
								w.WriteHeader(404)
								_, _ = w.Write([]byte(`{"message":"missing"}`))
								return
							}
							if mode == "malformed" {
								w.WriteHeader(200)
								_, _ = w.Write([]byte(`{"broken":`))
								return
							}
							w.WriteHeader(fixture.Status)
							if fixture.Status != 204 {
								_, _ = w.Write(fixture.Response)
							}
						}
					}
					data := httptest.NewServer(handler("data"))
					t.Cleanup(data.Close)
					mgmt := httptest.NewServer(handler("mgmt"))
					t.Cleanup(mgmt.Close)
					result, err := tc.call(newTestClient(t, token.URL, data.URL, mgmt.URL), fixture)
					if mode == "success" {
						if err != nil {
							t.Fatal(err)
						}
						if fixture.Status == 204 {
							return
						}
						b, err := json.Marshal(result)
						if err != nil {
							t.Fatal(err)
						}
						var fields map[string]json.RawMessage
						if err := json.Unmarshal(b, &fields); err != nil {
							t.Fatal(err)
						}
						for key, want := range fixture.Fields {
							modelJSONEqual(t, fields[key], want)
						}
						return
					}
					if result != nil && !reflect.ValueOf(result).IsNil() {
						t.Fatalf("partial result: %#v", result)
					}
					var sdkErr *aisec.AISecSDKError
					if !errors.As(err, &sdkErr) {
						t.Fatalf("error=%v", err)
					}
					if mode == "not_found" {
						if sdkErr.StatusCode != 404 || !errors.Is(err, aisec.ErrNotFound) {
							t.Fatalf("HTTP error=%+v", sdkErr)
						}
					} else {
						var syntax *json.SyntaxError
						if sdkErr.StatusCode != 200 || !errors.As(err, &syntax) {
							t.Fatalf("decode error=%+v", sdkErr)
						}
					}
				})
			}
		})
	}
	for _, plane := range []string{"data", "mgmt"} {
		raw, err := os.ReadFile("../../specs/contracts/model-" + plane + ".json")
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Paths map[string]map[string]json.RawMessage `json:"paths"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		for path, item := range doc.Paths {
			for method := range item {
				switch method {
				case "get", "post", "put", "delete", "patch":
					if !seen[plane+" "+strings.ToUpper(method)+" "+path] {
						t.Errorf("uncovered %s %s %s", plane, method, path)
					}
				}
			}
		}
	}
}
