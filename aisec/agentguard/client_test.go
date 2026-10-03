package agentguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/agentguard/schema"
)

const testUUID = "12345678-1234-1234-1234-123456789abc"
const chainUUID = "87654321-4321-4321-4321-cba987654321"

func testClient(t *testing.T, handler http.HandlerFunc) (*Client, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	token := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" {
			t.Errorf("token method %s", r.Method)
		}
		if r.Header.Get(aisec.HeaderTsgID) != "" {
			t.Error("tenant header leaked to token endpoint")
		}
		id, secret, ok := r.BasicAuth()
		if !ok || id != "id" || secret != "secret" {
			t.Error("bad token credentials")
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("scope") != "tsg_id:tsg" {
			t.Error("bad OAuth form")
		}
		_, _ = io.WriteString(w, `{"access_token":"token","expires_in":3600,"token_type":"Bearer"}`)
	}))
	t.Cleanup(token.Close)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Error("missing bearer token")
		}
		if r.Header.Get(aisec.HeaderTsgID) != "tsg" {
			t.Error("missing AgentGuard tenant header")
		}
		if r.Header.Get("User-Agent") != aisec.UserAgent {
			t.Error("missing SDK user agent")
		}
		handler(w, r)
	}))
	t.Cleanup(api.Close)
	c, err := NewClient(Opts{ClientID: "id", ClientSecret: "secret", TsgID: "tsg", TokenEndpoint: token.URL, DataEndpoint: api.URL + "/data", MgmtEndpoint: api.URL + "/mgmt", HTTPClient: api.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return c, calls
}

func TestOperationsMatchPinnedContracts(t *testing.T) {
	fingerprint := strings.Repeat("a", 64)
	instance := schema.InstanceCreateModel{TSGID: "tsg", TenantID: "tenant/a?b#c", CreatedBy: "user", SupportAccountID: "support", IamControlled: aisec.Value(false), AuthCode: aisec.Null[string]()}
	complete := schema.AgentGuardUploadCompleteRequest{Name: "skill", GitURL: aisec.Null[string](), ChecksumCrc32c: aisec.Value("yZRlqg==")}
	rules := schema.SkillSecurityRuleInstancesUpdateRequest{RuleConfigurations: map[string]schema.SkillSecurityRuleConfiguration{testUUID: {State: schema.RuleStateDisabled}}}
	override := schema.SkillOverrideCreateRequest{SkillName: "skill", Fingerprint: fingerprint, Decision: schema.OverrideDecisionAllow, TrustedBy: "user@example.com", Reason: aisec.Null[string]()}
	var nilQuery = url.Values{}
	tests := []struct {
		plane, verb, path, wirePath string
		query                       url.Values
		body                        string
		call                        func(*Client) (any, error)
	}{
		{"data", "GET", "/v1/scans", "/v1/scans", nilQuery, "", func(c *Client) (any, error) { return c.Scans.List(context.Background(), ScanListOpts{}) }},
		{"data", "GET", "/v1/scans/csv", "/v1/scans/csv", url.Values{"statuses": {"COMPLETED", "FAILED"}}, "", func(c *Client) (any, error) {
			return c.Scans.ExportCSV(context.Background(), ScanFilter{Statuses: []schema.AgentGuardScanStatus{schema.AgentGuardScanStatusCompleted, schema.AgentGuardScanStatusFailed}})
		}},
		{"data", "GET", "/v1/scans/lookup", "/v1/scans/lookup", url.Values{"fingerprint": {fingerprint}}, "", func(c *Client) (any, error) { return c.Scans.Lookup(context.Background(), fingerprint) }},
		{"data", "POST", "/v1/scans/upload-url", "/v1/scans/upload-url", nilQuery, "", func(c *Client) (any, error) { return c.Scans.UploadURL(context.Background()) }},
		{"data", "GET", "/v1/scans/{scan_uuid}", "/v1/scans/" + testUUID, nilQuery, "", func(c *Client) (any, error) { return c.Scans.Get(context.Background(), testUUID) }},
		{"data", "GET", "/v1/scans/{scan_uuid}/attack-chains", "/v1/scans/" + testUUID + "/attack-chains", url.Values{"limit": {"501"}, "skip": {"0"}}, "", func(c *Client) (any, error) {
			return c.Scans.ListAttackChains(context.Background(), testUUID, ListOpts{Limit: 501})
		}},
		{"data", "GET", "/v1/scans/{scan_uuid}/attack-chains/{chain_uuid}", "/v1/scans/" + testUUID + "/attack-chains/" + chainUUID, nilQuery, "", func(c *Client) (any, error) { return c.Scans.GetAttackChain(context.Background(), testUUID, chainUUID) }},
		{"data", "POST", "/v1/scans/{scan_uuid}/upload-complete", "/v1/scans/" + testUUID + "/upload-complete", url.Values{"artifact_type": {"SKILL"}}, `{"name":"skill","git_url":null,"checksum_crc32c":"yZRlqg=="}`, func(c *Client) (any, error) {
			return c.Scans.UploadComplete(context.Background(), testUUID, complete, UploadCompleteOpts{ArtifactType: schema.ArtifactType("SKILL")})
		}},
		{"data", "GET", "/v1/scans/{scan_uuid}/vulnerabilities", "/v1/scans/" + testUUID + "/vulnerabilities", url.Values{"limit": {"500"}, "skip": {"2"}, "type": {"PROMPT_INJECTION"}, "in_chain": {"false"}}, "", func(c *Client) (any, error) {
			f := false
			return c.Scans.ListVulnerabilities(context.Background(), testUUID, VulnerabilityListOpts{ListOpts: ListOpts{Limit: 500, Skip: 2}, Type: schema.VulnerabilityTypePromptInjection, InChain: &f})
		}},
		{"data", "GET", "/v1/stats/rules", "/v1/stats/rules", url.Values{"time_period": {"7_DAYS"}}, "", func(c *Client) (any, error) {
			return c.Statistics.Rules(context.Background(), schema.TimePeriodValue7Days)
		}},
		{"data", "GET", "/v1/stats/scans", "/v1/stats/scans", nilQuery, "", func(c *Client) (any, error) { return c.Statistics.Scans(context.Background(), "") }},
		{"mgmt", "POST", "/v1/instances", "/v1/instances", nilQuery, `{"tsg_id":"tsg","tenant_id":"tenant/a?b#c","created_by":"user","support_account_id":"support","iam_controlled":false,"auth_code":null}`, func(c *Client) (any, error) { return c.Instances.Create(context.Background(), instance) }},
		{"mgmt", "GET", "/v1/instances/{tenant_id}", "/v1/instances/tenant%2Fa%3Fb%23c", nilQuery, "", func(c *Client) (any, error) { return c.Instances.Get(context.Background(), instance.TenantID) }},
		{"mgmt", "PUT", "/v1/instances/{tenant_id}", "/v1/instances/tenant%2Fa%3Fb%23c", nilQuery, `{"tsg_id":"tsg","tenant_id":"tenant/a?b#c","created_by":"user","support_account_id":"support","iam_controlled":false,"auth_code":null}`, func(c *Client) (any, error) {
			return c.Instances.Update(context.Background(), instance.TenantID, instance)
		}},
		{"mgmt", "DELETE", "/v1/instances/{tenant_id}", "/v1/instances/tenant%2Fa%3Fb%23c", nilQuery, "", func(c *Client) (any, error) { return c.Instances.Delete(context.Background(), instance.TenantID) }},
		{"mgmt", "GET", "/v1/rules", "/v1/rules", url.Values{"limit": {"10"}, "skip": {"0"}}, "", func(c *Client) (any, error) { return c.Rules.List(context.Background(), ListOpts{Limit: 10}) }},
		{"mgmt", "GET", "/v1/rule-instances", "/v1/rule-instances", nilQuery, "", func(c *Client) (any, error) { return c.RuleInstances.List(context.Background(), ListOpts{}) }},
		{"mgmt", "PUT", "/v1/rule-instances", "/v1/rule-instances", nilQuery, `{"rule_configurations":{"12345678-1234-1234-1234-123456789abc":{"state":"DISABLED"}}}`, func(c *Client) (any, error) { return c.RuleInstances.Update(context.Background(), rules) }},
		{"mgmt", "GET", "/v1/skill-overrides", "/v1/skill-overrides", url.Values{"limit": {"50"}, "skip": {"3"}, "skill_name": {"name"}, "fingerprint": {fingerprint}, "trusted_by": {"user"}, "q": {"abc"}}, "", func(c *Client) (any, error) {
			return c.SkillOverrides.List(context.Background(), SkillOverrideListOpts{ListOpts: ListOpts{Limit: 50, Skip: 3}, SkillName: "name", Fingerprint: fingerprint, TrustedBy: "user", Q: "abc"})
		}},
		{"mgmt", "POST", "/v1/skill-overrides", "/v1/skill-overrides", nilQuery, `{"skill_name":"skill","fingerprint":"` + fingerprint + `","decision":"ALLOW","trusted_by":"user@example.com","reason":null}`, func(c *Client) (any, error) { return c.SkillOverrides.Create(context.Background(), override) }},
		{"mgmt", "DELETE", "/v1/skill-overrides/{override_uuid}", "/v1/skill-overrides/" + testUUID, nilQuery, "", func(c *Client) (any, error) { return nil, c.SkillOverrides.Delete(context.Background(), testUUID) }},
	}
	contracts := map[string]map[string]any{}
	count := 0
	for _, plane := range []string{"data", "mgmt"} {
		b, err := os.ReadFile("../../specs/contracts/agentguard-" + plane + ".json")
		if err != nil {
			t.Fatal(err)
		}
		var spec map[string]any
		if err := json.Unmarshal(b, &spec); err != nil {
			t.Fatal(err)
		}
		contracts[plane] = spec
		for _, path := range spec["paths"].(map[string]any) {
			count += len(path.(map[string]any))
		}
	}
	if len(tests) != count {
		t.Fatalf("covered %d of %d operations", len(tests), count)
	}
	seen := map[string]bool{}
	for _, tc := range tests {
		t.Run(tc.plane+" "+tc.verb+" "+tc.path, func(t *testing.T) {
			key := tc.plane + tc.verb + tc.path
			if seen[key] {
				t.Fatal("duplicate operation")
			}
			seen[key] = true
			op := contracts[tc.plane]["paths"].(map[string]any)[tc.path].(map[string]any)[strings.ToLower(tc.verb)].(map[string]any)
			status := 200
			if tc.verb == "POST" && tc.path != "/v1/scans/upload-url" {
				status = 201
			}
			if tc.verb == "DELETE" && tc.plane == "mgmt" && strings.Contains(tc.path, "skill-overrides") {
				status = 204
			}
			if _, ok := op["responses"].(map[string]any)[httpStatus(status)]; !ok {
				t.Fatalf("unexpected status %d", status)
			}
			var payload []byte
			if status != 204 && !strings.HasSuffix(tc.path, "/csv") {
				response := op["responses"].(map[string]any)[httpStatus(status)].(map[string]any)
				shape := response["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
				var err error
				payload, err = json.Marshal(contractFixture(shape, contracts[tc.plane]))
				if err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != tc.verb || r.URL.EscapedPath() != "/"+tc.plane+tc.wirePath {
					t.Errorf("request %s %s", r.Method, r.URL.EscapedPath())
				}
				if !reflect.DeepEqual(r.URL.Query(), tc.query) {
					t.Errorf("query %v want %v", r.URL.Query(), tc.query)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				if tc.body == "" {
					if len(body) != 0 {
						t.Errorf("unexpected body %s", body)
					}
				} else {
					assertJSONEqual(t, body, []byte(tc.body))
				}
				w.WriteHeader(status)
				if status != 204 {
					if strings.HasSuffix(tc.path, "/csv") {
						_, _ = w.Write([]byte{0x1f, 0x8b, 0x08})
					} else {
						_, _ = w.Write(payload)
					}
				}
			})
			result, err := tc.call(c)
			if err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Errorf("API calls %d", calls)
			}
			if strings.HasSuffix(tc.path, "/csv") {
				if !bytes.Equal(result.(*CSVExport).Body, []byte{0x1f, 0x8b, 0x08}) {
					t.Error("CSV bytes changed")
				}
			} else if status != 204 {
				encoded, err := json.Marshal(result)
				if err != nil {
					t.Fatal(err)
				}
				assertJSONEqual(t, encoded, payload)
			}
		})
	}
}

func httpStatus(status int) string {
	switch status {
	case 201:
		return "201"
	case 204:
		return "204"
	default:
		return "200"
	}
}
func assertJSONEqual(t *testing.T, got, want []byte) {
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

func TestScanFilters(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		want := url.Values{"limit": {"100"}, "skip": {"7"}, "sort_order": {"asc"}, "search_query": {"a & b"}, "status": {"COMPLETED"}, "artifact_type": {"SKILL"}, "statuses": {"COMPLETED", "FAILED"}, "artifact_types": {"SKILL", "AGENT"}, "start_time": {"2026-08-01T00:00:00Z"}, "end_time": {"2026-09-01T00:00:00Z"}, "fingerprint": {"exact"}}
		if !reflect.DeepEqual(r.URL.Query(), want) {
			t.Errorf("query %v", r.URL.Query())
		}
		_, _ = io.WriteString(w, `{"scans":[],"pagination":{"total_items":0}}`)
	})
	_, err := c.Scans.List(context.Background(), ScanListOpts{ListOpts: ListOpts{Limit: 100, Skip: 7}, ScanFilter: ScanFilter{SortOrder: schema.SortDirectionAsc, SearchQuery: "a & b", Status: schema.AgentGuardScanStatusCompleted, ArtifactType: "SKILL", Statuses: []schema.AgentGuardScanStatus{"COMPLETED", "FAILED"}, ArtifactTypes: []schema.ArtifactType{"SKILL", "AGENT"}, StartTime: "2026-08-01T00:00:00Z", EndTime: "2026-09-01T00:00:00Z", Fingerprint: "exact"}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestErrorsAndBoundedAuthRefresh(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 409, 429, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			c, tokens := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.WriteHeader(status)
				_, _ = io.WriteString(w, `{"message":"failure"}`)
			})
			_, err := c.Scans.Get(context.Background(), testUUID)
			var sdkErr *aisec.AISecSDKError
			if !errors.As(err, &sdkErr) || sdkErr.StatusCode != status {
				t.Fatalf("error %v", err)
			}
			want := 1
			if status == 401 || status == 403 {
				want = 2
			}
			if calls != want || int(tokens.Load()) != want {
				t.Errorf("API calls=%d tokens=%d want=%d", calls, tokens.Load(), want)
			}
			if status == 404 && !errors.Is(err, aisec.ErrNotFound) {
				t.Error("missing not-found sentinel")
			}
		})
	}
}

func TestMalformedSuccessAndCancellation(t *testing.T) {
	c, tokens := testClient(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{"scans":`) })
	resp, err := c.Scans.List(context.Background(), ScanListOpts{})
	var sdkErr *aisec.AISecSDKError
	if resp != nil || !errors.As(err, &sdkErr) || sdkErr.StatusCode != 200 {
		t.Fatalf("response %v error %v", resp, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = c.Scans.Get(ctx, testUUID)
	if err == nil || tokens.Load() != 1 {
		t.Fatalf("cancel error %v tokens %d", err, tokens.Load())
	}
}
