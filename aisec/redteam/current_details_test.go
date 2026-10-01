package redteam

import (
	"context"
	"encoding/json"
	"github.com/cdot65/prisma-airs-go/aisec/redteam/schema"
	"os"
	"testing"
)

func currentDetailsContractCases(t *testing.T) []extensionCase {
	ctx := context.Background()
	no := false
	return []extensionCase{
		{"ScansClient.CreateDetails", "data", "POST", "/v1/scan", "/v1/scan", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Scans.CreateDetails(ctx, extensionRequest[schema.JobCreateRequest](t, f.Request)))
		}},
		{"ScansClient.ListDetails", "data", "GET", "/v1/scan", "/v1/scan", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Scans.ListDetails(ctx, ScanListOpts{Skip: 2, Limit: 5, Search: "needle", Status: "COMPLETED", JobType: "STATIC", TargetID: "target"}))
		}},
		{"ScansClient.GetDetails", "data", "GET", "/v1/scan/{job_id}", "/v1/scan/id%2Fpart", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Scans.GetDetails(ctx, "id/part"))
		}},
		{"ScansClient.AbortDetails", "data", "POST", "/v1/scan/{job_id}/abort", "/v1/scan/id%2Fpart/abort", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Scans.AbortDetails(ctx, "id/part"))
		}},
		{"ScansClient.GetCategoriesDetails", "data", "GET", "/v1/categories", "/v1/categories", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Scans.GetCategoriesDetails(ctx))
		}},
		{"ReportsClient.GetStaticReportDetails", "data", "GET", "/v1/report/static/{job_id}/report", "/v1/report/static/id%2Fpart/report", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Reports.GetStaticReportDetails(ctx, "id/part"))
		}},
		{"ReportsClient.GetDynamicReportDetails", "data", "GET", "/v1/report/dynamic/{job_id}/report", "/v1/report/dynamic/id%2Fpart/report", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Reports.GetDynamicReportDetails(ctx, "id/part"))
		}},
		{"ReportsClient.GetStaticRemediationDetails", "data", "GET", "/v1/report/static/{job_id}/remediation", "/v1/report/static/id%2Fpart/remediation", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Reports.GetStaticRemediationDetails(ctx, "id/part"))
		}},
		{"ReportsClient.GetDynamicRemediationDetails", "data", "GET", "/v1/report/dynamic/{job_id}/remediation", "/v1/report/dynamic/id%2Fpart/remediation", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Reports.GetDynamicRemediationDetails(ctx, "id/part"))
		}},
		{"ReportsClient.GetStaticRuntimePolicyDetails", "data", "GET", "/v1/report/static/{job_id}/runtime-policy-config", "/v1/report/static/id%2Fpart/runtime-policy-config", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Reports.GetStaticRuntimePolicyDetails(ctx, "id/part"))
		}},
		{"ReportsClient.GetDynamicRuntimePolicyDetails", "data", "GET", "/v1/report/dynamic/{job_id}/runtime-policy-config", "/v1/report/dynamic/id%2Fpart/runtime-policy-config", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Reports.GetDynamicRuntimePolicyDetails(ctx, "id/part"))
		}},
		{"ReportsClient.ListAttacksDetails", "data", "GET", "/v1/report/static/{job_id}/list-attacks", "/v1/report/static/id%2Fpart/list-attacks", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Reports.ListAttacksDetails(ctx, "id/part", AttackListOpts{Skip: 2, Limit: 5, Search: "ignored", AttackStatus: "COMPLETED", Compliance: "OWASP", AttackModality: "TEXT", Threat: &no}))
		}},
		{"ReportsClient.GetAttackDetails", "data", "GET", "/v1/report/static/{job_id}/attack/{attack_id}", "/v1/report/static/id%2Fpart/attack/id%2Fpart", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Reports.GetAttackDetails(ctx, "id/part", "id/part"))
		}},
		{"ReportsClient.GetMultiTurnAttackDetails", "data", "GET", "/v1/report/static/{job_id}/attack-multi-turn/{attack_id}", "/v1/report/static/id%2Fpart/attack-multi-turn/id%2Fpart", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Reports.GetMultiTurnAttackDetails(ctx, "id/part", "id/part"))
		}},
		{"ReportsClient.ListGoalsDetails", "data", "GET", "/v1/report/dynamic/{job_id}/list-goals", "/v1/report/dynamic/id%2Fpart/list-goals", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Reports.ListGoalsDetails(ctx, "id/part", GoalListOpts{Skip: 2, Limit: 5, GoalCategory: "category", Count: &no}))
		}},
		{"ReportsClient.ListGoalStreamsDetails", "data", "GET", "/v1/report/dynamic/{job_id}/goal/{goal_id}/list-streams", "/v1/report/dynamic/id%2Fpart/goal/id%2Fpart/list-streams", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Reports.ListGoalStreamsDetails(ctx, "id/part", "id/part"))
		}},
		{"ReportsClient.GetStreamDetails", "data", "GET", "/v1/report/dynamic/stream/{stream_id}", "/v1/report/dynamic/stream/id%2Fpart", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Reports.GetStreamDetails(ctx, "id/part"))
		}},
		{"ReportsClient.GeneratePartialReportDetails", "data", "POST", "/v1/report/{job_id}/generate-partial-report", "/v1/report/id%2Fpart/generate-partial-report", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Reports.GeneratePartialReportDetails(ctx, "id/part"))
		}},
		{"CustomAttackReportsClient.GetReportDetails", "data", "GET", "/v1/custom-attacks/report/{job_id}", "/v1/custom-attacks/report/id%2Fpart", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttackReports.GetReportDetails(ctx, "id/part"))
		}},
		{"CustomAttackReportsClient.GetPromptSetsDetails", "data", "GET", "/v1/custom-attacks/report/{job_id}/prompt-sets", "/v1/custom-attacks/report/id%2Fpart/prompt-sets", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttackReports.GetPromptSetsDetails(ctx, "id/part", PromptSetsReportOpts{Skip: 2, Limit: 5, PropertyFilters: "severity:high", IsThreat: &no}))
		}},
		{"CustomAttackReportsClient.GetPromptsBySetDetails", "data", "GET", "/v1/custom-attacks/report/{job_id}/prompt-set/{prompt_set_id}/prompts", "/v1/custom-attacks/report/id%2Fpart/prompt-set/id%2Fpart/prompts", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttackReports.GetPromptsBySetDetails(ctx, "id/part", "id/part", PromptsBySetListOpts{Skip: 2, Limit: 5, Search: "ignored", IsThreat: &no}))
		}},
		{"CustomAttackReportsClient.GetPromptDetails", "data", "GET", "/v1/custom-attacks/report/{job_id}/prompt/{prompt_id}", "/v1/custom-attacks/report/id%2Fpart/prompt/id%2Fpart", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttackReports.GetPromptDetails(ctx, "id/part", "id/part"))
		}},
		{"CustomAttackReportsClient.ListCustomAttacksDetails", "data", "GET", "/v1/custom-attacks/job/{job_id}/list-custom-attacks", "/v1/custom-attacks/job/id%2Fpart/list-custom-attacks", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttackReports.ListCustomAttacksDetails(ctx, "id/part", CustomAttacksReportListOpts{Skip: 2, Limit: 5, Search: "ignored", Status: "COMPLETED", Threat: &no, PromptSetID: "set", PropertyValue: "high"}))
		}},
		{"CustomAttackReportsClient.GetAttackOutputsDetails", "data", "GET", "/v1/custom-attacks/job/{job_id}/attack/{attack_id}/list-outputs", "/v1/custom-attacks/job/id%2Fpart/attack/id%2Fpart/list-outputs", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttackReports.GetAttackOutputsDetails(ctx, "id/part", "id/part"))
		}},
		{"CustomAttackReportsClient.GetPropertyStatsDetails", "data", "GET", "/v1/custom-attacks/job/{job_id}/property-stats", "/v1/custom-attacks/job/id%2Fpart/property-stats", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttackReports.GetPropertyStatsDetails(ctx, "id/part"))
		}},
		{"Client.GetQuotaDetails", "data", "GET", "/v1/metering/quota", "/v1/metering/quota", false, func(c *Client, f extensionFixture) (any, error) { return extensionResult(c.GetQuotaDetails(ctx)) }},
		{"Client.GetErrorLogsDetails", "data", "GET", "/v1/error-log/job/{job_id}", "/v1/error-log/job/id%2Fpart", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.GetErrorLogsDetails(ctx, "id/part", ListOpts{Skip: 2, Limit: 5, Search: "ignored"}))
		}},
		{"Client.GetScanStatisticsDetails", "data", "GET", "/v1/dashboard/scan-statistics", "/v1/dashboard/scan-statistics", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.GetScanStatisticsDetails(ctx))
		}},
		{"Client.GetScoreTrendDetails", "data", "GET", "/v1/dashboard/score-trend", "/v1/dashboard/score-trend", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.GetScoreTrendDetails(ctx, "target", ScoreTrendOpts{StartDate: "2026-09-01", EndDate: "2026-10-01"}))
		}},
		{"Client.UpdateSentimentDetails", "data", "POST", "/v1/sentiment", "/v1/sentiment", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.UpdateSentimentDetails(ctx, extensionRequest[schema.SentimentRequest](t, f.Request)))
		}},
		{"Client.GetSentimentDetails", "data", "GET", "/v1/sentiment/{job_id}", "/v1/sentiment/id%2Fpart", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.GetSentimentDetails(ctx, "id/part"))
		}},
		{"Client.GetDashboardOverviewDetails", "mgmt", "GET", "/v1/dashboard/overview", "/v1/dashboard/overview", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.GetDashboardOverviewDetails(ctx))
		}},
		{"TargetsClient.CreateDetails", "mgmt", "POST", "/v1/target", "/v1/target", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Targets.CreateDetails(ctx, extensionRequest[schema.TargetCreateRequest](t, f.Request), false))
		}},
		{"TargetsClient.ListDetails", "mgmt", "GET", "/v1/target", "/v1/target", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Targets.ListDetails(ctx, TargetListOpts{Skip: 2, Limit: 5, Search: "needle", ProfilingStatus: "COMPLETED", AdapterUUID: "adapter"}))
		}},
		{"TargetsClient.GetDetails", "mgmt", "GET", "/v1/target/{target_uuid}", "/v1/target/id%2Fpart", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Targets.GetDetails(ctx, "id/part"))
		}},
		{"TargetsClient.UpdateDetails", "mgmt", "PUT", "/v1/target/{target_uuid}", "/v1/target/id%2Fpart", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Targets.UpdateDetails(ctx, "id/part", extensionRequest[schema.TargetUpdateRequest](t, f.Request), false))
		}},
		{"TargetsClient.ProbeDetails", "mgmt", "POST", "/v1/target/probe", "/v1/target/probe", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Targets.ProbeDetails(ctx, extensionRequest[schema.TargetProbeRequest](t, f.Request)))
		}},
		{"TargetsClient.GetProfileDetails", "mgmt", "GET", "/v1/target/{target_uuid}/profile", "/v1/target/id%2Fpart/profile", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Targets.GetProfileDetails(ctx, "id/part"))
		}},
		{"TargetsClient.UpdateProfileDetails", "mgmt", "PUT", "/v1/target/{target_uuid}/profile", "/v1/target/id%2Fpart/profile", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Targets.UpdateProfileDetails(ctx, "id/part", extensionRequest[schema.TargetContextUpdate](t, f.Request)))
		}},
		{"TargetsClient.ValidateAuthDetails", "mgmt", "POST", "/v1/target/validate-auth", "/v1/target/validate-auth", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Targets.ValidateAuthDetails(ctx, extensionRequest[schema.TargetAuthValidationRequest](t, f.Request)))
		}},
		{"CustomAttacksClient.CreatePromptSetDetails", "mgmt", "POST", "/v1/custom-attack/custom-prompt-set", "/v1/custom-attack/custom-prompt-set", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttacks.CreatePromptSetDetails(ctx, extensionRequest[schema.CustomPromptSetCreateRequest](t, f.Request)))
		}},
		{"CustomAttacksClient.ListPromptSetsDetails", "mgmt", "GET", "/v1/custom-attack/list-custom-prompt-sets", "/v1/custom-attack/list-custom-prompt-sets", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttacks.ListPromptSetsDetails(ctx, PromptSetListOpts{Skip: 2, Limit: 5, Language: "en", Active: &no, Archive: &no}))
		}},
		{"CustomAttacksClient.GetPromptSetDetails", "mgmt", "GET", "/v1/custom-attack/custom-prompt-set/{prompt_set_uuid}", "/v1/custom-attack/custom-prompt-set/id%2Fpart", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttacks.GetPromptSetDetails(ctx, "id/part"))
		}},
		{"CustomAttacksClient.UpdatePromptSetDetails", "mgmt", "PUT", "/v1/custom-attack/custom-prompt-set/{prompt_set_uuid}", "/v1/custom-attack/custom-prompt-set/id%2Fpart", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttacks.UpdatePromptSetDetails(ctx, "id/part", extensionRequest[schema.CustomPromptSetUpdateRequest](t, f.Request)))
		}},
		{"CustomAttacksClient.ArchivePromptSetDetails", "mgmt", "PUT", "/v1/custom-attack/custom-prompt-set/{prompt_set_uuid}/archive", "/v1/custom-attack/custom-prompt-set/id%2Fpart/archive", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttacks.ArchivePromptSetDetails(ctx, "id/part", extensionRequest[schema.CustomPromptSetArchiveRequest](t, f.Request)))
		}},
		{"CustomAttacksClient.GetPromptSetReferenceDetails", "mgmt", "GET", "/v1/custom-attack/custom-prompt-set/{prompt_set_uuid}/reference", "/v1/custom-attack/custom-prompt-set/id%2Fpart/reference", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttacks.GetPromptSetReferenceDetails(ctx, "id/part"))
		}},
		{"CustomAttacksClient.GetPromptSetVersionInfoDetails", "mgmt", "GET", "/v1/custom-attack/custom-prompt-set/{prompt_set_uuid}/version-info", "/v1/custom-attack/custom-prompt-set/id%2Fpart/version-info", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttacks.GetPromptSetVersionInfoDetails(ctx, "id/part", "v1"))
		}},
		{"CustomAttacksClient.ListActivePromptSetsDetails", "mgmt", "GET", "/v1/custom-attack/active-custom-prompt-sets", "/v1/custom-attack/active-custom-prompt-sets", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttacks.ListActivePromptSetsDetails(ctx))
		}},
		{"CustomAttacksClient.CreatePromptDetails", "mgmt", "POST", "/v1/custom-attack/custom-prompt-set/custom-prompt", "/v1/custom-attack/custom-prompt-set/custom-prompt", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttacks.CreatePromptDetails(ctx, extensionRequest[schema.CustomPromptCreateRequest](t, f.Request)))
		}},
		{"CustomAttacksClient.ListPromptsDetails", "mgmt", "GET", "/v1/custom-attack/custom-prompt-set/{prompt_set_uuid}/list-custom-prompts", "/v1/custom-attack/custom-prompt-set/id%2Fpart/list-custom-prompts", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttacks.ListPromptsDetails(ctx, "id/part", PromptListOpts{Skip: 2, Limit: 5, Status: "ACTIVE", Active: &no}))
		}},
		{"CustomAttacksClient.GetPromptDetails", "mgmt", "GET", "/v1/custom-attack/custom-prompt-set/{prompt_set_uuid}/custom-prompt/{prompt_uuid}", "/v1/custom-attack/custom-prompt-set/id%2Fpart/custom-prompt/id%2Fpart", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttacks.GetPromptDetails(ctx, "id/part", "id/part"))
		}},
		{"CustomAttacksClient.UpdatePromptDetails", "mgmt", "PUT", "/v1/custom-attack/custom-prompt-set/{prompt_set_uuid}/custom-prompt/{prompt_uuid}", "/v1/custom-attack/custom-prompt-set/id%2Fpart/custom-prompt/id%2Fpart", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttacks.UpdatePromptDetails(ctx, "id/part", "id/part", extensionRequest[schema.CustomPromptUpdateRequest](t, f.Request)))
		}},
		{"CustomAttacksClient.GetPropertyNamesDetails", "mgmt", "GET", "/v1/custom-attack/property-names", "/v1/custom-attack/property-names", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttacks.GetPropertyNamesDetails(ctx))
		}},
		{"CustomAttacksClient.CreatePropertyNameDetails", "mgmt", "POST", "/v1/custom-attack/property-names", "/v1/custom-attack/property-names", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttacks.CreatePropertyNameDetails(ctx, extensionRequest[schema.PropertyNameCreateRequest](t, f.Request)))
		}},
		{"CustomAttacksClient.GetPropertyValuesDetails", "mgmt", "GET", "/v1/custom-attack/property-values/{property_name}", "/v1/custom-attack/property-values/id%2Fpart", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttacks.GetPropertyValuesDetails(ctx, "id/part"))
		}},
		{"CustomAttacksClient.GetPropertyValuesMultipleDetails", "mgmt", "GET", "/v1/custom-attack/property-values", "/v1/custom-attack/property-values", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttacks.GetPropertyValuesMultipleDetails(ctx, []string{"first", "second"}))
		}},
		{"CustomAttacksClient.CreatePropertyValueDetails", "mgmt", "POST", "/v1/custom-attack/property-values", "/v1/custom-attack/property-values", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttacks.CreatePropertyValueDetails(ctx, extensionRequest[schema.PropertyValueCreateRequest](t, f.Request)))
		}},
	}
}
func TestCurrentRedTeamDetails_Contracts(t *testing.T) {
	var fixtures map[string]extensionFixture
	b, err := os.ReadFile("testdata/details.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &fixtures); err != nil {
		t.Fatal(err)
	}
	cases := currentDetailsContractCases(t)
	runExtensionContracts(t, cases, fixtures)
}
