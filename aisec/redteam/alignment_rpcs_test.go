package redteam

import (
	"context"
	"encoding/json"

	"github.com/cdot65/prisma-airs-go/aisec/redteam/schema"

	"os"
	"strings"

	"testing"
)

func currentRPCContractCases(t *testing.T) []extensionCase {
	ctx := context.Background()
	return []extensionCase{
		{"ReportsClient.DownloadReport", "data", "GET", "/v1/report/{job_id}/download", "/v1/report/id%2Fpart/download", true, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Reports.DownloadReport(ctx, "id/part", FileFormatJSON))
		}},
		{"TargetsClient.Delete", "mgmt", "DELETE", "/v1/target/{target_uuid}", "/v1/target/id%2Fpart", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Targets.Delete(ctx, "id/part"))
		}},
		{"CustomAttacksClient.DeletePrompt", "mgmt", "DELETE", "/v1/custom-attack/custom-prompt-set/{prompt_set_uuid}/custom-prompt/{prompt_uuid}", "/v1/custom-attack/custom-prompt-set/id%2Fpart/custom-prompt/id%2Fpart", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttacks.DeletePrompt(ctx, "id/part", "id/part"))
		}},
		{"CustomAttacksClient.UploadPromptsCsv", "mgmt", "POST", "/v1/custom-attack/upload-custom-prompts-csv", "/v1/custom-attack/upload-custom-prompts-csv", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttacks.UploadPromptsCsv(ctx, "id/part", strings.NewReader("prompt\nhello\n"), "prompts.csv"))
		}},
		{"CustomAttacksClient.DownloadTemplate", "mgmt", "GET", "/v1/custom-attack/download-template/{prompt_set_uuid}", "/v1/custom-attack/download-template/id%2Fpart", true, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttacks.DownloadTemplate(ctx, "id/part"))
		}},

		{"Client.GetLanguages", "data", "GET", "/v1/languages", "/v1/languages", false, func(c *Client, f extensionFixture) (any, error) { return extensionResult(c.GetLanguages(ctx)) }},
		{"Client.GetGoalCategories", "data", "GET", "/v1/goal-categories/{target_type}", "/v1/goal-categories/id%2Fpart", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.GetGoalCategories(ctx, "id/part"))
		}},
		{"ScansClient.GetMetadata", "data", "GET", "/v1/scan/scan-metadata", "/v1/scan/scan-metadata", false, func(c *Client, f extensionFixture) (any, error) { return extensionResult(c.Scans.GetMetadata(ctx)) }},
		{"ScansClient.SetRuntimeProfile", "data", "PUT", "/v1/scan/{job_id}/runtime-profile", "/v1/scan/id%2Fpart/runtime-profile", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Scans.SetRuntimeProfile(ctx, "id/part", extensionRequest[schema.RuntimeProfileUpdateRequest](t, f.Request)))
		}},
		{"ReportsClient.GetStaticASR", "data", "GET", "/v1/report/static/{job_id}/asr", "/v1/report/static/id%2Fpart/asr", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Reports.GetStaticASR(ctx, "id/part"))
		}},
		{"ReportsClient.GetDynamicASR", "data", "GET", "/v1/report/dynamic/{job_id}/asr", "/v1/report/dynamic/id%2Fpart/asr", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Reports.GetDynamicASR(ctx, "id/part"))
		}},
		{"ReportsClient.GetStatus", "data", "GET", "/v1/report/{job_id}/status", "/v1/report/id%2Fpart/status", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Reports.GetStatus(ctx, "id/part"))
		}},
		{"ReportsClient.Regenerate", "data", "POST", "/v1/report/{job_id}/regenerate", "/v1/report/id%2Fpart/regenerate", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Reports.Regenerate(ctx, "id/part"))
		}},
		{"ReportsClient.GetDownload", "data", "GET", "/v2/report/{job_id}/download", "/v2/report/id%2Fpart/download", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Reports.GetDownload(ctx, "id/part", FileFormatJSON))
		}},
		{"ReportsClient.OverrideAttackThreat", "data", "POST", "/v1/report/static/{job_id}/attack/{attack_id}/override", "/v1/report/static/id%2Fpart/attack/id%2Fpart/override", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Reports.OverrideAttackThreat(ctx, "id/part", "id/part", extensionRequest[schema.ThreatOverrideRequest](t, f.Request)))
		}},
		{"ReportsClient.OverrideMultiTurnThreat", "data", "POST", "/v1/report/static/{job_id}/attack-multi-turn/{attack_id}/override", "/v1/report/static/id%2Fpart/attack-multi-turn/id%2Fpart/override", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Reports.OverrideMultiTurnThreat(ctx, "id/part", "id/part", extensionRequest[schema.ThreatOverrideRequest](t, f.Request)))
		}},
		{"ReportsClient.OverrideStreamThreat", "data", "POST", "/v1/report/dynamic/{job_id}/stream/{stream_id}/override", "/v1/report/dynamic/id%2Fpart/stream/id%2Fpart/override", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Reports.OverrideStreamThreat(ctx, "id/part", "id/part", extensionRequest[schema.ThreatOverrideRequest](t, f.Request)))
		}},
		{"CustomAttackReportsClient.OverrideThreat", "data", "POST", "/v1/custom-attacks/job/{job_id}/attack/{attack_id}/override", "/v1/custom-attacks/job/id%2Fpart/attack/id%2Fpart/override", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.CustomAttackReports.OverrideThreat(ctx, "id/part", "id/part", extensionRequest[schema.ThreatOverrideRequest](t, f.Request)))
		}},
		{"Client.DownloadErrorLogs", "data", "GET", "/v1/error-log/job/{job_id}/download", "/v1/error-log/job/id%2Fpart/download", true, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.DownloadErrorLogs(ctx, "id/part"))
		}},
		{"Client.GetTargetProfileErrorLogs", "data", "GET", "/v1/error-log/target-profile/{target_id}", "/v1/error-log/target-profile/id%2Fpart", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.GetTargetProfileErrorLogs(ctx, "id/part", 5))
		}},
		{"TargetsClient.GetLanguages", "mgmt", "GET", "/v1/languages", "/v1/languages", false, func(c *Client, f extensionFixture) (any, error) { return extensionResult(c.Targets.GetLanguages(ctx)) }},
		{"TargetsClient.StartProfiling", "mgmt", "POST", "/v1/target/{target_uuid}/profile", "/v1/target/id%2Fpart/profile", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Targets.StartProfiling(ctx, "id/part"))
		}},
		{"TargetsClient.GetCopilotAuthURL", "mgmt", "POST", "/v1/target/ms-copilot-studio/auth-url", "/v1/target/ms-copilot-studio/auth-url", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Targets.GetCopilotAuthURL(ctx, extensionRequest[schema.MSCopilotStudioAuthURLRequest](t, f.Request)))
		}},
		{"TargetsClient.ExchangeCopilotToken", "mgmt", "POST", "/v1/target/ms-copilot-studio/token", "/v1/target/ms-copilot-studio/token", false, func(c *Client, f extensionFixture) (any, error) {
			return extensionResult(c.Targets.ExchangeCopilotToken(ctx, extensionRequest[schema.MSCopilotStudioTokenRequest](t, f.Request)))
		}},
		{"TargetsClient.DeleteCopilotToken", "mgmt", "DELETE", "/v1/target/ms-copilot-studio/token/{token_json_uuid}", "/v1/target/ms-copilot-studio/token/id%2Fpart", false, func(c *Client, f extensionFixture) (any, error) {
			return nil, c.Targets.DeleteCopilotToken(ctx, "id/part")
		}},
	}
}
func TestCurrentRedTeamRPC_Contracts(t *testing.T) {
	var fixtures map[string]extensionFixture
	b, err := os.ReadFile("testdata/rpcs.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &fixtures); err != nil {
		t.Fatal(err)
	}
	cases := currentRPCContractCases(t)
	runExtensionContracts(t, cases, fixtures)
}
