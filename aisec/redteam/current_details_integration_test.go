//go:build integration

package redteam

import (
	"context"
	"fmt"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/redteam/schema"
	"testing"
	"time"
)

func TestIntegration_CurrentRedTeamDetails_Reads(t *testing.T) {
	c := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	check := func(name string, err error) {
		t.Helper()
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, err := c.GetQuotaDetails(ctx)
	check("quota", err)
	_, err = c.GetScanStatisticsDetails(ctx)
	check("statistics", err)
	_, err = c.GetDashboardOverviewDetails(ctx)
	check("overview", err)
	_, err = c.Scans.GetCategoriesDetails(ctx)
	check("categories", err)
	_, err = c.CustomAttacks.ListPromptSetsDetails(ctx, PromptSetListOpts{Limit: 5})
	check("prompt_sets", err)
	_, err = c.CustomAttacks.ListActivePromptSetsDetails(ctx)
	check("active_prompt_sets", err)
	_, err = c.CustomAttacks.GetPropertyNamesDetails(ctx)
	check("property_names", err)
	_, err = c.Targets.ListDetails(ctx, TargetListOpts{Limit: 5})
	check("targets", err)
	list, err := c.Scans.ListDetails(ctx, ScanListOpts{Limit: 30})
	if err != nil {
		t.Fatal(err)
	}
	if list.Data == nil {
		t.Fatal("jobs list omitted data")
	}
	seen := map[schema.JobType]bool{}
	for _, job := range list.Data {
		if seen[job.JobType] {
			continue
		}
		if job.Status == nil || (*job.Status != "COMPLETED" && *job.Status != "PARTIALLY_COMPLETE") {
			continue
		}
		seen[job.JobType] = true
		_, err = c.Scans.GetDetails(ctx, job.UUID)
		check("job", err)
		_, err = c.GetErrorLogsDetails(ctx, job.UUID, ListOpts{Limit: 2})
		check("error_logs", err)
		switch job.JobType {
		case "STATIC":
			_, err = c.Reports.GetStaticReportDetails(ctx, job.UUID)
			check("static_report", err)
			_, err = c.Reports.ListAttacksDetails(ctx, job.UUID, AttackListOpts{Limit: 2})
			check("static_attacks", err)
		case "DYNAMIC":
			_, err = c.Reports.GetDynamicReportDetails(ctx, job.UUID)
			check("dynamic_report", err)
			_, err = c.Reports.ListGoalsDetails(ctx, job.UUID, GoalListOpts{Limit: 2})
			check("dynamic_goals", err)
		case "CUSTOM":
			_, err = c.CustomAttackReports.GetReportDetails(ctx, job.UUID)
			check("custom_report", err)
			_, err = c.CustomAttackReports.GetPromptSetsDetails(ctx, job.UUID, PromptSetsReportOpts{Limit: 2})
			check("custom_prompt_sets", err)
		}
	}
}
func TestIntegration_CurrentRedTeamDetails_DisposableCRUD(t *testing.T) {
	c := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	name := fmt.Sprintf("sdk-contract-%d", time.Now().UnixNano())
	connection := schema.TargetCreateRequestConnectionParams(`{"url":"https://httpbin.org/post","headers":{"Content-Type":"application/json"},"request_json":{"prompt":"{INPUT}"},"response_json":{"output":"{RESPONSE}"},"response_key":"output"}`)
	created, err := c.Targets.CreateDetails(ctx, schema.TargetCreateRequest{Name: name, TargetType: aisec.Value(schema.TargetType("APPLICATION")), ConnectionType: aisec.Value(schema.TargetConnectionType("CUSTOM")), APIEndpointType: aisec.Value(schema.APIEndpointType("PUBLIC")), ResponseMode: aisec.Value(schema.ResponseMode("REST")), ConnectionParams: aisec.Value(connection)}, false)
	if err != nil {
		t.Fatal(err)
	}
	if created.UUID == "" {
		t.Fatal("target receipt omitted UUID")
	}
	t.Cleanup(func() {
		clean, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := c.Targets.Delete(clean, created.UUID); err != nil {
			t.Errorf("cleanup target: %v", err)
		}
	})
	if _, err := c.Targets.GetDetails(ctx, created.UUID); err != nil {
		t.Fatal(err)
	}
	updated, err := c.Targets.UpdateDetails(ctx, created.UUID, schema.TargetUpdateRequest{Name: name, Description: aisec.Value("updated"), TargetType: aisec.Value(schema.TargetType("APPLICATION")), ConnectionType: aisec.Value(schema.TargetConnectionType("CUSTOM")), APIEndpointType: aisec.Value(schema.APIEndpointType("PUBLIC")), ResponseMode: aisec.Value(schema.ResponseMode("REST")), ConnectionParams: aisec.Value(schema.TargetUpdateRequestConnectionParams(connection))}, false)
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := updated.Description.Get(); !ok || d != "updated" {
		t.Fatal("target description not retained")
	}
	set, err := c.CustomAttacks.CreatePromptSetDetails(ctx, schema.CustomPromptSetCreateRequest{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	if set.UUID == "" {
		t.Fatal("prompt set receipt omitted UUID")
	}
	t.Cleanup(func() {
		clean, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := c.CustomAttacks.ArchivePromptSetDetails(clean, set.UUID, schema.CustomPromptSetArchiveRequest{Archive: true}); err != nil {
			t.Errorf("cleanup prompt set: %v", err)
		}
	})
	if _, err := c.CustomAttacks.GetPromptSetDetails(ctx, set.UUID); err != nil {
		t.Fatal(err)
	}
	prompt, err := c.CustomAttacks.CreatePromptDetails(ctx, schema.CustomPromptCreateRequest{PromptSetID: set.UUID, Prompt: "Integration verification prompt"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		clean, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := c.CustomAttacks.DeletePrompt(clean, set.UUID, prompt.UUID); err != nil {
			t.Errorf("cleanup prompt: %v", err)
		}
	})
	if _, err := c.CustomAttacks.GetPromptDetails(ctx, set.UUID, prompt.UUID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CustomAttacks.ListPromptsDetails(ctx, set.UUID, PromptListOpts{Limit: 2}); err != nil {
		t.Fatal(err)
	}
}
