//go:build integration

package redteam

import (
	"context"
	"testing"
	"time"

	"github.com/cdot65/prisma-airs-go/aisec"
)

// TestIntegration_Reports_ReadEndpoints exercises every report-style read
// endpoint against existing finished jobs in the tenant. It is read-only. A
// 404 from a job that exists means the SDK is calling a wrong path — exactly
// the class of bug the mock-based unit tests cannot see — so 404 fails the
// test. Other errors (a job type without that report, tenant entitlements) are
// logged, not failed.
func TestIntegration_Reports_ReadEndpoints(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	jobs, err := client.Scans.List(ctx, ScanListOpts{Limit: 100})
	if err != nil {
		t.Fatalf("Scans.List: %v", err)
	}
	pick := map[JobType]*JobResponse{}
	for i := range jobs.Data {
		j := &jobs.Data[i]
		if (j.Status == JobStatusCompleted || j.Status == JobStatusPartiallyComplete) && pick[j.JobType] == nil {
			pick[j.JobType] = j
		}
	}
	t.Logf("jobs listed: %d; finished job types available: static=%t dynamic=%t custom=%t",
		len(jobs.Data), pick[JobTypeStatic] != nil, pick[JobTypeDynamic] != nil, pick[JobTypeCustom] != nil)

	// check records one endpoint result. 404 on an existing job = wrong path.
	check := func(name string, err error) {
		t.Helper()
		switch {
		case err == nil:
			t.Logf("OK    %s", name)
		case aisec.IsNotFound(err):
			t.Errorf("404   %s: %v  (wrong path, or the data does not exist)", name, err)
		default:
			t.Logf("WARN  %s: %v", name, err)
		}
	}

	if j := pick[JobTypeStatic]; j != nil {
		id := j.UUID
		_, err := client.Reports.GetStaticReport(ctx, id)
		check("GetStaticReport", err)
		attacks, err := client.Reports.ListAttacks(ctx, id, AttackListOpts{Limit: 5})
		check("ListAttacks", err)
		_, err = client.Reports.GetStaticRemediation(ctx, id)
		check("GetStaticRemediation", err)
		_, err = client.Reports.GetStaticRuntimePolicy(ctx, id)
		check("GetStaticRuntimePolicy", err)
		if attacks != nil && len(attacks.Data) > 0 {
			if attacks.Data[0].UUID == "" {
				t.Error("list-attacks row has no uuid; AttackListItem is missing the identifier field")
			}
			_, err = client.Reports.GetAttackDetail(ctx, id, attacks.Data[0].UUID)
			check("GetAttackDetail", err)
			// The multi-turn endpoint only serves multi-turn attacks.
			var multi *AttackListItem
			if all, err := client.Reports.ListAttacks(ctx, id, AttackListOpts{Limit: 100}); err == nil {
				for i := range all.Data {
					if all.Data[i].MultiTurn {
						multi = &all.Data[i]
						break
					}
				}
			}
			if multi != nil {
				_, err = client.Reports.GetMultiTurnAttackDetail(ctx, id, multi.UUID)
				check("GetMultiTurnAttackDetail", err)
			} else {
				t.Log("SKIP  GetMultiTurnAttackDetail: no multi-turn attack in the first 100 rows")
			}
		} else {
			t.Log("SKIP  GetAttackDetail/GetMultiTurnAttackDetail: no attacks listed")
		}
		_, err = client.GetErrorLogs(ctx, id, ListOpts{Limit: 5})
		check("GetErrorLogs", err)
		_, err = client.GetSentiment(ctx, id)
		check("GetSentiment", err)
	} else {
		t.Log("SKIP  static report endpoints: no finished STATIC job")
	}

	if j := pick[JobTypeDynamic]; j != nil {
		id := j.UUID
		_, err := client.Reports.GetDynamicReport(ctx, id)
		check("GetDynamicReport", err)
		_, err = client.Reports.GetDynamicRemediation(ctx, id)
		check("GetDynamicRemediation", err)
		_, err = client.Reports.GetDynamicRuntimePolicy(ctx, id)
		check("GetDynamicRuntimePolicy", err)
		goals, err := client.Reports.ListGoals(ctx, id, GoalListOpts{Limit: 5})
		check("ListGoals", err)
		if goals != nil && len(goals.Data) > 0 {
			streams, err := client.Reports.ListGoalStreams(ctx, id, goals.Data[0].UUID, ListOpts{Limit: 5})
			check("ListGoalStreams", err)
			if streams != nil && len(streams.Data) > 0 {
				_, err = client.Reports.GetStreamDetail(ctx, streams.Data[0].UUID)
				check("GetStreamDetail", err)
			} else {
				t.Log("SKIP  GetStreamDetail: no streams listed")
			}
		} else {
			t.Log("SKIP  ListGoalStreams/GetStreamDetail: no goals listed")
		}
	} else {
		t.Log("SKIP  dynamic report endpoints: no finished DYNAMIC job")
	}

	if j := pick[JobTypeCustom]; j != nil {
		id := j.UUID
		_, err := client.CustomAttackReports.GetReport(ctx, id)
		check("CustomAttackReports.GetReport", err)
		sets, err := client.CustomAttackReports.GetPromptSets(ctx, id)
		check("CustomAttackReports.GetPromptSets", err)
		_, err = client.CustomAttackReports.ListCustomAttacks(ctx, id, CustomAttacksReportListOpts{Limit: 5})
		check("CustomAttackReports.ListCustomAttacks", err)
		_, err = client.CustomAttackReports.GetPropertyStats(ctx, id)
		check("CustomAttackReports.GetPropertyStats", err)
		if sets != nil && len(sets.Data) > 0 {
			if sid, ok := sets.Data[0]["id"].(string); ok {
				prompts, err := client.CustomAttackReports.GetPromptsBySet(ctx, id, sid, PromptsBySetListOpts{Limit: 5})
				check("CustomAttackReports.GetPromptsBySet", err)
				if len(prompts) > 0 {
					_, err = client.CustomAttackReports.GetPromptDetail(ctx, id, prompts[0].ID)
					check("CustomAttackReports.GetPromptDetail", err)
				}
			}
		}
	} else {
		t.Log("SKIP  custom attack report endpoints: no finished CUSTOM job")
	}

	// Dashboard endpoints (no job needed).
	_, err = client.GetScanStatistics(ctx, nil)
	check("GetScanStatistics", err)
	if len(jobs.Data) > 0 && jobs.Data[0].TargetID != "" {
		_, err = client.GetScoreTrend(ctx, jobs.Data[0].TargetID)
		check("GetScoreTrend", err)
		_, err = client.GetScoreTrend(ctx, jobs.Data[0].TargetID, ScoreTrendOpts{DateRange: DateRangeFilterLast30Days})
		check("GetScoreTrend(date_range)", err)
	}
}
