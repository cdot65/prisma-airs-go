//go:build integration

package redteam

import (
	"context"
	"testing"
	"time"
)

func TestIntegration_CurrentRedTeamMetadataAndReports(t *testing.T) {
	c := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	t.Run("data_languages", func(t *testing.T) {
		result, err := c.GetLanguages(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("languages=%d", len(result.Languages))
	})
	t.Run("management_languages", func(t *testing.T) {
		result, err := c.Targets.GetLanguages(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("languages=%d", len(result.Languages))
	})
	t.Run("goal_categories", func(t *testing.T) {
		result, err := c.GetGoalCategories(ctx, "APPLICATION")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("categories=%d", len(result.Categories))
	})
	t.Run("scan_metadata", func(t *testing.T) {
		result, err := c.Scans.GetMetadata(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("metadata_keys=%d", len(result))
	})
	list, err := c.Scans.List(ctx, ScanListOpts{Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Data) > 0 {
		job := list.Data[0]
		t.Run("report_status", func(t *testing.T) {
			if _, err := c.Reports.GetStatus(ctx, job.UUID); err != nil {
				t.Fatal(err)
			}
		})
		t.Run("asr", func(t *testing.T) {
			if job.JobType == JobTypeDynamic {
				if _, err := c.Reports.GetDynamicASR(ctx, job.UUID); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := c.Reports.GetStaticASR(ctx, job.UUID); err != nil {
					t.Fatal(err)
				}
			}
		})
		t.Run("download_receipt", func(t *testing.T) {
			receipt, err := c.Reports.GetDownload(ctx, job.UUID, FileFormatJSON)
			if err != nil {
				t.Fatal(err)
			}
			if receipt.DownloadURL == "" || receipt.Filename == "" {
				t.Fatal("download receipt missing location or filename")
			}
		})
		t.Run("error_log_download", func(t *testing.T) {
			if _, err := c.DownloadErrorLogs(ctx, job.UUID); err != nil {
				t.Fatal(err)
			}
		})
	}
	targets, err := c.Targets.List(ctx, TargetListOpts{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets.Data) > 0 {
		t.Run("profile_error_logs", func(t *testing.T) {
			if _, err := c.GetTargetProfileErrorLogs(ctx, targets.Data[0].UUID, 2); err != nil {
				t.Fatal(err)
			}
		})
	}
}
