package gateway

import (
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	"math"
	"reflect"
	"testing"
	"time"
)

func TestTelemetryFilterWireAndZeroValues(t *testing.T) {
	c := &TelemetryClient{cfg: &internal.OAuthServiceConfig{TsgID: "123"}}
	end := time.Date(2026, 10, 3, 12, 0, 0, 0, time.FixedZone("west", -7*3600))
	start := end.Add(-24 * time.Hour)
	zeroInt := int64(0)
	zero := 0.0
	p, err := c.chartParams(ChartOptions{TelemetryWindow: TelemetryWindow{WorkspaceSlug: "ws-test", Start: &start, End: &end}, Metadata: map[string]string{"team": "blue"}, StatusCodes: []int{0, 200}, APIKeyIDs: []string{"550e8400-e29b-41d4-a716-446655440000"}, AIOrgModels: []string{"openai__gpt-4o"}, TotalUnitsMin: &zeroInt, CostMin: &zero, CostMax: &zero})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"organisationId": "123", "workspaceSlug": "ws-test", "timeOfGenerationMin": "2026-10-02T12:00:00-07:00", "timeOfGenerationMax": "2026-10-03T12:00:00-07:00", "metadata": `{"team":"blue"}`, "statusCode": "0,200", "apiKeyIds": "550e8400-e29b-41d4-a716-446655440000", "aiOrgModel": "openai__gpt-4o", "totalUnitsMin": "0", "costMin": "0", "costMax": "0"}
	if !reflect.DeepEqual(p, want) {
		t.Fatalf("params=%#v", p)
	}
	zeroPage := 0
	logs, err := c.logsParams(LogsOptions{TelemetryWindow: TelemetryWindow{WorkspaceSlug: "ws-test", Start: &start, End: &end}, CurrentPage: &zeroPage, PageSize: &zeroPage, StatusCode: &zeroPage})
	if err != nil || logs["currentPage"] != "0" || logs["pageSize"] != "0" || logs["statusCode"] != "0" {
		t.Fatalf("logs=%v err=%v", logs, err)
	}
	group, err := c.groupParams(GroupOptions{ChartOptions: ChartOptions{TelemetryWindow: TelemetryWindow{WorkspaceSlug: "ws-test", Start: &start, End: &end}}, Columns: []string{"cost", "avg_tokens"}})
	if err != nil || group["columns"] != "cost,avg_tokens" {
		t.Fatalf("groups=%v err=%v", group, err)
	}
}
func TestTelemetryRejectsInvalidFilters(t *testing.T) {
	c := &TelemetryClient{cfg: &internal.OAuthServiceConfig{TsgID: "123"}}
	nan := math.NaN()
	neg := -1.0
	for _, opts := range []ChartOptions{{TelemetryWindow: TelemetryWindow{WorkspaceSlug: "ws-test"}, CostMin: &nan}, {TelemetryWindow: TelemetryWindow{WorkspaceSlug: "ws-test"}, CostMin: &neg}, {TelemetryWindow: TelemetryWindow{WorkspaceSlug: "ws-test"}, StatusCodes: []int{}}, {TelemetryWindow: TelemetryWindow{WorkspaceSlug: "ws-test"}, APIKeyIDs: []string{"invalid"}}, {TelemetryWindow: TelemetryWindow{WorkspaceSlug: "ws-test"}, AIOrgModels: []string{"invalid"}}, {TelemetryWindow: TelemetryWindow{WorkspaceSlug: "bad/path"}}} {
		if _, err := c.chartParams(opts); err == nil {
			t.Fatalf("accepted %#v", opts)
		}
	}
}
