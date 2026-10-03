package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	"github.com/cdot65/prisma-airs-go/aisec/internal/typedhttp"
	parity "github.com/cdot65/prisma-airs-go/aisec/parity/schema"
	"strings"
)

// DashboardClient reads runtime application/session dashboards without changing other management routes.
type DashboardClient struct{ cfg *internal.OAuthServiceConfig }

// DashboardTimeRangeQuery uses endpoint-specific defaults when its fields are zero-valued.
type DashboardTimeRangeQuery struct {
	TimeInterval int
	TimeUnit     string
}

// DashboardAppQuery identifies the literal scan metadata application bucket.
type DashboardAppQuery struct {
	DashboardTimeRangeQuery
	AppID, AppName string
}

// DashboardOverviewQuery selects a time range and offset page.
type DashboardOverviewQuery struct {
	DashboardTimeRangeQuery
	Limit, Offset int
}

// DashboardSessionQuery identifies a session/application and selects an action page.
type DashboardSessionQuery struct {
	DashboardOverviewQuery
	SessionID, AppID, AppName string
}

// DashboardTransactionQuery identifies one scan subrequest; zero is a valid subrequest ID.
type DashboardTransactionQuery struct {
	DashboardTimeRangeQuery
	SessionID, AppID, AppName, ScanID string
	ScanSubReqID                      int64
}

// DashboardScanContentQuery retrieves sensitive scan content explicitly.
type DashboardScanContentQuery struct {
	ScanID       string
	ScanSubReqID int64
}

// Application reads /v1/mgmt/dashboard/v2/apps/application using its pinned TypeScript response model.
func (c *DashboardClient) Application(ctx context.Context, opts DashboardAppQuery) (*parity.DashboardApplication, error) {
	params, err := dashboardAppParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.DashboardApplication](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.RuntimeV1MgmtDashboardV2AppsApplicationPath, Params: params}, ResponseSchema: "DashboardApplicationSchema"})
}

// ApplicationRaw reads /v1/mgmt/dashboard/v2/apps/application without imposing a response model; nil JSON means an empty body.
func (c *DashboardClient) ApplicationRaw(ctx context.Context, opts DashboardAppQuery) (*json.RawMessage, error) {
	params, err := dashboardAppParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[json.RawMessage](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.RuntimeV1MgmtDashboardV2AppsApplicationPath, Params: params, ResponsePolicy: internal.AllowEmptyJSON}})
}

// ApplicationViolationBreakdown reads /v1/mgmt/dashboard/v2/apps/applicationviolationbreakdown using its pinned TypeScript response model.
func (c *DashboardClient) ApplicationViolationBreakdown(ctx context.Context, opts DashboardAppQuery) (*parity.DashboardApplicationViolationBreakdown, error) {
	params, err := dashboardAppParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.DashboardApplicationViolationBreakdown](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.RuntimeV1MgmtDashboardV2AppsApplicationviolationbreakdownPath, Params: params}, ResponseSchema: "DashboardApplicationViolationBreakdownSchema"})
}

// ApplicationViolationBreakdownRaw reads /v1/mgmt/dashboard/v2/apps/applicationviolationbreakdown without imposing a response model; nil JSON means an empty body.
func (c *DashboardClient) ApplicationViolationBreakdownRaw(ctx context.Context, opts DashboardAppQuery) (*json.RawMessage, error) {
	params, err := dashboardAppParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[json.RawMessage](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.RuntimeV1MgmtDashboardV2AppsApplicationviolationbreakdownPath, Params: params, ResponsePolicy: internal.AllowEmptyJSON}})
}

// ApplicationsOverview reads /v1/mgmt/dashboard/v2/apps/applicationsoverview using its pinned TypeScript response model.
func (c *DashboardClient) ApplicationsOverview(ctx context.Context, opts DashboardOverviewQuery) (*parity.DashboardApplicationsOverview, error) {
	params, err := dashboardOverviewParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.DashboardApplicationsOverview](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.RuntimeV1MgmtDashboardV2AppsApplicationsoverviewPath, Params: params}, ResponseSchema: "DashboardApplicationsOverviewSchema"})
}

// ApplicationsOverviewRaw reads /v1/mgmt/dashboard/v2/apps/applicationsoverview without imposing a response model; nil JSON means an empty body.
func (c *DashboardClient) ApplicationsOverviewRaw(ctx context.Context, opts DashboardOverviewQuery) (*json.RawMessage, error) {
	params, err := dashboardOverviewParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[json.RawMessage](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.RuntimeV1MgmtDashboardV2AppsApplicationsoverviewPath, Params: params, ResponsePolicy: internal.AllowEmptyJSON}})
}

// TopApplicationsViolations reads /v1/mgmt/dashboard/v2/apps/topapplicationsviolations using its pinned TypeScript response model.
func (c *DashboardClient) TopApplicationsViolations(ctx context.Context, opts DashboardTimeRangeQuery) (*parity.DashboardTopApplicationsViolations, error) {
	params, err := dashboardTimeParams(opts, 1, "day")
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.DashboardTopApplicationsViolations](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.RuntimeV1MgmtDashboardV2AppsTopapplicationsviolationsPath, Params: params}, ResponseSchema: "DashboardTopApplicationsViolationsSchema"})
}

// TopApplicationsViolationsRaw reads /v1/mgmt/dashboard/v2/apps/topapplicationsviolations without imposing a response model; nil JSON means an empty body.
func (c *DashboardClient) TopApplicationsViolationsRaw(ctx context.Context, opts DashboardTimeRangeQuery) (*json.RawMessage, error) {
	params, err := dashboardTimeParams(opts, 1, "day")
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[json.RawMessage](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.RuntimeV1MgmtDashboardV2AppsTopapplicationsviolationsPath, Params: params, ResponsePolicy: internal.AllowEmptyJSON}})
}

// ApplicationsViolationsTrend reads /v1/mgmt/dashboard/v2/apps/applicationsviolationstrend using its pinned TypeScript response model.
func (c *DashboardClient) ApplicationsViolationsTrend(ctx context.Context, opts DashboardTimeRangeQuery) (*parity.DashboardApplicationsViolationsTrend, error) {
	params, err := dashboardTimeParams(opts, 1, "day")
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.DashboardApplicationsViolationsTrend](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.RuntimeV1MgmtDashboardV2AppsApplicationsviolationstrendPath, Params: params}, ResponseSchema: "DashboardApplicationsViolationsTrendSchema"})
}

// ApplicationsViolationsTrendRaw reads /v1/mgmt/dashboard/v2/apps/applicationsviolationstrend without imposing a response model; nil JSON means an empty body.
func (c *DashboardClient) ApplicationsViolationsTrendRaw(ctx context.Context, opts DashboardTimeRangeQuery) (*json.RawMessage, error) {
	params, err := dashboardTimeParams(opts, 1, "day")
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[json.RawMessage](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.RuntimeV1MgmtDashboardV2AppsApplicationsviolationstrendPath, Params: params, ResponsePolicy: internal.AllowEmptyJSON}})
}

// AppsList reads /v1/mgmt/dashboard/v2/apps/appslist using its pinned TypeScript response model.
func (c *DashboardClient) AppsList(ctx context.Context, opts DashboardTimeRangeQuery) (*parity.DashboardAppsList, error) {
	params, err := dashboardTimeParams(opts, 30, "days")
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.DashboardAppsList](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.RuntimeV1MgmtDashboardV2AppsAppslistPath, Params: params}, ResponseSchema: "DashboardAppsListSchema"})
}

// AppsListRaw reads /v1/mgmt/dashboard/v2/apps/appslist without imposing a response model; nil JSON means an empty body.
func (c *DashboardClient) AppsListRaw(ctx context.Context, opts DashboardTimeRangeQuery) (*json.RawMessage, error) {
	params, err := dashboardTimeParams(opts, 30, "days")
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[json.RawMessage](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.RuntimeV1MgmtDashboardV2AppsAppslistPath, Params: params, ResponsePolicy: internal.AllowEmptyJSON}})
}

// SessionsChart reads /v1/mgmt/dashboard/v2/sessions/sessionschart using its pinned TypeScript response model.
func (c *DashboardClient) SessionsChart(ctx context.Context, opts DashboardTimeRangeQuery) (*parity.DashboardSessionsChart, error) {
	params, err := dashboardTimeParams(opts, 1, "day")
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.DashboardSessionsChart](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.RuntimeV1MgmtDashboardV2SessionsSessionschartPath, Params: params}, ResponseSchema: "DashboardSessionsChartSchema"})
}

// SessionsChartRaw reads /v1/mgmt/dashboard/v2/sessions/sessionschart without imposing a response model; nil JSON means an empty body.
func (c *DashboardClient) SessionsChartRaw(ctx context.Context, opts DashboardTimeRangeQuery) (*json.RawMessage, error) {
	params, err := dashboardTimeParams(opts, 1, "day")
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[json.RawMessage](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.RuntimeV1MgmtDashboardV2SessionsSessionschartPath, Params: params, ResponsePolicy: internal.AllowEmptyJSON}})
}

// SessionsOverview reads /v1/mgmt/dashboard/v2/sessions/sessionsoverview using its pinned TypeScript response model.
func (c *DashboardClient) SessionsOverview(ctx context.Context, opts DashboardOverviewQuery) (*parity.DashboardSessionsOverview, error) {
	params, err := dashboardPageParams(opts, 1, "day")
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.DashboardSessionsOverview](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.RuntimeV1MgmtDashboardV2SessionsSessionsoverviewPath, Params: params}, ResponseSchema: "DashboardSessionsOverviewSchema"})
}

// SessionsOverviewRaw reads /v1/mgmt/dashboard/v2/sessions/sessionsoverview without imposing a response model; nil JSON means an empty body.
func (c *DashboardClient) SessionsOverviewRaw(ctx context.Context, opts DashboardOverviewQuery) (*json.RawMessage, error) {
	params, err := dashboardPageParams(opts, 1, "day")
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[json.RawMessage](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.RuntimeV1MgmtDashboardV2SessionsSessionsoverviewPath, Params: params, ResponsePolicy: internal.AllowEmptyJSON}})
}

// Session reads /v1/mgmt/dashboard/v2/sessions/session using its pinned TypeScript response model.
func (c *DashboardClient) Session(ctx context.Context, opts DashboardSessionQuery) (*parity.DashboardSession, error) {
	params, err := dashboardSessionParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.DashboardSession](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.RuntimeV1MgmtDashboardV2SessionsSessionPath, Params: params}, ResponseSchema: "DashboardSessionSchema"})
}

// SessionRaw reads /v1/mgmt/dashboard/v2/sessions/session without imposing a response model; nil JSON means an empty body.
func (c *DashboardClient) SessionRaw(ctx context.Context, opts DashboardSessionQuery) (*json.RawMessage, error) {
	params, err := dashboardSessionParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[json.RawMessage](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.RuntimeV1MgmtDashboardV2SessionsSessionPath, Params: params, ResponsePolicy: internal.AllowEmptyJSON}})
}

// SessionTransaction reads /v1/mgmt/dashboard/v2/sessions/sessiontransaction using its pinned TypeScript response model.
func (c *DashboardClient) SessionTransaction(ctx context.Context, opts DashboardTransactionQuery) (*parity.DashboardSessionTransaction, error) {
	params, err := dashboardTransactionParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.DashboardSessionTransaction](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.RuntimeV1MgmtDashboardV2SessionsSessiontransactionPath, Params: params}, ResponseSchema: "DashboardSessionTransactionSchema"})
}

// SessionTransactionRaw reads /v1/mgmt/dashboard/v2/sessions/sessiontransaction without imposing a response model; nil JSON means an empty body.
func (c *DashboardClient) SessionTransactionRaw(ctx context.Context, opts DashboardTransactionQuery) (*json.RawMessage, error) {
	params, err := dashboardTransactionParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[json.RawMessage](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.RuntimeV1MgmtDashboardV2SessionsSessiontransactionPath, Params: params, ResponsePolicy: internal.AllowEmptyJSON}})
}

// ScanContent reads /v1/mgmt/reports/scancontent using its pinned TypeScript response model.
func (c *DashboardClient) ScanContent(ctx context.Context, opts DashboardScanContentQuery) (*parity.DashboardScanContent, error) {
	params, err := dashboardScanParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.DashboardScanContent](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.RuntimeV1MgmtReportsScancontentPath, Params: params}, ResponseSchema: "DashboardScanContentSchema"})
}

// ScanContentRaw reads /v1/mgmt/reports/scancontent without imposing a response model; nil JSON means an empty body.
func (c *DashboardClient) ScanContentRaw(ctx context.Context, opts DashboardScanContentQuery) (*json.RawMessage, error) {
	params, err := dashboardScanParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[json.RawMessage](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.RuntimeV1MgmtReportsScancontentPath, Params: params, ResponsePolicy: internal.AllowEmptyJSON}})
}

func dashboardTimeParams(opts DashboardTimeRangeQuery, interval int, unit string) (map[string]string, error) {
	if opts.TimeInterval < 0 {
		return nil, dlpInvalid("dashboard interval must be positive")
	}
	if opts.TimeInterval > 0 {
		interval = opts.TimeInterval
	}
	if opts.TimeUnit != "" {
		if strings.TrimSpace(opts.TimeUnit) == "" {
			return nil, dlpInvalid("dashboard time unit must be nonblank")
		}
		unit = opts.TimeUnit
	}
	return map[string]string{"time_interval": fmt.Sprint(interval), "time_unit": unit}, nil
}
func dashboardAppParams(opts DashboardAppQuery) (map[string]string, error) {
	if strings.TrimSpace(opts.AppID) == "" || strings.TrimSpace(opts.AppName) == "" {
		return nil, dlpInvalid("dashboard application ID and name are required")
	}
	p, err := dashboardTimeParams(opts.DashboardTimeRangeQuery, 30, "days")
	if err != nil {
		return nil, err
	}
	if p["time_unit"] != "days" || (p["time_interval"] != "7" && p["time_interval"] != "30" && p["time_interval"] != "60") {
		return nil, dlpInvalid("application window must be 7, 30 or 60 days")
	}
	p["appid"] = opts.AppID
	p["appname"] = opts.AppName
	return p, nil
}
func dashboardPageParams(opts DashboardOverviewQuery, interval int, unit string) (map[string]string, error) {
	p, err := dashboardTimeParams(opts.DashboardTimeRangeQuery, interval, unit)
	if err != nil {
		return nil, err
	}
	if opts.Limit < 0 || opts.Offset < 0 {
		return nil, dlpInvalid("invalid dashboard pagination")
	}
	limit := opts.Limit
	if limit == 0 {
		limit = 25
	}
	p["limit"] = fmt.Sprint(limit)
	p["offset"] = fmt.Sprint(opts.Offset)
	return p, nil
}
func dashboardOverviewParams(opts DashboardOverviewQuery) (map[string]string, error) {
	p, err := dashboardPageParams(opts, 30, "days")
	if err != nil {
		return nil, err
	}
	valid := (p["time_unit"] == "days" && (p["time_interval"] == "7" || p["time_interval"] == "30" || p["time_interval"] == "60")) || ((p["time_unit"] == "day" || p["time_unit"] == "hour") && p["time_interval"] == "1")
	if !valid {
		return nil, dlpInvalid("invalid dashboard overview window")
	}
	return p, nil
}
func dashboardIdentity(sessionID, appID, appName string, p map[string]string) error {
	if strings.TrimSpace(sessionID) == "" || strings.TrimSpace(appID) == "" || strings.TrimSpace(appName) == "" {
		return dlpInvalid("session and application identity required")
	}
	p["session_id"] = sessionID
	p["app_id"] = appID
	p["app_name"] = appName
	return nil
}
func dashboardSessionParams(opts DashboardSessionQuery) (map[string]string, error) {
	p, err := dashboardPageParams(opts.DashboardOverviewQuery, 30, "days")
	if err != nil {
		return nil, err
	}
	return p, dashboardIdentity(opts.SessionID, opts.AppID, opts.AppName, p)
}
func dashboardScanParams(opts DashboardScanContentQuery) (map[string]string, error) {
	if strings.TrimSpace(opts.ScanID) == "" || opts.ScanSubReqID < 0 {
		return nil, dlpInvalid("scan ID and nonnegative subrequest ID required")
	}
	return map[string]string{"scan_id": opts.ScanID, "scan_sub_req_id": fmt.Sprint(opts.ScanSubReqID)}, nil
}
func dashboardTransactionParams(opts DashboardTransactionQuery) (map[string]string, error) {
	p, err := dashboardTimeParams(opts.DashboardTimeRangeQuery, 30, "days")
	if err != nil {
		return nil, err
	}
	if err := dashboardIdentity(opts.SessionID, opts.AppID, opts.AppName, p); err != nil {
		return nil, err
	}
	scan, err := dashboardScanParams(DashboardScanContentQuery{ScanID: opts.ScanID, ScanSubReqID: opts.ScanSubReqID})
	if err != nil {
		return nil, err
	}
	for key, value := range scan {
		p[key] = value
	}
	return p, nil
}
