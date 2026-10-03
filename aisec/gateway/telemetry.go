package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	"github.com/cdot65/prisma-airs-go/aisec/internal/typedhttp"
	parity "github.com/cdot65/prisma-airs-go/aisec/parity/schema"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// TelemetryClient exposes SCM observability queries, independently of runtime inference.
type TelemetryClient struct{ cfg *internal.OAuthServiceConfig }

// TelemetryWindow selects a workspace slug and fixed/rolling time range; default lookback is seven days.
type TelemetryWindow struct {
	WorkspaceSlug string
	Days          *float64
	Start, End    *time.Time
}

// ChartOptions uses cents for costs and preserves zero-valued bounds. Filters are combined with AND; list members with OR.
type ChartOptions struct {
	TelemetryWindow
	TraceID                      *string
	Metadata                     map[string]string
	StatusCodes                  []int
	APIKeyIDs, AIOrgModels       []string
	TotalUnitsMin, TotalUnitsMax *int64
	CostMin, CostMax             *float64
}

// GroupOptions adds supported aggregate columns to chart filters.
type GroupOptions struct {
	ChartOptions
	Columns []string
}

// LogsOptions selects zero-based currentPage/pageSize, without offset aliases.
type LogsOptions struct {
	TelemetryWindow
	PageSize, CurrentPage, StatusCode *int
	TraceID                           *string
}

// ErrorCategoryTrends queries /logs/charts/error-category-trends with validated SCM query names and time offsets.
func (c *TelemetryClient) ErrorCategoryTrends(ctx context.Context, opts TelemetryWindow) (*parity.ErrorCategoryTrendsResponse, error) {
	params, err := c.windowParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.ErrorCategoryTrendsResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.GatewayLogsChartsErrorCategoryTrendsPath, Params: params}, ResponseSchema: "ErrorCategoryTrendsResponseSchema"})
}

// GroupedErrors queries /logs/charts/grouped-errors with validated SCM query names and time offsets.
func (c *TelemetryClient) GroupedErrors(ctx context.Context, opts TelemetryWindow) (*parity.GroupedErrorsResponse, error) {
	params, err := c.windowParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.GroupedErrorsResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.GatewayLogsChartsGroupedErrorsPath, Params: params}, ResponseSchema: "GroupedErrorsResponseSchema"})
}

// FilterBoundaries queries /analytics/filter-boundaries with validated SCM query names and time offsets.
func (c *TelemetryClient) FilterBoundaries(ctx context.Context, opts TelemetryWindow) (*parity.GatewayFilterBoundariesResponse, error) {
	params, err := c.windowParams(opts)
	if err != nil {
		return nil, err
	}
	delete(params, "organisationId")
	return typedhttp.Do[parity.GatewayFilterBoundariesResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.GatewayAnalyticsFilterBoundariesPath, Params: params}, ResponseSchema: "GatewayFilterBoundariesResponseSchema"})
}

// Cost queries /logs/charts/cost with validated SCM query names and time offsets.
func (c *TelemetryClient) Cost(ctx context.Context, opts ChartOptions) (*parity.CostChartResponse, error) {
	params, err := c.chartParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.CostChartResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.GatewayLogsChartsCostPath, Params: params}, ResponseSchema: "CostChartResponseSchema"})
}

// Requests queries /logs/charts/requests with validated SCM query names and time offsets.
func (c *TelemetryClient) Requests(ctx context.Context, opts ChartOptions) (*parity.CountChartResponse, error) {
	params, err := c.chartParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.CountChartResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.GatewayLogsChartsRequestsPath, Params: params}, ResponseSchema: "CountChartResponseSchema"})
}

// Latency queries /logs/charts/latency with validated SCM query names and time offsets.
func (c *TelemetryClient) Latency(ctx context.Context, opts ChartOptions) (*parity.LatencyChartResponse, error) {
	params, err := c.chartParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.LatencyChartResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.GatewayLogsChartsLatencyPath, Params: params}, ResponseSchema: "LatencyChartResponseSchema"})
}

// Tokens queries /logs/charts/tokens with validated SCM query names and time offsets.
func (c *TelemetryClient) Tokens(ctx context.Context, opts ChartOptions) (*parity.TokensChartResponse, error) {
	params, err := c.chartParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.TokensChartResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.GatewayLogsChartsTokensPath, Params: params}, ResponseSchema: "TokensChartResponseSchema"})
}

// Errors queries /logs/charts/errors with validated SCM query names and time offsets.
func (c *TelemetryClient) Errors(ctx context.Context, opts TelemetryWindow) (*parity.CountChartResponse, error) {
	params, err := c.windowParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.CountChartResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.GatewayLogsChartsErrorsPath, Params: params}, ResponseSchema: "CountChartResponseSchema"})
}

// Users queries /logs/charts/users with validated SCM query names and time offsets.
func (c *TelemetryClient) Users(ctx context.Context, opts TelemetryWindow) (*parity.CountChartResponse, error) {
	params, err := c.windowParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.CountChartResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.GatewayLogsChartsUsersPath, Params: params}, ResponseSchema: "CountChartResponseSchema"})
}

// CacheSummary queries /logs/charts/cache-summary with validated SCM query names and time offsets.
func (c *TelemetryClient) CacheSummary(ctx context.Context, opts TelemetryWindow) (*parity.CacheSummaryResponse, error) {
	params, err := c.windowParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.CacheSummaryResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.GatewayLogsChartsCacheSummaryPath, Params: params}, ResponseSchema: "CacheSummaryResponseSchema"})
}

// CacheHitTrend queries /logs/charts/cache-hit-trend with validated SCM query names and time offsets.
func (c *TelemetryClient) CacheHitTrend(ctx context.Context, opts TelemetryWindow) (*parity.CacheHitTrendResponse, error) {
	params, err := c.windowParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.CacheHitTrendResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.GatewayLogsChartsCacheHitTrendPath, Params: params}, ResponseSchema: "CacheHitTrendResponseSchema"})
}

// UserTrends queries /logs/charts/user-trends with validated SCM query names and time offsets.
func (c *TelemetryClient) UserTrends(ctx context.Context, opts TelemetryWindow) (*parity.UserTrendsResponse, error) {
	params, err := c.windowParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.UserTrendsResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.GatewayLogsChartsUserTrendsPath, Params: params}, ResponseSchema: "UserTrendsResponseSchema"})
}

// ErrorTrends queries /logs/charts/error-trends with validated SCM query names and time offsets.
func (c *TelemetryClient) ErrorTrends(ctx context.Context, opts TelemetryWindow) (*parity.ErrorTrendsResponse, error) {
	params, err := c.windowParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.ErrorTrendsResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.GatewayLogsChartsErrorTrendsPath, Params: params}, ResponseSchema: "ErrorTrendsResponseSchema"})
}

// RescuedRetries queries /logs/charts/rescued-retries with validated SCM query names and time offsets.
func (c *TelemetryClient) RescuedRetries(ctx context.Context, opts TelemetryWindow) (*parity.RescuedRetriesResponse, error) {
	params, err := c.windowParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.RescuedRetriesResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.GatewayLogsChartsRescuedRetriesPath, Params: params}, ResponseSchema: "RescuedRetriesResponseSchema"})
}

// FeedbackTrend queries /logs/charts/feedback-trend with validated SCM query names and time offsets.
func (c *TelemetryClient) FeedbackTrend(ctx context.Context, opts TelemetryWindow) (*parity.CountChartResponse, error) {
	params, err := c.windowParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.CountChartResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.GatewayLogsChartsFeedbackTrendPath, Params: params}, ResponseSchema: "CountChartResponseSchema"})
}

// FeedbackWeighted queries /logs/charts/feedback-weighted with validated SCM query names and time offsets.
func (c *TelemetryClient) FeedbackWeighted(ctx context.Context, opts TelemetryWindow) (*parity.CountChartResponse, error) {
	params, err := c.windowParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.CountChartResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.GatewayLogsChartsFeedbackWeightedPath, Params: params}, ResponseSchema: "CountChartResponseSchema"})
}

// FeedbackScoreDistribution queries /logs/charts/feedback-score-distribution with validated SCM query names and time offsets.
func (c *TelemetryClient) FeedbackScoreDistribution(ctx context.Context, opts TelemetryWindow) (*parity.FeedbackScoreDistributionResponse, error) {
	params, err := c.windowParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.FeedbackScoreDistributionResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.GatewayLogsChartsFeedbackScoreDistributionPath, Params: params}, ResponseSchema: "FeedbackScoreDistributionResponseSchema"})
}

// FeedbackModels queries /logs/charts/feedback-models with validated SCM query names and time offsets.
func (c *TelemetryClient) FeedbackModels(ctx context.Context, opts TelemetryWindow) (*parity.FeedbackModelsResponse, error) {
	params, err := c.windowParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.FeedbackModelsResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.GatewayLogsChartsFeedbackModelsPath, Params: params}, ResponseSchema: "FeedbackModelsResponseSchema"})
}

// GroupBy queries /logs/groups/{dimension} with validated SCM query names and time offsets.
func (c *TelemetryClient) GroupBy(ctx context.Context, dimension string, opts GroupOptions) (*parity.GroupListResponse, error) {
	params, err := c.groupParams(opts)
	if err != nil {
		return nil, err
	}
	if dimension != "ai_service" && dimension != "model" && dimension != "api_key" && dimension != "provider" {
		return nil, invalidInput("unsupported analytics grouping dimension")
	}
	return typedhttp.Do[parity.GroupListResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.GatewayLogsGroupsPath + "/" + seg(dimension) + "", Params: params}, ResponseSchema: "GroupListResponseSchema"})
}

// ByUser queries /logs/groups/users with validated SCM query names and time offsets.
func (c *TelemetryClient) ByUser(ctx context.Context, opts ChartOptions) (*parity.UserGroupResponse, error) {
	params, err := c.chartParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.UserGroupResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.GatewayLogsGroupsUsersPath, Params: params}, ResponseSchema: "UserGroupResponseSchema"})
}

// ByStatusCode queries /logs/groups/status_code with validated SCM query names and time offsets.
func (c *TelemetryClient) ByStatusCode(ctx context.Context, opts GroupOptions) (*parity.GroupListResponse, error) {
	params, err := c.groupParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.GroupListResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.GatewayLogsGroupsStatusCodePath, Params: params}, ResponseSchema: "GroupListResponseSchema"})
}

// Logs queries /logs with validated SCM query names and time offsets.
func (c *TelemetryClient) Logs(ctx context.Context, opts LogsOptions) (*parity.GatewayLogsResponse, error) {
	params, err := c.logsParams(opts)
	if err != nil {
		return nil, err
	}
	return typedhttp.Do[parity.GatewayLogsResponse](ctx, c.cfg, typedhttp.Options{MgmtRequestOptions: internal.MgmtRequestOptions{Method: "GET", Path: aisec.GatewayLogsPath, Params: params}, ResponseSchema: "GatewayLogsResponseSchema"})
}

var numericTenantPattern = regexp.MustCompile(`^\d+$`)
var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var orgModelPattern = regexp.MustCompile(`^[^,\s]+__[^,\s]+$`)

func (c *TelemetryClient) windowParams(opts TelemetryWindow) (map[string]string, error) {
	if !numericTenantPattern.MatchString(c.cfg.TsgID) || !workspaceRefPattern.MatchString(opts.WorkspaceSlug) {
		return nil, invalidInput("telemetry requires numeric tenant ID and workspace slug")
	}
	end := time.Now()
	if opts.End != nil {
		end = *opts.End
	}
	days := 7.0
	if opts.Days != nil {
		days = *opts.Days
	}
	if math.IsNaN(days) || math.IsInf(days, 0) {
		return nil, invalidInput("invalid telemetry lookback")
	}
	start := end
	if opts.Start != nil {
		start = *opts.Start
	} else {
		seconds := days * 86400
		if math.Abs(seconds) > float64(math.MaxInt64)/1e9 {
			return nil, invalidInput("telemetry lookback is too large")
		}
		start = end.Add(-time.Duration(seconds * 1e9))
	}
	if start.After(end) || start.Year() < 0 || start.Year() > 9999 || end.Year() < 0 || end.Year() > 9999 {
		return nil, invalidInput("invalid telemetry window")
	}
	const format = "2006-01-02T15:04:05-07:00"
	return map[string]string{"organisationId": c.cfg.TsgID, "workspaceSlug": opts.WorkspaceSlug, "timeOfGenerationMin": start.Format(format), "timeOfGenerationMax": end.Format(format)}, nil
}
func (c *TelemetryClient) chartParams(opts ChartOptions) (map[string]string, error) {
	params, err := c.windowParams(opts.TelemetryWindow)
	if err != nil {
		return nil, err
	}
	if opts.TraceID != nil {
		if strings.TrimSpace(*opts.TraceID) == "" {
			return nil, invalidInput("trace ID must be nonblank")
		}
		params["traceId"] = *opts.TraceID
	}
	if opts.Metadata != nil {
		b, err := json.Marshal(opts.Metadata)
		if err != nil {
			return nil, err
		}
		params["metadata"] = string(b)
	}
	if opts.StatusCodes != nil {
		if len(opts.StatusCodes) == 0 {
			return nil, invalidInput("status codes must be nonempty")
		}
		list := []string{}
		for _, v := range opts.StatusCodes {
			if v < 0 {
				return nil, invalidInput("status codes must be nonnegative")
			}
			list = append(list, strconv.Itoa(v))
		}
		params["statusCode"] = strings.Join(list, ",")
	}
	for key, list := range map[string][]string{"apiKeyIds": opts.APIKeyIDs, "aiOrgModel": opts.AIOrgModels} {
		if list == nil {
			continue
		}
		if len(list) == 0 {
			return nil, invalidInput("analytics filter list must be nonempty")
		}
		for _, v := range list {
			if (key == "apiKeyIds" && !uuidPattern.MatchString(v)) || (key == "aiOrgModel" && !orgModelPattern.MatchString(v)) {
				return nil, invalidInput("invalid analytics filter identifier")
			}
		}
		params[key] = strings.Join(list, ",")
	}
	if opts.TotalUnitsMin != nil && opts.TotalUnitsMax != nil && *opts.TotalUnitsMin > *opts.TotalUnitsMax {
		return nil, invalidInput("invalid token bounds")
	}
	if opts.CostMin != nil && opts.CostMax != nil && *opts.CostMin > *opts.CostMax {
		return nil, invalidInput("invalid cost bounds")
	}
	for key, v := range map[string]*int64{"totalUnitsMin": opts.TotalUnitsMin, "totalUnitsMax": opts.TotalUnitsMax} {
		if v != nil {
			if *v < 0 {
				return nil, invalidInput("token bounds must be nonnegative")
			}
			params[key] = fmt.Sprint(*v)
		}
	}
	for key, v := range map[string]*float64{"costMin": opts.CostMin, "costMax": opts.CostMax} {
		if v != nil {
			if *v < 0 || math.IsNaN(*v) || math.IsInf(*v, 0) {
				return nil, invalidInput("cost bounds must be finite and nonnegative")
			}
			params[key] = strconv.FormatFloat(*v, 'f', -1, 64)
		}
	}
	return params, nil
}
func (c *TelemetryClient) groupParams(opts GroupOptions) (map[string]string, error) {
	p, err := c.chartParams(opts.ChartOptions)
	if err != nil {
		return nil, err
	}
	for _, column := range opts.Columns {
		switch column {
		case "cost", "avg_latency", "avg_tokens", "total_tokens", "success_rate", "last_seen":
		default:
			return nil, invalidInput("unsupported analytics aggregate column")
		}
	}
	if len(opts.Columns) > 0 {
		p["columns"] = strings.Join(opts.Columns, ",")
	}
	return p, nil
}
func (c *TelemetryClient) logsParams(opts LogsOptions) (map[string]string, error) {
	p, err := c.windowParams(opts.TelemetryWindow)
	if err != nil {
		return nil, err
	}
	if opts.TraceID != nil {
		if strings.TrimSpace(*opts.TraceID) == "" {
			return nil, invalidInput("trace ID must be nonblank")
		}
		p["traceId"] = *opts.TraceID
	}
	for key, v := range map[string]*int{"pageSize": opts.PageSize, "currentPage": opts.CurrentPage, "statusCode": opts.StatusCode} {
		if v != nil {
			if *v < 0 {
				return nil, invalidInput("log query values must be nonnegative")
			}
			p[key] = fmt.Sprint(*v)
		}
	}
	return p, nil
}
