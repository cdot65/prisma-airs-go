package redteam

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
)

// Opts are options for creating a RedTeamClient.
type Opts struct {
	ClientID      string
	ClientSecret  string
	TsgID         string
	DataEndpoint  string
	MgmtEndpoint  string
	TokenEndpoint string
	NumRetries    int
}

// Client is the Red Team API client with dual-endpoint routing.
type Client struct {
	Scans               *ScansClient
	Reports             *ReportsClient
	CustomAttackReports *CustomAttackReportsClient
	Targets             *TargetsClient
	CustomAttacks       *CustomAttacksClient

	dataCfg *internal.OAuthServiceConfig
	mgmtCfg *internal.OAuthServiceConfig
}

// NewClient creates a new Red Team API client.
func NewClient(opts Opts) (*Client, error) {
	dataEndpoint := opts.DataEndpoint
	if dataEndpoint == "" {
		dataEndpoint = aisec.DefaultRedTeamDataEndpoint
	}
	mgmtEndpoint := opts.MgmtEndpoint
	if mgmtEndpoint == "" {
		mgmtEndpoint = aisec.DefaultRedTeamMgmtEndpoint
	}

	mgmtCfg, err := internal.ResolveOAuthConfig(internal.ResolveOAuthConfigOpts{
		ClientID:          opts.ClientID,
		ClientSecret:      opts.ClientSecret,
		TsgID:             opts.TsgID,
		BaseURL:           mgmtEndpoint,
		NumRetries:        opts.NumRetries,
		TokenEndpoint:     opts.TokenEndpoint,
		PrimaryEnvPrefix:  "PANW_RED_TEAM",
		FallbackEnvPrefix: "PANW_MGMT",
	})
	if err != nil {
		return nil, err
	}

	dataCfg := &internal.OAuthServiceConfig{
		BaseURL:    dataEndpoint,
		OAuth:      mgmtCfg.OAuth,
		NumRetries: mgmtCfg.NumRetries,
		TsgID:      mgmtCfg.TsgID,
	}

	c := &Client{dataCfg: dataCfg, mgmtCfg: mgmtCfg}
	c.Scans = &ScansClient{dataCfg: dataCfg}
	c.Reports = &ReportsClient{dataCfg: dataCfg}
	c.CustomAttackReports = &CustomAttackReportsClient{dataCfg: dataCfg}
	c.Targets = &TargetsClient{mgmtCfg: mgmtCfg}
	c.CustomAttacks = &CustomAttacksClient{mgmtCfg: mgmtCfg}

	return c, nil
}

// --- Convenience methods ---

// GetScanStatistics gets scan statistics from the data plane.
func (c *Client) GetScanStatistics(ctx context.Context, params map[string]string) (*ScanStatisticsResponse, error) {
	resp, err := internal.DoMgmtRequest[ScanStatisticsResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamDashboardPath + "/scan-statistics", Params: params,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetScoreTrend gets the score trend for a target.
func (c *Client) GetScoreTrend(ctx context.Context, targetID string) (*ScoreTrendResponse, error) {
	resp, err := internal.DoMgmtRequest[ScoreTrendResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamDashboardPath + "/score-trend/" + targetID,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetQuota gets the quota summary.
func (c *Client) GetQuota(ctx context.Context) (*QuotaSummary, error) {
	resp, err := internal.DoMgmtRequest[QuotaSummary](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamQuotaPath,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetErrorLogs gets error logs for a job.
func (c *Client) GetErrorLogs(ctx context.Context, jobID string, opts ListOpts) (*ErrorLogListResponse, error) {
	resp, err := internal.DoMgmtRequest[ErrorLogListResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamErrorLogPath + "/" + jobID, Params: buildListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// UpdateSentiment updates the sentiment for a job.
func (c *Client) UpdateSentiment(ctx context.Context, req SentimentRequest) (*SentimentResponse, error) {
	resp, err := internal.DoMgmtRequest[SentimentResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodPut, Path: aisec.RedTeamSentimentPath, Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetSentiment gets the sentiment for a job.
func (c *Client) GetSentiment(ctx context.Context, jobID string) (*SentimentResponse, error) {
	resp, err := internal.DoMgmtRequest[SentimentResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamSentimentPath + "/" + jobID,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetDashboardOverview gets the dashboard overview from the mgmt plane.
func (c *Client) GetDashboardOverview(ctx context.Context) (*DashboardOverviewResponse, error) {
	resp, err := internal.DoMgmtRequest[DashboardOverviewResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamMgmtDashboardPath,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// --- Scans Client (data plane) ---

// ScansClient provides red team scan operations.
type ScansClient struct {
	dataCfg *internal.OAuthServiceConfig
}

func (c *ScansClient) Create(ctx context.Context, req JobCreateRequest) (*JobResponse, error) {
	resp, err := internal.DoMgmtRequest[JobResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.RedTeamScanPath, Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ScansClient) List(ctx context.Context, opts ScanListOpts) (*JobListResponse, error) {
	resp, err := internal.DoMgmtRequest[JobListResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamScanPath, Params: buildScanListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ScansClient) Get(ctx context.Context, jobID string) (*JobResponse, error) {
	resp, err := internal.DoMgmtRequest[JobResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamScanPath + "/" + jobID,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ScansClient) Abort(ctx context.Context, jobID string) (*JobAbortResponse, error) {
	resp, err := internal.DoMgmtRequest[JobAbortResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.RedTeamScanPath + "/" + jobID + "/abort",
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ScansClient) GetCategories(ctx context.Context) ([]CategoryModel, error) {
	resp, err := internal.DoMgmtRequest[[]CategoryModel](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamCategoriesPath,
	})
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// --- Reports Client (data plane) ---

// ReportsClient provides red team report operations.
type ReportsClient struct {
	dataCfg *internal.OAuthServiceConfig
}

func (c *ReportsClient) GetStaticReport(ctx context.Context, jobID string) (*StaticJobReport, error) {
	resp, err := internal.DoMgmtRequest[StaticJobReport](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamReportStaticPath + "/" + jobID,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ReportsClient) GetDynamicReport(ctx context.Context, jobID string) (*DynamicJobReport, error) {
	resp, err := internal.DoMgmtRequest[DynamicJobReport](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamReportDynamicPath + "/" + jobID,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ReportsClient) ListAttacks(ctx context.Context, jobID string, opts AttackListOpts) (*AttackListResponse, error) {
	resp, err := internal.DoMgmtRequest[AttackListResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamReportPath + "/" + jobID + "/attacks", Params: buildAttackListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ReportsClient) GetAttackDetail(ctx context.Context, jobID, attackID string) (*AttackDetailResponse, error) {
	resp, err := internal.DoMgmtRequest[AttackDetailResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamReportPath + "/" + jobID + "/attacks/" + attackID,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ReportsClient) GetMultiTurnAttackDetail(ctx context.Context, jobID, attackID string) (*AttackMultiTurnDetailResponse, error) {
	resp, err := internal.DoMgmtRequest[AttackMultiTurnDetailResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamReportPath + "/" + jobID + "/attacks/" + attackID + "/multi-turn",
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ReportsClient) GetStaticRemediation(ctx context.Context, jobID string) (*RemediationResponse, error) {
	resp, err := internal.DoMgmtRequest[RemediationResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamReportStaticPath + "/" + jobID + "/remediation",
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ReportsClient) GetStaticRuntimePolicy(ctx context.Context, jobID string) (*RuntimePolicyConfigResponse, error) {
	resp, err := internal.DoMgmtRequest[RuntimePolicyConfigResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamReportStaticPath + "/" + jobID + "/runtime-policy-config",
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ReportsClient) GetDynamicRemediation(ctx context.Context, jobID string) (*RemediationResponse, error) {
	resp, err := internal.DoMgmtRequest[RemediationResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamReportDynamicPath + "/" + jobID + "/remediation",
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ReportsClient) GetDynamicRuntimePolicy(ctx context.Context, jobID string) (*RuntimePolicyConfigResponse, error) {
	resp, err := internal.DoMgmtRequest[RuntimePolicyConfigResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamReportDynamicPath + "/" + jobID + "/runtime-policy-config",
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ReportsClient) ListGoals(ctx context.Context, jobID string, opts GoalListOpts) (*GoalListResponse, error) {
	resp, err := internal.DoMgmtRequest[GoalListResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamReportDynamicPath + "/" + jobID + "/goals", Params: buildGoalListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ReportsClient) ListGoalStreams(ctx context.Context, jobID, goalID string, opts ListOpts) (*StreamListResponse, error) {
	resp, err := internal.DoMgmtRequest[StreamListResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamReportDynamicPath + "/" + jobID + "/goals/" + goalID + "/streams", Params: buildListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ReportsClient) GetStreamDetail(ctx context.Context, streamID string) (*StreamDetailResponse, error) {
	resp, err := internal.DoMgmtRequest[StreamDetailResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamReportPath + "/streams/" + streamID,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// DownloadReport downloads a report in the specified format.
func (c *ReportsClient) DownloadReport(ctx context.Context, jobID string, format FileFormat) ([]byte, error) {
	svcCfg := c.dataCfg
	path := aisec.RedTeamReportDownloadPath + "/" + jobID + "/download"

	u, err := url.Parse(svcCfg.BaseURL + path)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %s%s: %w", svcCfg.BaseURL, path, err)
	}
	q := u.Query()
	q.Set("file_format", string(format))
	u.RawQuery = q.Encode()

	resp, err := internal.ExecuteWithRetry(internal.RetryOptions{
		MaxRetries: svcCfg.NumRetries,
		Execute: func(attempt int) (*http.Response, error) {
			token, tokenErr := svcCfg.OAuth.GetToken()
			if tokenErr != nil {
				return nil, tokenErr
			}
			req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
			if reqErr != nil {
				return nil, reqErr
			}
			req.Header.Set("User-Agent", aisec.UserAgent)
			req.Header.Set(aisec.HeaderAuthToken, aisec.Bearer+token)
			return http.DefaultClient.Do(req)
		},
		OnRetryableFailure: func(resp *http.Response, attempt int) (bool, error) {
			if resp.StatusCode == 401 || resp.StatusCode == 403 {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				svcCfg.OAuth.ClearToken()
				return true, nil
			}
			return false, nil
		},
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, resp.Body); err != nil {
		return nil, fmt.Errorf("failed to read report body: %w", err)
	}
	return buf.Bytes(), nil
}

// --- Custom Attack Reports Client (data plane) ---

// CustomAttackReportsClient provides custom attack report operations.
type CustomAttackReportsClient struct {
	dataCfg *internal.OAuthServiceConfig
}

func (c *CustomAttackReportsClient) GetReport(ctx context.Context, jobID string) (*CustomAttackReportResponse, error) {
	resp, err := internal.DoMgmtRequest[CustomAttackReportResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamCustomAttacksReportPath + "/" + jobID,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *CustomAttackReportsClient) GetPromptSets(ctx context.Context, jobID string) (*PromptSetsReportResponse, error) {
	resp, err := internal.DoMgmtRequest[PromptSetsReportResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamCustomAttacksReportPath + "/" + jobID + "/prompt-sets",
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *CustomAttackReportsClient) GetPromptsBySet(ctx context.Context, jobID, promptSetID string, opts PromptsBySetListOpts) ([]PromptDetailResponse, error) {
	resp, err := internal.DoMgmtRequest[[]PromptDetailResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamCustomAttacksReportPath + "/" + jobID + "/prompt-sets/" + promptSetID + "/prompts",
		Params: buildPromptsBySetListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *CustomAttackReportsClient) GetPromptDetail(ctx context.Context, jobID, promptID string) (*PromptDetailResponse, error) {
	resp, err := internal.DoMgmtRequest[PromptDetailResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamCustomAttacksReportPath + "/" + jobID + "/prompts/" + promptID,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *CustomAttackReportsClient) ListCustomAttacks(ctx context.Context, jobID string, opts CustomAttacksReportListOpts) (*CustomAttacksListResponse, error) {
	resp, err := internal.DoMgmtRequest[CustomAttacksListResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamCustomAttacksReportPath + "/" + jobID + "/attacks",
		Params: buildCustomAttacksReportListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *CustomAttackReportsClient) GetAttackOutputs(ctx context.Context, jobID, attackID string) ([]CustomAttackOutput, error) {
	resp, err := internal.DoMgmtRequest[[]CustomAttackOutput](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamCustomAttacksReportPath + "/" + jobID + "/attacks/" + attackID + "/outputs",
	})
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *CustomAttackReportsClient) GetPropertyStats(ctx context.Context, jobID string) ([]PropertyStatistic, error) {
	resp, err := internal.DoMgmtRequest[[]PropertyStatistic](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamCustomAttacksReportPath + "/" + jobID + "/property-stats",
	})
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// --- Targets Client (mgmt plane) ---

// TargetsClient provides target management operations.
type TargetsClient struct {
	mgmtCfg *internal.OAuthServiceConfig
}

func (c *TargetsClient) Create(ctx context.Context, req TargetCreateRequest, validate bool) (*TargetResponse, error) {
	params := map[string]string{}
	if validate {
		params["validate"] = "true"
	}
	resp, err := internal.DoMgmtRequest[TargetResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.RedTeamTargetPath, Body: req, Params: params,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *TargetsClient) List(ctx context.Context, opts TargetListOpts) (*TargetList, error) {
	resp, err := internal.DoMgmtRequest[TargetList](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamTargetPath, Params: buildTargetListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *TargetsClient) Get(ctx context.Context, uuid string) (*TargetResponse, error) {
	resp, err := internal.DoMgmtRequest[TargetResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamTargetPath + "/" + uuid,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *TargetsClient) Update(ctx context.Context, uuid string, req TargetUpdateRequest, validate bool) (*TargetResponse, error) {
	params := map[string]string{}
	if validate {
		params["validate"] = "true"
	}
	resp, err := internal.DoMgmtRequest[TargetResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodPut, Path: aisec.RedTeamTargetPath + "/" + uuid, Body: req, Params: params,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *TargetsClient) Delete(ctx context.Context, uuid string) (*BaseResponse, error) {
	resp, err := internal.DoMgmtRequest[BaseResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodDelete, Path: aisec.RedTeamTargetPath + "/" + uuid,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *TargetsClient) Probe(ctx context.Context, req TargetProbeRequest) (*TargetResponse, error) {
	resp, err := internal.DoMgmtRequest[TargetResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.RedTeamTargetPath + "/probe", Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *TargetsClient) GetProfile(ctx context.Context, uuid string) (*TargetProfileResponse, error) {
	resp, err := internal.DoMgmtRequest[TargetProfileResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamTargetPath + "/" + uuid + "/profile",
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *TargetsClient) UpdateProfile(ctx context.Context, uuid string, req TargetContextUpdate) (*TargetResponse, error) {
	resp, err := internal.DoMgmtRequest[TargetResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodPut, Path: aisec.RedTeamTargetPath + "/" + uuid + "/context", Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// --- Custom Attacks Client (mgmt plane) ---

// CustomAttacksClient provides custom attack/prompt set management.
type CustomAttacksClient struct {
	mgmtCfg *internal.OAuthServiceConfig
}

// Prompt Set operations

func (c *CustomAttacksClient) CreatePromptSet(ctx context.Context, req CustomPromptSetCreateRequest) (*CustomPromptSetResponse, error) {
	resp, err := internal.DoMgmtRequest[CustomPromptSetResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.RedTeamCustomPromptSetPath, Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *CustomAttacksClient) ListPromptSets(ctx context.Context, opts PromptSetListOpts) (*CustomPromptSetList, error) {
	resp, err := internal.DoMgmtRequest[CustomPromptSetList](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamListCustomPromptSetsPath, Params: buildPromptSetListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *CustomAttacksClient) GetPromptSet(ctx context.Context, uuid string) (*CustomPromptSetResponse, error) {
	resp, err := internal.DoMgmtRequest[CustomPromptSetResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamCustomPromptSetPath + "/" + uuid,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *CustomAttacksClient) UpdatePromptSet(ctx context.Context, uuid string, req CustomPromptSetUpdateRequest) (*CustomPromptSetResponse, error) {
	resp, err := internal.DoMgmtRequest[CustomPromptSetResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodPut, Path: aisec.RedTeamCustomPromptSetPath + "/" + uuid, Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *CustomAttacksClient) ArchivePromptSet(ctx context.Context, uuid string, req CustomPromptSetArchiveRequest) (*CustomPromptSetResponse, error) {
	resp, err := internal.DoMgmtRequest[CustomPromptSetResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodPut, Path: aisec.RedTeamCustomPromptSetPath + "/" + uuid + "/archive", Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *CustomAttacksClient) GetPromptSetReference(ctx context.Context, uuid string) (*CustomPromptSetReference, error) {
	resp, err := internal.DoMgmtRequest[CustomPromptSetReference](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamCustomPromptSetPath + "/" + uuid + "/reference",
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *CustomAttacksClient) GetPromptSetVersionInfo(ctx context.Context, uuid string) (*CustomPromptSetVersionInfo, error) {
	resp, err := internal.DoMgmtRequest[CustomPromptSetVersionInfo](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamCustomPromptSetPath + "/" + uuid + "/version-info",
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *CustomAttacksClient) ListActivePromptSets(ctx context.Context) (*CustomPromptSetListActive, error) {
	resp, err := internal.DoMgmtRequest[CustomPromptSetListActive](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamActiveCustomPromptSetsPath,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Prompt operations

func (c *CustomAttacksClient) CreatePrompt(ctx context.Context, req CustomPromptCreateRequest) (*CustomPromptResponse, error) {
	resp, err := internal.DoMgmtRequest[CustomPromptResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.RedTeamCustomPromptSetPath + "/custom-prompt", Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *CustomAttacksClient) ListPrompts(ctx context.Context, promptSetID string, opts PromptListOpts) (*CustomPromptList, error) {
	resp, err := internal.DoMgmtRequest[CustomPromptList](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamCustomPromptSetPath + "/" + promptSetID + "/list-custom-prompts",
		Params: buildPromptListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *CustomAttacksClient) GetPrompt(ctx context.Context, promptSetID, promptID string) (*CustomPromptResponse, error) {
	resp, err := internal.DoMgmtRequest[CustomPromptResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamCustomPromptSetPath + "/" + promptSetID + "/custom-prompt/" + promptID,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *CustomAttacksClient) UpdatePrompt(ctx context.Context, promptSetID, promptID string, req CustomPromptUpdateRequest) (*CustomPromptResponse, error) {
	resp, err := internal.DoMgmtRequest[CustomPromptResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodPut, Path: aisec.RedTeamCustomPromptSetPath + "/" + promptSetID + "/custom-prompt/" + promptID, Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *CustomAttacksClient) DeletePrompt(ctx context.Context, promptSetID, promptID string) (*BaseResponse, error) {
	resp, err := internal.DoMgmtRequest[BaseResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodDelete, Path: aisec.RedTeamCustomPromptSetPath + "/" + promptSetID + "/custom-prompt/" + promptID,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Property operations

func (c *CustomAttacksClient) GetPropertyNames(ctx context.Context) (*PropertyNamesListResponse, error) {
	resp, err := internal.DoMgmtRequest[PropertyNamesListResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamCustomAttackPath + "/property-names",
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *CustomAttacksClient) CreatePropertyName(ctx context.Context, req PropertyNameCreateRequest) (*BaseResponse, error) {
	resp, err := internal.DoMgmtRequest[BaseResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.RedTeamCustomAttackPath + "/property-names", Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *CustomAttacksClient) GetPropertyValues(ctx context.Context, propertyName string) (*PropertyValuesResponse, error) {
	resp, err := internal.DoMgmtRequest[PropertyValuesResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.RedTeamCustomAttackPath + "/property-values/" + propertyName,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *CustomAttacksClient) GetPropertyValuesMultiple(ctx context.Context, propertyNames []string) (*PropertyValuesMultipleResponse, error) {
	resp, err := internal.DoMgmtRequest[PropertyValuesMultipleResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.RedTeamCustomAttackPath + "/property-values",
		Body: map[string][]string{"property_names": propertyNames},
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *CustomAttacksClient) CreatePropertyValue(ctx context.Context, req PropertyValueCreateRequest) (*BaseResponse, error) {
	resp, err := internal.DoMgmtRequest[BaseResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.RedTeamCustomAttackPath + "/property-values/create", Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// --- Param builders ---

func buildListParams(opts ListOpts) map[string]string {
	params := map[string]string{}
	if opts.Skip > 0 {
		params["skip"] = fmt.Sprintf("%d", opts.Skip)
	}
	if opts.Limit > 0 {
		params["limit"] = fmt.Sprintf("%d", opts.Limit)
	}
	if opts.Search != "" {
		params["search"] = opts.Search
	}
	return params
}

func buildScanListParams(opts ScanListOpts) map[string]string {
	params := map[string]string{}
	if opts.Skip > 0 {
		params["skip"] = fmt.Sprintf("%d", opts.Skip)
	}
	if opts.Limit > 0 {
		params["limit"] = fmt.Sprintf("%d", opts.Limit)
	}
	if opts.Search != "" {
		params["search"] = opts.Search
	}
	if opts.Status != "" {
		params["status"] = opts.Status
	}
	if opts.JobType != "" {
		params["job_type"] = opts.JobType
	}
	if opts.TargetID != "" {
		params["target_id"] = opts.TargetID
	}
	return params
}

func buildAttackListParams(opts AttackListOpts) map[string]string {
	params := map[string]string{}
	if opts.Skip > 0 {
		params["skip"] = fmt.Sprintf("%d", opts.Skip)
	}
	if opts.Limit > 0 {
		params["limit"] = fmt.Sprintf("%d", opts.Limit)
	}
	if opts.Search != "" {
		params["search"] = opts.Search
	}
	if opts.Status != "" {
		params["status"] = opts.Status
	}
	if opts.Severity != "" {
		params["severity"] = opts.Severity
	}
	if opts.Category != "" {
		params["category"] = opts.Category
	}
	if opts.SubCategory != "" {
		params["sub_category"] = opts.SubCategory
	}
	if opts.AttackType != "" {
		params["attack_type"] = opts.AttackType
	}
	if opts.Threat != nil {
		params["threat"] = fmt.Sprintf("%t", *opts.Threat)
	}
	return params
}

func buildGoalListParams(opts GoalListOpts) map[string]string {
	params := map[string]string{}
	if opts.GoalType != "" {
		params["goal_type"] = opts.GoalType
	}
	if opts.Status != "" {
		params["status"] = opts.Status
	}
	if opts.Count != nil {
		params["count"] = fmt.Sprintf("%t", *opts.Count)
	}
	return params
}

func buildTargetListParams(opts TargetListOpts) map[string]string {
	params := map[string]string{}
	if opts.Skip > 0 {
		params["skip"] = fmt.Sprintf("%d", opts.Skip)
	}
	if opts.Limit > 0 {
		params["limit"] = fmt.Sprintf("%d", opts.Limit)
	}
	if opts.Search != "" {
		params["search"] = opts.Search
	}
	if opts.TargetType != "" {
		params["target_type"] = opts.TargetType
	}
	if opts.Status != "" {
		params["status"] = opts.Status
	}
	return params
}

func buildPromptSetListParams(opts PromptSetListOpts) map[string]string {
	params := map[string]string{}
	if opts.Skip > 0 {
		params["skip"] = fmt.Sprintf("%d", opts.Skip)
	}
	if opts.Limit > 0 {
		params["limit"] = fmt.Sprintf("%d", opts.Limit)
	}
	if opts.Search != "" {
		params["search"] = opts.Search
	}
	if opts.Status != "" {
		params["status"] = opts.Status
	}
	if opts.Active != nil {
		params["active"] = fmt.Sprintf("%t", *opts.Active)
	}
	if opts.Archive != nil {
		params["archive"] = fmt.Sprintf("%t", *opts.Archive)
	}
	return params
}

func buildPromptListParams(opts PromptListOpts) map[string]string {
	params := map[string]string{}
	if opts.Skip > 0 {
		params["skip"] = fmt.Sprintf("%d", opts.Skip)
	}
	if opts.Limit > 0 {
		params["limit"] = fmt.Sprintf("%d", opts.Limit)
	}
	if opts.Search != "" {
		params["search"] = opts.Search
	}
	if opts.Active != nil {
		params["active"] = fmt.Sprintf("%t", *opts.Active)
	}
	return params
}

func buildPromptsBySetListParams(opts PromptsBySetListOpts) map[string]string {
	params := map[string]string{}
	if opts.Skip > 0 {
		params["skip"] = fmt.Sprintf("%d", opts.Skip)
	}
	if opts.Limit > 0 {
		params["limit"] = fmt.Sprintf("%d", opts.Limit)
	}
	if opts.Search != "" {
		params["search"] = opts.Search
	}
	if opts.IsThreat != nil {
		params["is_threat"] = fmt.Sprintf("%t", *opts.IsThreat)
	}
	return params
}

func buildCustomAttacksReportListParams(opts CustomAttacksReportListOpts) map[string]string {
	params := map[string]string{}
	if opts.Skip > 0 {
		params["skip"] = fmt.Sprintf("%d", opts.Skip)
	}
	if opts.Limit > 0 {
		params["limit"] = fmt.Sprintf("%d", opts.Limit)
	}
	if opts.Search != "" {
		params["search"] = opts.Search
	}
	if opts.Threat != nil {
		params["threat"] = fmt.Sprintf("%t", *opts.Threat)
	}
	if opts.PromptSetID != "" {
		params["prompt_set_id"] = opts.PromptSetID
	}
	if opts.PropertyValue != "" {
		params["property_value"] = opts.PropertyValue
	}
	return params
}
