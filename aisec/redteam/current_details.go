package redteam

import (
	"context"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	"github.com/cdot65/prisma-airs-go/aisec/redteam/schema"
	"net/http"
	"strconv"
	"strings"
)

// CreateDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *ScansClient) CreateDetails(ctx context.Context, req schema.JobCreateRequest) (*schema.JobResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.JobResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.RedTeamScanPath, Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *ScansClient) ListDetails(ctx context.Context, opts ScanListOpts) (*schema.JobListResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.JobListResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamScanPath, Params: buildScanListParams(opts)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *ScansClient) GetDetails(ctx context.Context, jobID string) (*schema.JobResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.JobResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamScanPath + "/" + seg(jobID)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// AbortDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *ScansClient) AbortDetails(ctx context.Context, jobID string) (*schema.JobAbortResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.JobAbortResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.RedTeamScanPath + "/" + seg(jobID) + "/abort"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetCategoriesDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *ScansClient) GetCategoriesDetails(ctx context.Context) ([]schema.CategoryModel, error) {
	resp, err := internal.DoMgmtRequest[[]schema.CategoryModel](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamCategoriesPath})
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// GetStaticReportDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *ReportsClient) GetStaticReportDetails(ctx context.Context, jobID string) (*schema.StaticJobReport, error) {
	resp, err := internal.DoMgmtRequest[schema.StaticJobReport](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamReportStaticPath + "/" + seg(jobID) + "/report"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetDynamicReportDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *ReportsClient) GetDynamicReportDetails(ctx context.Context, jobID string) (*schema.DynamicJobReport, error) {
	resp, err := internal.DoMgmtRequest[schema.DynamicJobReport](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamReportDynamicPath + "/" + seg(jobID) + "/report"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetStaticRemediationDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *ReportsClient) GetStaticRemediationDetails(ctx context.Context, jobID string) (*schema.RemediationResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.RemediationResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamReportStaticPath + "/" + seg(jobID) + "/remediation"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetDynamicRemediationDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *ReportsClient) GetDynamicRemediationDetails(ctx context.Context, jobID string) (*schema.DynamicRemediationResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.DynamicRemediationResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamReportDynamicPath + "/" + seg(jobID) + "/remediation"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetStaticRuntimePolicyDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *ReportsClient) GetStaticRuntimePolicyDetails(ctx context.Context, jobID string) (*schema.RuntimeSecurityProfileResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.RuntimeSecurityProfileResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamReportStaticPath + "/" + seg(jobID) + "/runtime-policy-config"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetDynamicRuntimePolicyDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *ReportsClient) GetDynamicRuntimePolicyDetails(ctx context.Context, jobID string) (*schema.RuntimeSecurityProfileResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.RuntimeSecurityProfileResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamReportDynamicPath + "/" + seg(jobID) + "/runtime-policy-config"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListAttacksDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *ReportsClient) ListAttacksDetails(ctx context.Context, jobID string, opts AttackListOpts) (*schema.AttackListResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.AttackListResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamReportStaticPath + "/" + seg(jobID) + "/list-attacks", Params: currentAttackParams(opts)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetAttackDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *ReportsClient) GetAttackDetails(ctx context.Context, jobID string, attackID string) (*schema.AttackDetailResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.AttackDetailResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamReportStaticPath + "/" + seg(jobID) + "/attack/" + seg(attackID)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetMultiTurnAttackDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *ReportsClient) GetMultiTurnAttackDetails(ctx context.Context, jobID string, attackID string) (*schema.AttackMultiTurnDetailResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.AttackMultiTurnDetailResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamReportStaticPath + "/" + seg(jobID) + "/attack-multi-turn/" + seg(attackID)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListGoalsDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *ReportsClient) ListGoalsDetails(ctx context.Context, jobID string, opts GoalListOpts) (*schema.GoalListResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.GoalListResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamReportDynamicPath + "/" + seg(jobID) + "/list-goals", Params: buildGoalListParams(opts)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListGoalStreamsDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *ReportsClient) ListGoalStreamsDetails(ctx context.Context, jobID string, goalID string) (*schema.StreamListResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.StreamListResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamReportDynamicPath + "/" + seg(jobID) + "/goal/" + seg(goalID) + "/list-streams"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetStreamDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *ReportsClient) GetStreamDetails(ctx context.Context, streamID string) (*schema.StreamDetailResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.StreamDetailResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamReportDynamicPath + "/stream/" + seg(streamID)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GeneratePartialReportDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *ReportsClient) GeneratePartialReportDetails(ctx context.Context, jobID string) (any, error) {
	resp, err := internal.DoMgmtRequest[any](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.RedTeamReportPath + "/" + seg(jobID) + "/generate-partial-report"})
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// GetReportDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *CustomAttackReportsClient) GetReportDetails(ctx context.Context, jobID string) (*schema.CustomAttackReportResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.CustomAttackReportResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamCustomAttacksReportPath + "/report/" + seg(jobID)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetPromptSetsDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *CustomAttackReportsClient) GetPromptSetsDetails(ctx context.Context, jobID string, opts PromptSetsReportOpts) (*schema.PromptSetsReportResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.PromptSetsReportResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamCustomAttacksReportPath + "/report/" + seg(jobID) + "/prompt-sets", Params: promptSetsReportParams(opts)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetPromptsBySetDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *CustomAttackReportsClient) GetPromptsBySetDetails(ctx context.Context, jobID string, promptSetID string, opts PromptsBySetListOpts) ([]schema.PromptDetailResponse, error) {
	resp, err := internal.DoMgmtRequest[[]schema.PromptDetailResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamCustomAttacksReportPath + "/report/" + seg(jobID) + "/prompt-set/" + seg(promptSetID) + "/prompts", Params: currentPromptsBySetParams(opts)})
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// GetPromptDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *CustomAttackReportsClient) GetPromptDetails(ctx context.Context, jobID string, promptID string) (*schema.PromptDetailResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.PromptDetailResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamCustomAttacksReportPath + "/report/" + seg(jobID) + "/prompt/" + seg(promptID)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListCustomAttacksDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *CustomAttackReportsClient) ListCustomAttacksDetails(ctx context.Context, jobID string, opts CustomAttacksReportListOpts) (*schema.CustomAttacksListResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.CustomAttacksListResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamCustomAttacksReportPath + "/job/" + seg(jobID) + "/list-custom-attacks", Params: currentCustomAttacksParams(opts)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetAttackOutputsDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *CustomAttackReportsClient) GetAttackOutputsDetails(ctx context.Context, jobID string, attackID string) ([]schema.CustomAttackOutputResponse, error) {
	resp, err := internal.DoMgmtRequest[[]schema.CustomAttackOutputResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamCustomAttacksReportPath + "/job/" + seg(jobID) + "/attack/" + seg(attackID) + "/list-outputs"})
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// GetPropertyStatsDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *CustomAttackReportsClient) GetPropertyStatsDetails(ctx context.Context, jobID string) ([]map[string]any, error) {
	resp, err := internal.DoMgmtRequest[[]map[string]any](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamCustomAttacksReportPath + "/job/" + seg(jobID) + "/property-stats"})
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// GetQuotaDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *Client) GetQuotaDetails(ctx context.Context) (*schema.QuotaSummary, error) {
	resp, err := internal.DoMgmtRequest[schema.QuotaSummary](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamQuotaPath})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetErrorLogsDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *Client) GetErrorLogsDetails(ctx context.Context, jobID string, opts ListOpts) (*schema.ErrorLogListResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.ErrorLogListResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamErrorLogPath + "/" + seg(jobID), Params: currentPagingParams(opts.Skip, opts.Limit)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetScanStatisticsDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *Client) GetScanStatisticsDetails(ctx context.Context) (*schema.ScanStatisticsResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.ScanStatisticsResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamDashboardPath + "/scan-statistics"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetScoreTrendDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *Client) GetScoreTrendDetails(ctx context.Context, targetID string, opts ScoreTrendOpts) (*schema.ScoreTrendResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.ScoreTrendResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamDashboardPath + "/score-trend", Params: scoreTrendParams(targetID, opts)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// UpdateSentimentDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *Client) UpdateSentimentDetails(ctx context.Context, req schema.SentimentRequest) (*schema.SentimentResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.SentimentResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.RedTeamSentimentPath, Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetSentimentDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *Client) GetSentimentDetails(ctx context.Context, jobID string) (*schema.SentimentResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.SentimentResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamSentimentPath + "/" + seg(jobID)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetDashboardOverviewDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *Client) GetDashboardOverviewDetails(ctx context.Context) (*schema.DashboardOverviewResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.DashboardOverviewResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamMgmtDashboardPath})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// CreateDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *TargetsClient) CreateDetails(ctx context.Context, req schema.TargetCreateRequest, validate bool) (*schema.TargetResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.TargetResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.RedTeamTargetPath, Params: map[string]string{"validate": strconv.FormatBool(validate)}, Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *TargetsClient) ListDetails(ctx context.Context, opts TargetListOpts) (*schema.TargetList, error) {
	resp, err := internal.DoMgmtRequest[schema.TargetList](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamTargetPath, Params: buildTargetListParams(opts)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *TargetsClient) GetDetails(ctx context.Context, uuid string) (*schema.TargetRedact, error) {
	resp, err := internal.DoMgmtRequest[schema.TargetRedact](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamTargetPath + "/" + seg(uuid)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// UpdateDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *TargetsClient) UpdateDetails(ctx context.Context, uuid string, req schema.TargetUpdateRequest, validate bool) (*schema.Target, error) {
	resp, err := internal.DoMgmtRequest[schema.Target](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.RedTeamTargetPath + "/" + seg(uuid), Params: map[string]string{"validate": strconv.FormatBool(validate)}, Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ProbeDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *TargetsClient) ProbeDetails(ctx context.Context, req schema.TargetProbeRequest) (*schema.TargetResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.TargetResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.RedTeamTargetPath + "/probe", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetProfileDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *TargetsClient) GetProfileDetails(ctx context.Context, uuid string) (*schema.TargetProfileResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.TargetProfileResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamTargetPath + "/" + seg(uuid) + "/profile"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// UpdateProfileDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *TargetsClient) UpdateProfileDetails(ctx context.Context, uuid string, req schema.TargetContextUpdate) (*schema.Target, error) {
	resp, err := internal.DoMgmtRequest[schema.Target](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.RedTeamTargetPath + "/" + seg(uuid) + "/profile", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ValidateAuthDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *TargetsClient) ValidateAuthDetails(ctx context.Context, req schema.TargetAuthValidationRequest) (*schema.TargetAuthValidationResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.TargetAuthValidationResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.RedTeamTargetValidateAuthPath, Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// CreatePromptSetDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *CustomAttacksClient) CreatePromptSetDetails(ctx context.Context, req schema.CustomPromptSetCreateRequest) (*schema.CustomPromptSetResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.CustomPromptSetResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.RedTeamCustomPromptSetPath, Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListPromptSetsDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *CustomAttacksClient) ListPromptSetsDetails(ctx context.Context, opts PromptSetListOpts) (*schema.CustomPromptSetList, error) {
	resp, err := internal.DoMgmtRequest[schema.CustomPromptSetList](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamListCustomPromptSetsPath, Params: buildPromptSetListParams(opts)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetPromptSetDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *CustomAttacksClient) GetPromptSetDetails(ctx context.Context, uuid string) (*schema.CustomPromptSetResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.CustomPromptSetResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamCustomPromptSetPath + "/" + seg(uuid)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// UpdatePromptSetDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *CustomAttacksClient) UpdatePromptSetDetails(ctx context.Context, uuid string, req schema.CustomPromptSetUpdateRequest) (*schema.CustomPromptSetResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.CustomPromptSetResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.RedTeamCustomPromptSetPath + "/" + seg(uuid), Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ArchivePromptSetDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *CustomAttacksClient) ArchivePromptSetDetails(ctx context.Context, uuid string, req schema.CustomPromptSetArchiveRequest) (*schema.CustomPromptSetResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.CustomPromptSetResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.RedTeamCustomPromptSetPath + "/" + seg(uuid) + "/archive", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetPromptSetReferenceDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *CustomAttacksClient) GetPromptSetReferenceDetails(ctx context.Context, uuid string) (*schema.CustomPromptSetReference, error) {
	resp, err := internal.DoMgmtRequest[schema.CustomPromptSetReference](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamCustomPromptSetPath + "/" + seg(uuid) + "/reference"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetPromptSetVersionInfoDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *CustomAttacksClient) GetPromptSetVersionInfoDetails(ctx context.Context, uuid string, version string) (*schema.CustomPromptSetVersionInfo, error) {
	resp, err := internal.DoMgmtRequest[schema.CustomPromptSetVersionInfo](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamCustomPromptSetPath + "/" + seg(uuid) + "/version-info", Params: map[string]string{"version": version}})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListActivePromptSetsDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *CustomAttacksClient) ListActivePromptSetsDetails(ctx context.Context) (*schema.CustomPromptSetListActive, error) {
	resp, err := internal.DoMgmtRequest[schema.CustomPromptSetListActive](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamActiveCustomPromptSetsPath})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// CreatePromptDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *CustomAttacksClient) CreatePromptDetails(ctx context.Context, req schema.CustomPromptCreateRequest) (*schema.CustomPromptResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.CustomPromptResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.RedTeamCustomPromptSetPath + "/custom-prompt", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListPromptsDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *CustomAttacksClient) ListPromptsDetails(ctx context.Context, uuid string, opts PromptListOpts) (*schema.CustomPromptList, error) {
	resp, err := internal.DoMgmtRequest[schema.CustomPromptList](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamCustomPromptSetPath + "/" + seg(uuid) + "/list-custom-prompts", Params: buildPromptListParams(opts)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetPromptDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *CustomAttacksClient) GetPromptDetails(ctx context.Context, uuid string, promptID string) (*schema.CustomPromptResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.CustomPromptResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamCustomPromptSetPath + "/" + seg(uuid) + "/custom-prompt/" + seg(promptID)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// UpdatePromptDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *CustomAttacksClient) UpdatePromptDetails(ctx context.Context, uuid string, promptID string, req schema.CustomPromptUpdateRequest) (*schema.CustomPromptResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.CustomPromptResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.RedTeamCustomPromptSetPath + "/" + seg(uuid) + "/custom-prompt/" + seg(promptID), Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetPropertyNamesDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *CustomAttacksClient) GetPropertyNamesDetails(ctx context.Context) (*schema.PropertyNamesListResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.PropertyNamesListResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamCustomAttackPath + "/property-names"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// CreatePropertyNameDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *CustomAttacksClient) CreatePropertyNameDetails(ctx context.Context, req schema.PropertyNameCreateRequest) (*schema.PropertyNamesListResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.PropertyNamesListResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.RedTeamCustomAttackPath + "/property-names", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetPropertyValuesDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *CustomAttacksClient) GetPropertyValuesDetails(ctx context.Context, name string) (*schema.PropertyValuesResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.PropertyValuesResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamCustomAttackPath + "/property-values/" + seg(name)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetPropertyValuesMultipleDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *CustomAttacksClient) GetPropertyValuesMultipleDetails(ctx context.Context, names []string) (*schema.PropertyValuesMultipleResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.PropertyValuesMultipleResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamCustomAttackPath + "/property-values", Params: map[string]string{"property_names": strings.Join(names, ",")}})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// CreatePropertyValueDetails returns the complete current-schema response while the legacy method retains its existing type.
func (c *CustomAttacksClient) CreatePropertyValueDetails(ctx context.Context, req schema.PropertyValueCreateRequest) (*schema.BaseResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.BaseResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.RedTeamCustomAttackPath + "/property-values", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func currentAttackParams(opts AttackListOpts) map[string]string {
	p := buildAttackListParams(opts)
	delete(p, "search")
	return p
}
func currentPromptsBySetParams(opts PromptsBySetListOpts) map[string]string {
	p := buildPromptsBySetListParams(opts)
	delete(p, "search")
	return p
}
func currentCustomAttacksParams(opts CustomAttacksReportListOpts) map[string]string {
	p := buildCustomAttacksReportListParams(opts)
	delete(p, "search")
	return p
}
func currentPagingParams(skip, limit int) map[string]string {
	return buildListParams(ListOpts{Skip: skip, Limit: limit})
}
func promptSetsReportParams(opts PromptSetsReportOpts) map[string]string {
	p := currentPagingParams(opts.Skip, opts.Limit)
	if opts.PropertyFilters != "" {
		p["property_filters"] = opts.PropertyFilters
	}
	if opts.IsThreat != nil {
		p["is_threat"] = strconv.FormatBool(*opts.IsThreat)
	}
	return p
}
func scoreTrendParams(targetID string, opts ScoreTrendOpts) map[string]string {
	p := map[string]string{"target_id": targetID}
	if opts.DateRange != "" {
		p["date_range"] = string(opts.DateRange)
	}
	if opts.StartDate != "" {
		p["start_date"] = opts.StartDate
	}
	if opts.EndDate != "" {
		p["end_date"] = opts.EndDate
	}
	return p
}
