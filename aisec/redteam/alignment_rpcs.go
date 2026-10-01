package redteam

import (
	"context"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	"github.com/cdot65/prisma-airs-go/aisec/redteam/schema"
	"net/http"
	"strconv"
)

// GetLanguages calls the current data-plane contract.
func (c *Client) GetLanguages(ctx context.Context) (*schema.TenantLanguagesResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.TenantLanguagesResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamLanguagesPath})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetGoalCategories calls the current data-plane contract.
func (c *Client) GetGoalCategories(ctx context.Context, targetType string) (*schema.GoalCategoryListResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.GoalCategoryListResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamGoalCategoriesPath + "/" + seg(targetType)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetMetadata calls the current data-plane contract.
func (c *ScansClient) GetMetadata(ctx context.Context) (map[string]any, error) {
	resp, err := internal.DoMgmtRequest[map[string]any](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamScanPath + "/scan-metadata"})
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// SetRuntimeProfile calls the current data-plane contract.
func (c *ScansClient) SetRuntimeProfile(ctx context.Context, jobID string, req schema.RuntimeProfileUpdateRequest) (*schema.JobResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.JobResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.RedTeamScanPath + "/" + seg(jobID) + "/runtime-profile", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetStaticASR calls the current data-plane contract.
func (c *ReportsClient) GetStaticASR(ctx context.Context, jobID string) (*schema.ASRResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.ASRResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamReportStaticPath + "/" + seg(jobID) + "/asr"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetDynamicASR calls the current data-plane contract.
func (c *ReportsClient) GetDynamicASR(ctx context.Context, jobID string) (*schema.ASRResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.ASRResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamReportDynamicPath + "/" + seg(jobID) + "/asr"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetStatus calls the current data-plane contract.
func (c *ReportsClient) GetStatus(ctx context.Context, jobID string) (*schema.ReportStatusResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.ReportStatusResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamReportPath + "/" + seg(jobID) + "/status"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Regenerate calls the current data-plane contract.
func (c *ReportsClient) Regenerate(ctx context.Context, jobID string) (*schema.RegenerateResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.RegenerateResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.RedTeamReportPath + "/" + seg(jobID) + "/regenerate"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetDownload returns a short-lived download URL and filename without following the URL.
func (c *ReportsClient) GetDownload(ctx context.Context, jobID string, format FileFormat) (*schema.ReportDownload, error) {
	resp, err := internal.DoMgmtRequest[schema.ReportDownload](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamReportV2Path + "/" + seg(jobID) + "/download", Params: map[string]string{"file_format": string(format)}})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// OverrideAttackThreat calls the current data-plane contract.
func (c *ReportsClient) OverrideAttackThreat(ctx context.Context, jobID string, attackID string, req schema.ThreatOverrideRequest) (*schema.ThreatOverrideResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.ThreatOverrideResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.RedTeamReportStaticPath + "/" + seg(jobID) + "/attack/" + seg(attackID) + "/override", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// OverrideMultiTurnThreat calls the current data-plane contract.
func (c *ReportsClient) OverrideMultiTurnThreat(ctx context.Context, jobID string, attackID string, req schema.ThreatOverrideRequest) (*schema.ThreatOverrideResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.ThreatOverrideResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.RedTeamReportStaticPath + "/" + seg(jobID) + "/attack-multi-turn/" + seg(attackID) + "/override", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// OverrideStreamThreat calls the current data-plane contract.
func (c *ReportsClient) OverrideStreamThreat(ctx context.Context, jobID string, streamID string, req schema.ThreatOverrideRequest) (*schema.ThreatOverrideResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.ThreatOverrideResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.RedTeamReportDynamicPath + "/" + seg(jobID) + "/stream/" + seg(streamID) + "/override", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// OverrideThreat calls the current data-plane contract.
func (c *CustomAttackReportsClient) OverrideThreat(ctx context.Context, jobID string, attackID string, req schema.ThreatOverrideRequest) (*schema.ThreatOverrideResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.ThreatOverrideResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.RedTeamCustomAttacksReportPath + "/job/" + seg(jobID) + "/attack/" + seg(attackID) + "/override", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// DownloadErrorLogs calls the current data-plane contract.
func (c *Client) DownloadErrorLogs(ctx context.Context, jobID string) ([]byte, error) {
	resp, err := internal.DoMgmtRaw(ctx, c.dataCfg, internal.RawMgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamErrorLogPath + "/" + seg(jobID) + "/download"})
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// GetTargetProfileErrorLogs calls the current data-plane contract.
func (c *Client) GetTargetProfileErrorLogs(ctx context.Context, targetID string, limit int) (*schema.ErrorLogListResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.ErrorLogListResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamTargetProfileErrorLogPath + "/" + seg(targetID), Params: profileLogParams(limit)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetLanguages calls the current mgmt-plane contract.
func (c *TargetsClient) GetLanguages(ctx context.Context) (*schema.TenantLanguagesResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.TenantLanguagesResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamLanguagesPath})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// StartProfiling calls the current mgmt-plane contract.
func (c *TargetsClient) StartProfiling(ctx context.Context, uuid string) (*schema.StartProfilingResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.StartProfilingResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.RedTeamTargetPath + "/" + seg(uuid) + "/profile"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetCopilotAuthURL calls the current mgmt-plane contract.
func (c *TargetsClient) GetCopilotAuthURL(ctx context.Context, req schema.MSCopilotStudioAuthURLRequest) (*schema.MSCopilotStudioAuthURLResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.MSCopilotStudioAuthURLResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.RedTeamTargetPath + "/ms-copilot-studio/auth-url", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ExchangeCopilotToken calls the current mgmt-plane contract.
func (c *TargetsClient) ExchangeCopilotToken(ctx context.Context, req schema.MSCopilotStudioTokenRequest) (*schema.MSCopilotStudioTokenResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.MSCopilotStudioTokenResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.RedTeamTargetPath + "/ms-copilot-studio/token", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// DeleteCopilotToken calls the current mgmt-plane contract.
func (c *TargetsClient) DeleteCopilotToken(ctx context.Context, uuid string) error {
	_, err := internal.DoMgmtRequest[any](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodDelete, Path: aisec.RedTeamTargetPath + "/ms-copilot-studio/token/" + seg(uuid), ResponsePolicy: internal.AllowEmptyJSON})
	return err
}

func profileLogParams(limit int) map[string]string {
	params := map[string]string{}
	if limit > 0 {
		params["limit"] = strconv.Itoa(limit)
	}
	return params
}
