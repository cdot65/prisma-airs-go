package scan

import (
	"context"
	"fmt"
	"strings"

	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
)

// SyncScanOpts are optional parameters for SyncScan.
type SyncScanOpts struct {
	TrID      string
	SessionID string
	Metadata  *Metadata
}

// Scanner is the client for AIRS scan operations.
type Scanner struct {
	cfg *aisec.Config
}

// NewScanner creates a new Scanner with the given configuration.
func NewScanner(cfg *aisec.Config) *Scanner {
	return &Scanner{cfg: cfg}
}

// SyncScan performs a synchronous content scan.
func (s *Scanner) SyncScan(ctx context.Context, profile AiProfile, content *Content, opts ...SyncScanOpts) (*ScanResponse, error) {
	var opt SyncScanOpts
	if len(opts) > 0 {
		opt = opts[0]
	}

	if opt.TrID != "" && len(opt.TrID) > aisec.MaxTransactionIDLength {
		return nil, aisec.NewAISecSDKError(
			fmt.Sprintf("trId exceeds max length of %d", aisec.MaxTransactionIDLength),
			aisec.UserRequestPayloadError,
		)
	}
	if opt.SessionID != "" && len(opt.SessionID) > aisec.MaxSessionIDLength {
		return nil, aisec.NewAISecSDKError(
			fmt.Sprintf("sessionId exceeds max length of %d", aisec.MaxSessionIDLength),
			aisec.UserRequestPayloadError,
		)
	}

	body := map[string]any{
		"ai_profile": profile,
		"contents":   []ContentInner{content.ToJSON()},
	}
	if opt.TrID != "" {
		body["tr_id"] = opt.TrID
	}
	if opt.SessionID != "" {
		body["session_id"] = opt.SessionID
	}
	if opt.Metadata != nil {
		body["metadata"] = opt.Metadata
	}

	resp, err := internal.DoRequest[ScanResponse](ctx, s.cfg, internal.RequestOptions{
		Method: "POST",
		Path:   aisec.SyncScanPath,
		Body:   body,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// AsyncScan submits content for asynchronous scanning (1-5 items).
func (s *Scanner) AsyncScan(ctx context.Context, objects []AsyncScanObject) (*AsyncScanResponse, error) {
	if len(objects) < 1 {
		return nil, aisec.NewAISecSDKError("at least 1 scan object is required", aisec.UserRequestPayloadError)
	}
	if len(objects) > aisec.MaxNumberOfBatchScanObjects {
		return nil, aisec.NewAISecSDKError(
			fmt.Sprintf("max of %d scan objects allowed", aisec.MaxNumberOfBatchScanObjects),
			aisec.UserRequestPayloadError,
		)
	}

	resp, err := internal.DoRequest[AsyncScanResponse](ctx, s.cfg, internal.RequestOptions{
		Method: "POST",
		Path:   aisec.AsyncScanPath,
		Body:   objects,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// QueryByScanIDs queries scan results by scan UUIDs (1-5 items).
func (s *Scanner) QueryByScanIDs(ctx context.Context, scanIDs []string) ([]ScanIDResult, error) {
	if len(scanIDs) < 1 {
		return nil, aisec.NewAISecSDKError("at least 1 scan_id is required", aisec.UserRequestPayloadError)
	}
	if len(scanIDs) > aisec.MaxNumberOfScanIDs {
		return nil, aisec.NewAISecSDKError(
			fmt.Sprintf("max of %d scan_ids allowed", aisec.MaxNumberOfScanIDs),
			aisec.UserRequestPayloadError,
		)
	}
	for _, id := range scanIDs {
		if !aisec.IsValidUUID(id) {
			return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid scan_id: %s", id), aisec.UserRequestPayloadError)
		}
	}

	resp, err := internal.DoRequest[[]ScanIDResult](ctx, s.cfg, internal.RequestOptions{
		Method: "GET",
		Path:   aisec.ScanResultsPath,
		Params: map[string]string{"scan_ids": strings.Join(scanIDs, ",")},
	})
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// QueryByReportIDs queries detailed threat reports by report IDs (1-5 items).
func (s *Scanner) QueryByReportIDs(ctx context.Context, reportIDs []string) ([]ThreatScanReport, error) {
	if len(reportIDs) < 1 {
		return nil, aisec.NewAISecSDKError("at least 1 report_id is required", aisec.UserRequestPayloadError)
	}
	if len(reportIDs) > aisec.MaxNumberOfReportIDs {
		return nil, aisec.NewAISecSDKError(
			fmt.Sprintf("max of %d report_ids allowed", aisec.MaxNumberOfReportIDs),
			aisec.UserRequestPayloadError,
		)
	}

	resp, err := internal.DoRequest[[]ThreatScanReport](ctx, s.cfg, internal.RequestOptions{
		Method: "GET",
		Path:   aisec.ScanReportsPath,
		Params: map[string]string{"report_ids": strings.Join(reportIDs, ",")},
	})
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}
