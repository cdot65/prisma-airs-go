package agentguard

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strconv"

	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/agentguard/schema"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
)

// List calls GET /v1/scans.
func (c *ScansClient) List(ctx context.Context, opts ScanListOpts) (*schema.AgentGuardScanList, error) {
	return request[schema.AgentGuardScanList](ctx, c.cfg, http.MethodGet, aisec.AgentGuardScansPath, scanListQuery(opts), nil)
}

// Lookup calls GET /v1/scans/lookup by lowercase SHA-256 fingerprint.
func (c *ScansClient) Lookup(ctx context.Context, fingerprint string) (*schema.AgentGuardScanResponse, error) {
	if !fingerprintPattern.MatchString(fingerprint) {
		return nil, aisec.NewAISecSDKError("fingerprint must be 64 lowercase hexadecimal characters", aisec.UserRequestPayloadError)
	}
	return request[schema.AgentGuardScanResponse](ctx, c.cfg, http.MethodGet, aisec.AgentGuardScanLookupPath, url.Values{"fingerprint": {fingerprint}}, nil)
}

var fingerprintPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// UploadURL calls POST /v1/scans/upload-url without a request body. Upload the
// archive to the returned signed URL before calling UploadComplete.
func (c *ScansClient) UploadURL(ctx context.Context) (*schema.AgentGuardUploadURLResponse, error) {
	return request[schema.AgentGuardUploadURLResponse](ctx, c.cfg, http.MethodPost, aisec.AgentGuardUploadURLPath, nil, nil)
}

// Get calls GET /v1/scans/{scan_uuid}.
func (c *ScansClient) Get(ctx context.Context, scanUUID string) (*schema.AgentGuardScanResponse, error) {
	if err := validUUIDs(scanUUID); err != nil {
		return nil, err
	}
	return request[schema.AgentGuardScanResponse](ctx, c.cfg, http.MethodGet, aisec.AgentGuardScansPath+"/"+internal.PathSeg(scanUUID), nil, nil)
}

// ListAttackChains calls GET /v1/scans/{scan_uuid}/attack-chains.
func (c *ScansClient) ListAttackChains(ctx context.Context, scanUUID string, opts ListOpts) (*schema.AgentGuardAttackChainList, error) {
	if err := validUUIDs(scanUUID); err != nil {
		return nil, err
	}
	return request[schema.AgentGuardAttackChainList](ctx, c.cfg, http.MethodGet, aisec.AgentGuardScansPath+"/"+internal.PathSeg(scanUUID)+"/attack-chains", listQuery(opts), nil)
}

// GetAttackChain calls GET /v1/scans/{scan_uuid}/attack-chains/{chain_uuid}.
func (c *ScansClient) GetAttackChain(ctx context.Context, scanUUID, chainUUID string) (*schema.AgentGuardAttackChainResponse, error) {
	if err := validUUIDs(scanUUID, chainUUID); err != nil {
		return nil, err
	}
	return request[schema.AgentGuardAttackChainResponse](ctx, c.cfg, http.MethodGet, aisec.AgentGuardScansPath+"/"+internal.PathSeg(scanUUID)+"/attack-chains/"+internal.PathSeg(chainUUID), nil, nil)
}

// UploadComplete calls POST /v1/scans/{scan_uuid}/upload-complete to start
// analysis of an uploaded archive. Artifact type is a query parameter.
func (c *ScansClient) UploadComplete(ctx context.Context, scanUUID string, req schema.AgentGuardUploadCompleteRequest, opts UploadCompleteOpts) (*schema.AgentGuardUploadCompleteResponse, error) {
	if err := validUUIDs(scanUUID); err != nil {
		return nil, err
	}
	q := url.Values{}
	if opts.ArtifactType != "" {
		q.Set("artifact_type", string(opts.ArtifactType))
	}
	return request[schema.AgentGuardUploadCompleteResponse](ctx, c.cfg, http.MethodPost, aisec.AgentGuardScansPath+"/"+internal.PathSeg(scanUUID)+"/upload-complete", q, req)
}

// ListVulnerabilities calls GET /v1/scans/{scan_uuid}/vulnerabilities.
func (c *ScansClient) ListVulnerabilities(ctx context.Context, scanUUID string, opts VulnerabilityListOpts) (*schema.AgentGuardVulnerabilityList, error) {
	if err := validUUIDs(scanUUID); err != nil {
		return nil, err
	}
	q := listQuery(opts.ListOpts)
	if opts.Type != "" {
		q.Set("type", string(opts.Type))
	}
	if opts.InChain != nil {
		q.Set("in_chain", strconv.FormatBool(*opts.InChain))
	}
	return request[schema.AgentGuardVulnerabilityList](ctx, c.cfg, http.MethodGet, aisec.AgentGuardScansPath+"/"+internal.PathSeg(scanUUID)+"/vulnerabilities", q, nil)
}

// Rules calls GET /v1/stats/rules. An empty period retains the server default.
func (c *StatisticsClient) Rules(ctx context.Context, period schema.TimePeriod) (*schema.AgentGuardSkillStatsResponse, error) {
	return request[schema.AgentGuardSkillStatsResponse](ctx, c.cfg, http.MethodGet, aisec.AgentGuardRuleStatsPath, periodQuery(period), nil)
}

// Scans calls GET /v1/stats/scans. An empty period retains the server default.
func (c *StatisticsClient) Scans(ctx context.Context, period schema.TimePeriod) (*schema.AgentGuardScanStatsResponse, error) {
	return request[schema.AgentGuardScanStatsResponse](ctx, c.cfg, http.MethodGet, aisec.AgentGuardScanStatsPath, periodQuery(period), nil)
}

func periodQuery(period schema.TimePeriod) url.Values {
	q := url.Values{}
	if period != "" {
		q.Set("time_period", string(period))
	}
	return q
}
