package agentguard

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/cdot65/prisma-airs-go/aisec/agentguard/schema"
)

// Opts configures SCM OAuth and the two AgentGuard service endpoints.
// Endpoints resolve from options, then PANW_AGENT_GUARD_*_ENDPOINT; both are
// required. Credentials fall back from PANW_AGENT_GUARD_* to PANW_MGMT_*.
type Opts struct {
	ClientID      string
	ClientSecret  string
	TsgID         string
	DataEndpoint  string
	MgmtEndpoint  string
	TokenEndpoint string
	NumRetries    int
	HTTPClient    *http.Client
}

// ListOpts controls pagination. Zero values omit parameters and retain server
// defaults. A nonzero Limit sends Skip even when zero. Endpoints have different
// default limits: scans/rules 10, overrides 50, findings/attack chains 500.
type ListOpts struct {
	Limit int
	Skip  int
}

// ScanFilter contains filters shared by scan listing and CSV export. Slice
// filters are encoded as repeated query parameters. Times are RFC3339 strings.
type ScanFilter struct {
	SortOrder     schema.SortDirection
	SearchQuery   string
	Status        schema.AgentGuardScanStatus
	ArtifactType  schema.ArtifactType
	Statuses      []schema.AgentGuardScanStatus
	ArtifactTypes []schema.ArtifactType
	StartTime     string
	EndTime       string
	Fingerprint   string
}

// ScanListOpts filters and paginates scans.
type ScanListOpts struct {
	// IsBackgroundRefresh preserves the captured browser refresh flag, including false.
	IsBackgroundRefresh *bool
	ListOpts
	ScanFilter
}

// VulnerabilityListOpts filters scan findings. InChain distinguishes omission
// from explicit false, which selects findings outside attack chains.
type VulnerabilityListOpts struct {
	ListOpts
	Type    schema.VulnerabilityType
	InChain *bool
}

// SkillOverrideListOpts filters trusted skills. Q is the broad search parameter;
// when provided, the server requires at least three characters.
type SkillOverrideListOpts struct {
	ListOpts
	SkillName   string
	Fingerprint string
	TrustedBy   string
	Q           string
}

// UploadCompleteOpts optionally skips artifact type auto-detection.
type UploadCompleteOpts struct{ ArtifactType schema.ArtifactType }

// CSVExport contains the bytes and response headers returned by the configured
// HTTP transport. The preview documents gzip-compressed CSV; Content-Encoding
// decompression follows the configured http.Client's transport behavior.
type CSVExport struct {
	Body   []byte
	Header http.Header
}

func listQuery(opts ListOpts) url.Values {
	q := url.Values{}
	if opts.Limit != 0 {
		q.Set("limit", strconv.Itoa(opts.Limit))
	}
	if opts.Skip != 0 || opts.Limit != 0 {
		q.Set("skip", strconv.Itoa(opts.Skip))
	}
	return q
}

func scanQuery(opts ScanFilter) url.Values {
	q := url.Values{}
	for key, value := range map[string]string{"sort_order": string(opts.SortOrder), "search_query": opts.SearchQuery, "status": string(opts.Status), "artifact_type": string(opts.ArtifactType), "start_time": opts.StartTime, "end_time": opts.EndTime, "fingerprint": opts.Fingerprint} {
		if value != "" {
			q.Set(key, value)
		}
	}
	for _, v := range opts.Statuses {
		q.Add("statuses", string(v))
	}
	for _, v := range opts.ArtifactTypes {
		q.Add("artifact_types", string(v))
	}
	return q
}

func scanListQuery(opts ScanListOpts) url.Values {
	q := scanQuery(opts.ScanFilter)
	if opts.IsBackgroundRefresh != nil {
		q.Set("isBackgroundRefresh", strconv.FormatBool(*opts.IsBackgroundRefresh))
	}
	for key, values := range listQuery(opts.ListOpts) {
		q[key] = values
	}
	return q
}
