package redteam

// --- Dashboard / Statistics types ---

// CountByName is a name+count pair for statistics.
type CountByName struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// RiskLevel is a level+count pair for risk profiles.
type RiskLevel struct {
	Level string `json:"level"`
	Count int    `json:"count"`
}

// ScanStatisticsResponse is the scan statistics response.
type ScanStatisticsResponse struct {
	TotalScans           int           `json:"total_scans"`
	TargetsScanned       int           `json:"targets_scanned"`
	TargetsScannedByType []CountByName `json:"targets_scanned_by_type,omitempty"`
	ScanStatus           []CountByName `json:"scan_status,omitempty"`
	RiskProfile          []RiskLevel   `json:"risk_profile,omitempty"`
}

// ScoreTrendSeries is one data series in a score trend.
type ScoreTrendSeries struct {
	Label string    `json:"label"`
	Data  []float64 `json:"data"`
}

// ScoreTrendResponse is the score trend response.
type ScoreTrendResponse struct {
	Labels []string           `json:"labels,omitempty"`
	Series []ScoreTrendSeries `json:"series,omitempty"`
}

// QuotaDetails holds quota details for a specific scan type.
type QuotaDetails struct {
	Allocated int  `json:"allocated"`
	Unlimited bool `json:"unlimited"`
	Consumed  int  `json:"consumed"`
}

// QuotaSummary is the quota summary organized by scan type.
type QuotaSummary struct {
	Static  QuotaDetails `json:"static"`
	Dynamic QuotaDetails `json:"dynamic"`
	Custom  QuotaDetails `json:"custom"`
}

// ErrorLog represents a single error log entry.
type ErrorLog struct {
	JobID        string `json:"job_id,omitempty"`
	TargetID     string `json:"target_id,omitempty"`
	ErrorSource  string `json:"error_source,omitempty"`
	ErrorType    string `json:"error_type,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
	CreatedAt    string `json:"created_at,omitempty"`
}

// ErrorLogListResponse is the paginated list of error logs.
type ErrorLogListResponse struct {
	Data       []ErrorLog        `json:"data"`
	Pagination RedTeamPagination `json:"pagination"`
}

// SentimentRequest is the request to update sentiment.
type SentimentRequest struct {
	JobID     string `json:"job_id"`
	Sentiment string `json:"sentiment"`
}

// SentimentResponse is the sentiment response.
type SentimentResponse struct {
	JobID     string `json:"job_id,omitempty"`
	Sentiment string `json:"sentiment,omitempty"`
}

// DashboardOverviewResponse is the dashboard overview.
type DashboardOverviewResponse struct {
	Overview map[string]any `json:"overview,omitempty"`
}

// BaseResponse is a generic base response.
type BaseResponse struct {
	Message string `json:"message,omitempty"`
}

// --- List Options ---

// ListOpts are base pagination options.
type ListOpts struct {
	Skip   int
	Limit  int
	Search string
}

// ScanListOpts extends ListOpts with scan-specific filters.
type ScanListOpts struct {
	Skip     int
	Limit    int
	Search   string
	Status   string
	JobType  string
	TargetID string
}

// AttackListOpts are options for listing attacks.
type AttackListOpts struct {
	Skip        int
	Limit       int
	Search      string
	Status      string
	Severity    string
	Category    string
	SubCategory string
	AttackType  string
	Threat      *bool
}

// GoalListOpts are options for listing goals.
type GoalListOpts struct {
	GoalType string
	Status   string
	Count    *bool
}

// TargetListOpts are options for listing targets.
type TargetListOpts struct {
	Skip       int
	Limit      int
	Search     string
	TargetType string
	Status     string
}

// PromptSetListOpts are options for listing prompt sets.
type PromptSetListOpts struct {
	Skip    int
	Limit   int
	Search  string
	Status  string
	Active  *bool
	Archive *bool
}

// PromptListOpts are options for listing prompts.
type PromptListOpts struct {
	Skip   int
	Limit  int
	Search string
	Active *bool
}

// PromptsBySetListOpts are options for listing prompts by set.
type PromptsBySetListOpts struct {
	Skip     int
	Limit    int
	Search   string
	IsThreat *bool
}

// CustomAttacksReportListOpts are options for listing custom attacks in a report.
type CustomAttacksReportListOpts struct {
	Skip          int
	Limit         int
	Search        string
	Threat        *bool
	PromptSetID   string
	PropertyValue string
}
