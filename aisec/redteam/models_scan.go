package redteam

// --- Pagination ---

// RedTeamPagination holds pagination metadata.
type RedTeamPagination struct {
	Total int `json:"total"`
	Skip  int `json:"skip"`
	Limit int `json:"limit"`
}

// --- Job / Scan types ---

// TargetJobRequest is the nested target reference in a job create request.
type TargetJobRequest struct {
	UUID    string `json:"uuid"`
	Version int    `json:"version,omitempty"`
}

// JobCreateRequest is the request to create a red team scan job.
type JobCreateRequest struct {
	Name        string           `json:"name"`
	Target      TargetJobRequest `json:"target"`
	JobType     JobType          `json:"job_type"`
	JobMetadata map[string]any   `json:"job_metadata,omitempty"`
	Version     *int             `json:"version,omitempty"`
	ExtraInfo   map[string]any   `json:"extra_info,omitempty"`
}

// JobTargetResponse is the nested target info in a job response.
type JobTargetResponse struct {
	UUID    string `json:"uuid,omitempty"`
	Name    string `json:"name,omitempty"`
	Version int    `json:"version,omitempty"`
}

// JobResponse represents a red team scan job.
type JobResponse struct {
	UUID            string            `json:"uuid"`
	Name            string            `json:"name,omitempty"`
	TsgID           string            `json:"tsg_id,omitempty"`
	Target          JobTargetResponse `json:"target,omitempty"`
	JobType         JobType           `json:"job_type,omitempty"`
	Status          JobStatus         `json:"status,omitempty"`
	JobMetadata     map[string]any    `json:"job_metadata,omitempty"`
	Version         int               `json:"version,omitempty"`
	TargetType      TargetType        `json:"target_type,omitempty"`
	Total           int               `json:"total,omitempty"`
	Completed       int               `json:"completed,omitempty"`
	Score           float64           `json:"score,omitempty"`
	ASR             float64           `json:"asr,omitempty"`
	CreatedAt       string            `json:"created_at,omitempty"`
	UpdatedAt       string            `json:"updated_at,omitempty"`
	FinishedAt      string            `json:"finished_at,omitempty"`
	TargetID        string            `json:"target_id,omitempty"`
	ExtraInfo       map[string]any    `json:"extra_info,omitempty"`
	InvocationID    string            `json:"invocation_id,omitempty"`
	CreatedByUserID string            `json:"created_by_user_id,omitempty"`
}

// JobListResponse is the paginated list of jobs.
type JobListResponse struct {
	Data       []JobResponse     `json:"data"`
	Pagination RedTeamPagination `json:"pagination"`
}

// JobAbortResponse is the response from aborting a job.
type JobAbortResponse struct {
	Message string `json:"message,omitempty"`
	Status  string `json:"status,omitempty"`
}

// CategoryModel represents a red team attack category.
type CategoryModel struct {
	ID            string         `json:"id"`
	Name          string         `json:"name,omitempty"`
	SubCategories []SubCategory  `json:"sub_categories"`
	Details       map[string]any `json:"details,omitempty"`
}

// SubCategory represents a sub-category within a category.
type SubCategory struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// --- Report types ---

// SeverityReport holds severity-level counts.
type SeverityReport struct {
	Low      int `json:"low"`
	Medium   int `json:"medium"`
	High     int `json:"high"`
	Critical int `json:"critical"`
}

// CategoryReport holds per-category report data.
type CategoryReport struct {
	Category      string         `json:"category,omitempty"`
	SubCategories map[string]any `json:"sub_categories,omitempty"`
}

// StaticJobReport represents a static scan report.
type StaticJobReport struct {
	ASR              *float64         `json:"asr,omitempty"`
	Score            *float64         `json:"score,omitempty"`
	SecurityReport   *CategoryReport  `json:"security_report,omitempty"`
	SafetyReport     *CategoryReport  `json:"safety_report,omitempty"`
	BrandReport      *CategoryReport  `json:"brand_report,omitempty"`
	ComplianceReport []map[string]any `json:"compliance_report,omitempty"`
	SeverityReport   *SeverityReport  `json:"severity_report,omitempty"`
	ReportSummary    string           `json:"report_summary,omitempty"`
	Recommendations  map[string]any   `json:"recommendations,omitempty"`
}

// DynamicJobReport represents a dynamic scan report.
type DynamicJobReport struct {
	TotalGoals    int     `json:"total_goals"`
	TotalStreams  int     `json:"total_streams"`
	TotalThreats  int     `json:"total_threats"`
	GoalsAchieved int     `json:"goals_achieved"`
	ReportSummary string  `json:"report_summary,omitempty"`
	Score         float64 `json:"score"`
	ASR           float64 `json:"asr"`
}

// ReportDownloadResponse wraps raw bytes from a report download.
type ReportDownloadResponse struct {
	Data []byte `json:"data,omitempty"`
}

// AttackListItem represents an attack in a list.
type AttackListItem struct {
	ID       string         `json:"id,omitempty"`
	Category string         `json:"category,omitempty"`
	Severity string         `json:"severity,omitempty"`
	Status   string         `json:"status,omitempty"`
	Details  map[string]any `json:"details,omitempty"`
}

// AttackListResponse is the paginated list of attacks.
type AttackListResponse struct {
	Data       []AttackListItem  `json:"data"`
	Pagination RedTeamPagination `json:"pagination"`
}

// AttackDetailResponse represents detailed attack information.
type AttackDetailResponse struct {
	UUID                   string           `json:"uuid,omitempty"`
	TsgID                  string           `json:"tsg_id,omitempty"`
	JobID                  string           `json:"job_id,omitempty"`
	TargetID               string           `json:"target_id,omitempty"`
	Prompt                 string           `json:"prompt,omitempty"`
	Status                 string           `json:"status,omitempty"`
	MarkedSafe             *bool            `json:"marked_safe,omitempty"`
	Threat                 *bool            `json:"threat,omitempty"`
	AttackType             string           `json:"attack_type,omitempty"`
	MultiTurn              bool             `json:"multi_turn"`
	ASR                    *float64         `json:"asr,omitempty"`
	Version                *int             `json:"version,omitempty"`
	PromptMappingID        string           `json:"prompt_mapping_id,omitempty"`
	PromptID               string           `json:"prompt_id,omitempty"`
	Category               string           `json:"category,omitempty"`
	SubCategory            string           `json:"sub_category,omitempty"`
	Severity               string           `json:"severity,omitempty"`
	CategoryDisplayName    string           `json:"category_display_name,omitempty"`
	SubCategoryDisplayName string           `json:"sub_category_display_name,omitempty"`
	ComplianceFrameworks   []string         `json:"compliance_frameworks,omitempty"`
	Outputs                []map[string]any `json:"outputs,omitempty"`
	Goal                   map[string]any   `json:"goal,omitempty"`
}

// AttackMultiTurnDetailResponse represents multi-turn attack detail.
type AttackMultiTurnDetailResponse struct {
	UUID       string `json:"uuid,omitempty"`
	TsgID      string `json:"tsg_id,omitempty"`
	AttackID   string `json:"attack_id,omitempty"`
	JobID      string `json:"job_id,omitempty"`
	TargetID   string `json:"target_id,omitempty"`
	Prompt     string `json:"prompt,omitempty"`
	Output     string `json:"output,omitempty"`
	Threat     *bool  `json:"threat,omitempty"`
	MarkedSafe *bool  `json:"marked_safe,omitempty"`
	Turn       int    `json:"turn,omitempty"`
	Generation int    `json:"generation,omitempty"`
	MultiTurn  bool   `json:"multi_turn"`
}

// RemediationResponse is the remediation advice response.
type RemediationResponse struct {
	JobID   string         `json:"job_id,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

// RuntimePolicyConfigResponse is the runtime policy configuration.
type RuntimePolicyConfigResponse struct {
	JobID    string         `json:"job_id,omitempty"`
	Policies map[string]any `json:"policies,omitempty"`
}

// GoalListResponse is the paginated list of goals.
type GoalListResponse struct {
	Data       []Goal            `json:"data"`
	Pagination RedTeamPagination `json:"pagination"`
}

// Goal represents a dynamic red team goal.
type Goal struct {
	UUID               string         `json:"uuid,omitempty"`
	GoalType           GoalType       `json:"goal_type,omitempty"`
	Status             string         `json:"status,omitempty"`
	Goal               string         `json:"goal,omitempty"`
	SafeResponse       string         `json:"safe_response,omitempty"`
	JailbrokenResponse string         `json:"jailbroken_response,omitempty"`
	GoalMetadata       map[string]any `json:"goal_metadata,omitempty"`
	CustomGoal         bool           `json:"custom_goal"`
	TsgID              string         `json:"tsg_id,omitempty"`
	JobID              string         `json:"job_id,omitempty"`
	GoalToShow         string         `json:"goal_to_show,omitempty"`
	Threat             *bool          `json:"threat,omitempty"`
	Version            *int           `json:"version,omitempty"`
	ExtraInfo          map[string]any `json:"extra_info,omitempty"`
}

// StreamListResponse is the paginated list of streams.
type StreamListResponse struct {
	Data       []StreamDetailResponse `json:"data"`
	Pagination RedTeamPagination      `json:"pagination"`
}

// StreamDetailResponse is the detail of a single stream.
type StreamDetailResponse struct {
	UUID                 string         `json:"uuid,omitempty"`
	TsgID                string         `json:"tsg_id,omitempty"`
	JobID                string         `json:"job_id,omitempty"`
	TargetID             string         `json:"target_id,omitempty"`
	GoalID               string         `json:"goal_id,omitempty"`
	StreamIdx            int            `json:"stream_idx,omitempty"`
	StreamType           string         `json:"stream_type,omitempty"`
	Threat               *bool          `json:"threat,omitempty"`
	MarkedSafe           *bool          `json:"marked_safe,omitempty"`
	Iteration            int            `json:"iteration,omitempty"`
	FirstThreatIteration *int           `json:"first_threat_iteration,omitempty"`
	CreatedAt            string         `json:"created_at,omitempty"`
	UpdatedAt            string         `json:"updated_at,omitempty"`
	Version              int            `json:"version,omitempty"`
	Goal                 map[string]any `json:"goal,omitempty"`
	ExtraInfo            map[string]any `json:"extra_info,omitempty"`
}
