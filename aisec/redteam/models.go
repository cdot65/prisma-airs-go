package redteam

// --- Enums ---

// JobType represents the type of a red team job.
type JobType string

const (
	JobTypeStatic  JobType = "STATIC"
	JobTypeDynamic JobType = "DYNAMIC"
	JobTypeCustom  JobType = "CUSTOM"
)

// JobStatus represents the status of a red team job.
type JobStatus string

const (
	JobStatusInit              JobStatus = "INIT"
	JobStatusQueued            JobStatus = "QUEUED"
	JobStatusRunning           JobStatus = "RUNNING"
	JobStatusCompleted         JobStatus = "COMPLETED"
	JobStatusPartiallyComplete JobStatus = "PARTIALLY_COMPLETE"
	JobStatusFailed            JobStatus = "FAILED"
	JobStatusAborted           JobStatus = "ABORTED"
)

// TargetType represents the type of a target.
type TargetType string

const (
	TargetTypeApplication TargetType = "APPLICATION"
	TargetTypeAgent       TargetType = "AGENT"
	TargetTypeModel       TargetType = "MODEL"
)

// TargetStatus represents the status of a target.
type TargetStatus string

const (
	TargetStatusDraft       TargetStatus = "DRAFT"
	TargetStatusValidating  TargetStatus = "VALIDATING"
	TargetStatusValidated   TargetStatus = "VALIDATED"
	TargetStatusActive      TargetStatus = "ACTIVE"
	TargetStatusInactive    TargetStatus = "INACTIVE"
	TargetStatusFailed      TargetStatus = "FAILED"
	TargetStatusPendingAuth TargetStatus = "PENDING_AUTH"
)

// TargetConnectionType represents the connection type for a target.
type TargetConnectionType string

const (
	TargetConnectionTypeDatabricks  TargetConnectionType = "DATABRICKS"
	TargetConnectionTypeBedrock     TargetConnectionType = "BEDROCK"
	TargetConnectionTypeOpenAI      TargetConnectionType = "OPENAI"
	TargetConnectionTypeHuggingFace TargetConnectionType = "HUGGING_FACE"
	TargetConnectionTypeCustom      TargetConnectionType = "CUSTOM"
	TargetConnectionTypeRest        TargetConnectionType = "REST"
	TargetConnectionTypeStreaming   TargetConnectionType = "STREAMING"
)

// APIEndpointType represents the API endpoint type for a target.
type APIEndpointType string

const (
	APIEndpointTypePublic        APIEndpointType = "PUBLIC"
	APIEndpointTypePrivate       APIEndpointType = "PRIVATE"
	APIEndpointTypeNetworkBroker APIEndpointType = "NETWORK_BROKER"
)

// RedTeamCategory represents a red team attack category.
type RedTeamCategory string

const (
	RedTeamCategorySecurity   RedTeamCategory = "SECURITY"
	RedTeamCategorySafety     RedTeamCategory = "SAFETY"
	RedTeamCategoryCompliance RedTeamCategory = "COMPLIANCE"
	RedTeamCategoryBrand      RedTeamCategory = "BRAND"
)

// RiskRating represents a risk rating level.
type RiskRating string

const (
	RiskRatingLow      RiskRating = "LOW"
	RiskRatingMedium   RiskRating = "MEDIUM"
	RiskRatingHigh     RiskRating = "HIGH"
	RiskRatingCritical RiskRating = "CRITICAL"
)

// ResponseMode represents the response mode.
type ResponseMode string

const (
	ResponseModeRest      ResponseMode = "REST"
	ResponseModeStreaming ResponseMode = "STREAMING"
)

// GoalType represents a dynamic red team goal type.
type GoalType string

const (
	GoalTypeBase             GoalType = "BASE"
	GoalTypeToolMisuse       GoalType = "TOOL_MISUSE"
	GoalTypeGoalManipulation GoalType = "GOAL_MANIPULATION"
)

// FileFormat represents a report download format.
type FileFormat string

const (
	FileFormatCSV  FileFormat = "CSV"
	FileFormatJSON FileFormat = "JSON"
	FileFormatAll  FileFormat = "ALL"
)

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
	Items      []JobResponse     `json:"items"`
	Pagination RedTeamPagination `json:"pagination"`
}

// JobAbortResponse is the response from aborting a job.
type JobAbortResponse struct {
	Message string `json:"message,omitempty"`
	Status  string `json:"status,omitempty"`
}

// CategoryModel represents a red team attack category.
type CategoryModel struct {
	ID            string         `json:"id,omitempty"`
	Name          string         `json:"name,omitempty"`
	SubCategories []SubCategory  `json:"sub_categories,omitempty"`
	Details       map[string]any `json:"details,omitempty"`
}

// SubCategory represents a sub-category within a category.
type SubCategory struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// --- Report types ---

// StaticJobReport represents a static scan report.
type StaticJobReport struct {
	JobID   string         `json:"job_id,omitempty"`
	Stats   map[string]any `json:"stats,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

// DynamicJobReport represents a dynamic scan report.
type DynamicJobReport struct {
	JobID   string         `json:"job_id,omitempty"`
	Stats   map[string]any `json:"stats,omitempty"`
	Details map[string]any `json:"details,omitempty"`
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
	Items      []AttackListItem  `json:"items"`
	Pagination RedTeamPagination `json:"pagination"`
}

// AttackDetailResponse represents detailed attack information.
type AttackDetailResponse struct {
	ID       string         `json:"id,omitempty"`
	Category string         `json:"category,omitempty"`
	Severity string         `json:"severity,omitempty"`
	Details  map[string]any `json:"details,omitempty"`
}

// AttackMultiTurnDetailResponse represents multi-turn attack detail.
type AttackMultiTurnDetailResponse struct {
	ID       string         `json:"id,omitempty"`
	Category string         `json:"category,omitempty"`
	Details  map[string]any `json:"details,omitempty"`
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
	Items      []Goal            `json:"items"`
	Pagination RedTeamPagination `json:"pagination"`
}

// Goal represents a dynamic red team goal.
type Goal struct {
	ID       string         `json:"id,omitempty"`
	GoalType GoalType       `json:"goal_type,omitempty"`
	Status   string         `json:"status,omitempty"`
	Details  map[string]any `json:"details,omitempty"`
}

// StreamListResponse is the paginated list of streams.
type StreamListResponse struct {
	Items      []map[string]any  `json:"items"`
	Pagination RedTeamPagination `json:"pagination"`
}

// StreamDetailResponse is the detail of a single stream.
type StreamDetailResponse struct {
	ID      string         `json:"id,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

// --- Custom Attack Report types ---

// CustomAttackReportResponse is the custom attack report.
type CustomAttackReportResponse struct {
	JobID   string         `json:"job_id,omitempty"`
	Stats   map[string]any `json:"stats,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

// PromptSetsReportResponse is the prompt sets report.
type PromptSetsReportResponse struct {
	Items []map[string]any `json:"items"`
}

// PromptDetailResponse is the detail of a single prompt.
type PromptDetailResponse struct {
	ID      string         `json:"id,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

// CustomAttacksListResponse is the paginated list of custom attacks in a report.
type CustomAttacksListResponse struct {
	Items      []map[string]any  `json:"items"`
	Pagination RedTeamPagination `json:"pagination"`
}

// CustomAttackOutput represents a custom attack output.
type CustomAttackOutput struct {
	ID      string         `json:"id,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

// PropertyStatistic represents property statistics.
type PropertyStatistic struct {
	PropertyName string           `json:"property_name,omitempty"`
	Values       []map[string]any `json:"values,omitempty"`
}

// --- Target types ---

// TargetCreateRequest is the request to create a target.
type TargetCreateRequest struct {
	Name                     string               `json:"name"`
	Description              string               `json:"description,omitempty"`
	TargetType               TargetType           `json:"target_type,omitempty"`
	ConnectionType           TargetConnectionType `json:"connection_type,omitempty"`
	ConnectionParams         map[string]any       `json:"connection_params,omitempty"`
	Background               map[string]any       `json:"background,omitempty"`
	Context                  map[string]any       `json:"context,omitempty"`
	Metadata                 map[string]any       `json:"metadata,omitempty"`
	APIEndpointType          APIEndpointType      `json:"api_endpoint_type,omitempty"`
	NetworkBrokerChannelUUID string               `json:"network_broker_channel_uuid,omitempty"`
	ResponseMode             string               `json:"response_mode,omitempty"`
	SessionSupported         bool                 `json:"session_supported,omitempty"`
	ExtraInfo                map[string]any       `json:"extra_info,omitempty"`
}

// TargetUpdateRequest is the request to update a target.
type TargetUpdateRequest struct {
	Name             string               `json:"name,omitempty"`
	Description      string               `json:"description,omitempty"`
	TargetType       TargetType           `json:"target_type,omitempty"`
	ConnectionType   TargetConnectionType `json:"connection_type,omitempty"`
	ConnectionParams map[string]any       `json:"connection_params,omitempty"`
	Background       map[string]any       `json:"background,omitempty"`
	Context          map[string]any       `json:"context,omitempty"`
	Metadata         map[string]any       `json:"metadata,omitempty"`
}

// TargetContextUpdate is the request to update a target's context.
type TargetContextUpdate struct {
	Background map[string]any `json:"background,omitempty"`
	Context    map[string]any `json:"context,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// TargetResponse represents a target.
type TargetResponse struct {
	UUID             string               `json:"uuid"`
	Name             string               `json:"name,omitempty"`
	Description      string               `json:"description,omitempty"`
	TargetType       TargetType           `json:"target_type,omitempty"`
	Status           TargetStatus         `json:"status,omitempty"`
	ConnectionType   TargetConnectionType `json:"connection_type,omitempty"`
	ConnectionParams map[string]any       `json:"connection_params,omitempty"`
	CreatedAt        string               `json:"created_at,omitempty"`
	UpdatedAt        string               `json:"updated_at,omitempty"`
	Active           bool                 `json:"active,omitempty"`
	TsgID            string               `json:"tsg_id,omitempty"`
	Version          int                  `json:"version,omitempty"`
	ProfilingStatus  string               `json:"profiling_status,omitempty"`
	APIEndpointType  APIEndpointType      `json:"api_endpoint_type,omitempty"`
	ResponseMode     string               `json:"response_mode,omitempty"`
	SessionSupported bool                 `json:"session_supported,omitempty"`
	Validated        bool                 `json:"validated,omitempty"`
	SecretVersion    string               `json:"secret_version,omitempty"`
	CreatedByUserID  string               `json:"created_by_user_id,omitempty"`
	UpdatedByUserID  string               `json:"updated_by_user_id,omitempty"`
	ExtraInfo        map[string]any       `json:"extra_info,omitempty"`
}

// TargetList is the paginated list of targets.
type TargetList struct {
	Items      []TargetResponse  `json:"items"`
	Pagination RedTeamPagination `json:"pagination"`
}

// TargetProbeRequest is the request to probe a target.
type TargetProbeRequest struct {
	Name                     string               `json:"name"`
	Description              string               `json:"description,omitempty"`
	TargetType               TargetType           `json:"target_type,omitempty"`
	ConnectionType           TargetConnectionType `json:"connection_type,omitempty"`
	APIEndpointType          APIEndpointType      `json:"api_endpoint_type,omitempty"`
	ResponseMode             ResponseMode         `json:"response_mode,omitempty"`
	SessionSupported         *bool                `json:"session_supported,omitempty"`
	ConnectionParams         map[string]any       `json:"connection_params,omitempty"`
	NetworkBrokerChannelUUID string               `json:"network_broker_channel_uuid,omitempty"`
	ExtraInfo                map[string]any       `json:"extra_info,omitempty"`
	TargetMetadata           map[string]any       `json:"target_metadata,omitempty"`
	TargetBackground         map[string]any       `json:"target_background,omitempty"`
	AdditionalContext        map[string]any       `json:"additional_context,omitempty"`
	UUID                     string               `json:"uuid,omitempty"`
	ProbeFields              []string             `json:"probe_fields,omitempty"`
}

// TargetProfileResponse is the target profile.
type TargetProfileResponse struct {
	UUID    string         `json:"uuid,omitempty"`
	Profile map[string]any `json:"profile,omitempty"`
}

// BaseResponse is a generic base response.
type BaseResponse struct {
	Message string `json:"message,omitempty"`
}

// --- Custom Attack types ---

// CustomPromptSetCreateRequest is the request to create a prompt set.
type CustomPromptSetCreateRequest struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Properties  map[string]any `json:"properties,omitempty"`
}

// CustomPromptSetUpdateRequest is the request to update a prompt set.
type CustomPromptSetUpdateRequest struct {
	Name        string         `json:"name,omitempty"`
	Description string         `json:"description,omitempty"`
	Properties  map[string]any `json:"properties,omitempty"`
}

// CustomPromptSetArchiveRequest is the request to archive a prompt set.
type CustomPromptSetArchiveRequest struct {
	Archive bool `json:"archive"`
}

// CustomPromptSetResponse represents a custom prompt set.
type CustomPromptSetResponse struct {
	UUID        string         `json:"uuid"`
	Name        string         `json:"name,omitempty"`
	Description string         `json:"description,omitempty"`
	Status      string         `json:"status,omitempty"`
	Active      bool           `json:"active,omitempty"`
	Archive     bool           `json:"archive,omitempty"`
	Stats       map[string]any `json:"stats,omitempty"`
	CreatedAt   string         `json:"created_at,omitempty"`
	UpdatedAt   string         `json:"updated_at,omitempty"`
}

// CustomPromptSetList is the paginated list of prompt sets.
type CustomPromptSetList struct {
	Items      []CustomPromptSetResponse `json:"items"`
	Pagination RedTeamPagination         `json:"pagination"`
}

// CustomPromptSetListActive is the active prompt sets list.
type CustomPromptSetListActive struct {
	Items []CustomPromptSetResponse `json:"items"`
}

// CustomPromptSetReference is the reference for a prompt set.
type CustomPromptSetReference struct {
	UUID      string         `json:"uuid,omitempty"`
	Reference map[string]any `json:"reference,omitempty"`
}

// CustomPromptSetVersionInfo is the version info for a prompt set.
type CustomPromptSetVersionInfo struct {
	UUID    string         `json:"uuid,omitempty"`
	Version map[string]any `json:"version,omitempty"`
}

// CustomPromptCreateRequest is the request to create a prompt.
type CustomPromptCreateRequest struct {
	PromptSetID string         `json:"prompt_set_id"`
	Prompt      string         `json:"prompt"`
	Goal        string         `json:"goal,omitempty"`
	Properties  map[string]any `json:"properties,omitempty"`
}

// CustomPromptUpdateRequest is the request to update a prompt.
type CustomPromptUpdateRequest struct {
	Prompt     string         `json:"prompt,omitempty"`
	Goal       string         `json:"goal,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

// CustomPromptResponse represents a custom prompt.
type CustomPromptResponse struct {
	UUID             string         `json:"uuid"`
	PromptSetID      string         `json:"prompt_set_id,omitempty"`
	Prompt           string         `json:"prompt,omitempty"`
	Goal             string         `json:"goal,omitempty"`
	UserDefinedGoal  string         `json:"user_defined_goal,omitempty"`
	DetectorCategory string         `json:"detector_category,omitempty"`
	Severity         string         `json:"severity,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
	Active           bool           `json:"active,omitempty"`
	CreatedAt        string         `json:"created_at,omitempty"`
}

// CustomPromptList is the paginated list of prompts.
type CustomPromptList struct {
	Items      []CustomPromptResponse `json:"items"`
	Pagination RedTeamPagination      `json:"pagination"`
}

// PropertyNamesListResponse lists property names.
type PropertyNamesListResponse struct {
	Items []map[string]any `json:"items"`
}

// PropertyNameCreateRequest is the request to create a property name.
type PropertyNameCreateRequest struct {
	Name string `json:"name"`
}

// PropertyValueCreateRequest is the request to create a property value.
type PropertyValueCreateRequest struct {
	PropertyName string `json:"property_name"`
	Value        string `json:"value"`
}

// PropertyValuesResponse lists values for a property.
type PropertyValuesResponse struct {
	Values []string `json:"values"`
}

// PropertyValuesMultipleResponse lists values for multiple properties.
type PropertyValuesMultipleResponse struct {
	Properties map[string][]string `json:"properties"`
}

// --- Dashboard / Statistics types ---

// ScanStatisticsResponse is the scan statistics response.
type ScanStatisticsResponse struct {
	Stats map[string]any `json:"stats,omitempty"`
}

// ScoreTrendResponse is the score trend response.
type ScoreTrendResponse struct {
	TargetID string           `json:"target_id,omitempty"`
	Series   []map[string]any `json:"series,omitempty"`
}

// QuotaSummary is the quota summary.
type QuotaSummary struct {
	Details map[string]any `json:"details,omitempty"`
}

// ErrorLogListResponse is the paginated list of error logs.
type ErrorLogListResponse struct {
	Items      []map[string]any  `json:"items"`
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
