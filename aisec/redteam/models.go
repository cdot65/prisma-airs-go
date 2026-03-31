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
	TargetConnectionTypeWebSocket   TargetConnectionType = "WEBSOCKET"
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
	ResponseModeWebSocket ResponseMode = "WEBSOCKET"
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

// AttackStatus represents the status of an individual attack.
type AttackStatus string

const (
	AttackStatusInit      AttackStatus = "INIT"
	AttackStatusAttack    AttackStatus = "ATTACK"
	AttackStatusDetection AttackStatus = "DETECTION"
	AttackStatusReport    AttackStatus = "REPORT"
	AttackStatusCompleted AttackStatus = "COMPLETED"
	AttackStatusFailed    AttackStatus = "FAILED"
)

// AttackType represents the type of an attack.
type AttackType string

const (
	AttackTypeNormal AttackType = "NORMAL"
	AttackTypeCustom AttackType = "CUSTOM"
)

// AuthType represents authentication type for targets.
type AuthType string

const (
	AuthTypeOAuth       AuthType = "OAUTH"
	AuthTypeAccessToken AuthType = "ACCESS_TOKEN"
)

// BrandSubCategory represents brand attack sub-categories.
type BrandSubCategory string

const (
	BrandSubCategoryCompetitorEndorsements BrandSubCategory = "COMPETITOR_ENDORSEMENTS"
	BrandSubCategoryBrandTarnishing        BrandSubCategory = "BRAND_TARNISHING_SELF_CRITICISM"
	BrandSubCategoryDiscriminatingClaims   BrandSubCategory = "DISCRIMINATING_CLAIMS"
	BrandSubCategoryPoliticalEndorsements  BrandSubCategory = "POLITICAL_ENDORSEMENTS"
)

// ComplianceSubCategory represents compliance attack sub-categories.
type ComplianceSubCategory string

const (
	ComplianceSubCategoryOWASP      ComplianceSubCategory = "OWASP"
	ComplianceSubCategoryMITREATLAS ComplianceSubCategory = "MITRE_ATLAS"
	ComplianceSubCategoryNIST       ComplianceSubCategory = "NIST"
	ComplianceSubCategoryDASFV2     ComplianceSubCategory = "DASF_V2"
)

// SafetySubCategory represents safety attack sub-categories.
type SafetySubCategory string

const (
	SafetySubCategoryBias                 SafetySubCategory = "BIAS"
	SafetySubCategoryCBRN                 SafetySubCategory = "CBRN"
	SafetySubCategoryCybercrime           SafetySubCategory = "CYBERCRIME"
	SafetySubCategoryDrugs                SafetySubCategory = "DRUGS"
	SafetySubCategoryHateToxicAbuse       SafetySubCategory = "HATE_TOXIC_ABUSE"
	SafetySubCategoryNonViolentCrimes     SafetySubCategory = "NON_VIOLENT_CRIMES"
	SafetySubCategoryPolitical            SafetySubCategory = "POLITICAL"
	SafetySubCategorySelfHarm             SafetySubCategory = "SELF_HARM"
	SafetySubCategorySexual               SafetySubCategory = "SEXUAL"
	SafetySubCategoryViolentCrimesWeapons SafetySubCategory = "VIOLENT_CRIMES_WEAPONS"
)

// SecuritySubCategory represents security attack sub-categories.
type SecuritySubCategory string

const (
	SecuritySubCategoryAdversarialSuffix       SecuritySubCategory = "ADVERSARIAL_SUFFIX"
	SecuritySubCategoryEvasion                 SecuritySubCategory = "EVASION"
	SecuritySubCategoryIndirectPromptInjection SecuritySubCategory = "INDIRECT_PROMPT_INJECTION"
	SecuritySubCategoryJailbreak               SecuritySubCategory = "JAILBREAK"
	SecuritySubCategoryMultiTurn               SecuritySubCategory = "MULTI_TURN"
	SecuritySubCategoryPromptInjection         SecuritySubCategory = "PROMPT_INJECTION"
	SecuritySubCategoryRemoteCodeExecution     SecuritySubCategory = "REMOTE_CODE_EXECUTION"
	SecuritySubCategorySystemPromptLeak        SecuritySubCategory = "SYSTEM_PROMPT_LEAK"
	SecuritySubCategoryToolLeak                SecuritySubCategory = "TOOL_LEAK"
	SecuritySubCategoryMalwareGeneration       SecuritySubCategory = "MALWARE_GENERATION"
)

// ErrorSource represents the source of an error log.
type ErrorSource string

const (
	ErrorSourceTarget          ErrorSource = "TARGET"
	ErrorSourceJob             ErrorSource = "JOB"
	ErrorSourceSystem          ErrorSource = "SYSTEM"
	ErrorSourceValidation      ErrorSource = "VALIDATION"
	ErrorSourceTargetProfiling ErrorSource = "TARGET_PROFILING"
)

// ErrorTypeEnum represents the type of an error log.
type ErrorTypeEnum string

const (
	ErrorTypeContentFilter  ErrorTypeEnum = "CONTENT_FILTER"
	ErrorTypeRateLimit      ErrorTypeEnum = "RATE_LIMIT"
	ErrorTypeAuthentication ErrorTypeEnum = "AUTHENTICATION"
	ErrorTypeNetwork        ErrorTypeEnum = "NETWORK"
	ErrorTypeValidation     ErrorTypeEnum = "VALIDATION"
	ErrorTypeNetworkChannel ErrorTypeEnum = "NETWORK_CHANNEL"
	ErrorTypeUnknown        ErrorTypeEnum = "UNKNOWN"
)

// ProfilingStatus represents the profiling status of a target.
type ProfilingStatus string

const (
	ProfilingStatusInit       ProfilingStatus = "INIT"
	ProfilingStatusQueued     ProfilingStatus = "QUEUED"
	ProfilingStatusInProgress ProfilingStatus = "IN_PROGRESS"
	ProfilingStatusCompleted  ProfilingStatus = "COMPLETED"
	ProfilingStatusFailed     ProfilingStatus = "FAILED"
)

// StreamType represents the type of a conversation stream.
type StreamType string

const (
	StreamTypeNormal      StreamType = "NORMAL"
	StreamTypeAdversarial StreamType = "ADVERSARIAL"
)

// PolicyType represents runtime policy types.
type PolicyType string

const (
	PolicyTypePromptInjection         PolicyType = "PROMPT_INJECTION"
	PolicyTypeToxicContent            PolicyType = "TOXIC_CONTENT"
	PolicyTypeCustomTopicGuardrails   PolicyType = "CUSTOM_TOPIC_GUARDRAILS"
	PolicyTypeMaliciousCodeDetection  PolicyType = "MALICIOUS_CODE_DETECTION"
	PolicyTypeMaliciousURLDetection   PolicyType = "MALICIOUS_URL_DETECTION"
	PolicyTypeSensitiveDataProtection PolicyType = "SENSITIVE_DATA_PROTECTION"
)

// GuardrailAction represents a guardrail action.
type GuardrailAction string

const (
	GuardrailActionAllow GuardrailAction = "ALLOW"
	GuardrailActionBlock GuardrailAction = "BLOCK"
)

// DateRangeFilter represents date range filter options.
type DateRangeFilter string

const (
	DateRangeFilterLast7Days  DateRangeFilter = "LAST_7_DAYS"
	DateRangeFilterLast15Days DateRangeFilter = "LAST_15_DAYS"
	DateRangeFilterLast30Days DateRangeFilter = "LAST_30_DAYS"
	DateRangeFilterAll        DateRangeFilter = "ALL"
)

// CountedQuotaEnum represents quota counting status.
type CountedQuotaEnum string

const (
	CountedQuotaHeld       CountedQuotaEnum = "HELD"
	CountedQuotaCounted    CountedQuotaEnum = "COUNTED"
	CountedQuotaNotCounted CountedQuotaEnum = "NOT_COUNTED"
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

// --- Custom Attack Report types ---

// CustomAttackReportResponse is the custom attack report.
type CustomAttackReportResponse struct {
	JobID   string         `json:"job_id,omitempty"`
	Stats   map[string]any `json:"stats,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

// PromptSetsReportResponse is the prompt sets report.
type PromptSetsReportResponse struct {
	Data []map[string]any `json:"data"`
}

// PromptDetailResponse is the detail of a single prompt.
type PromptDetailResponse struct {
	ID      string         `json:"id,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

// CustomAttacksListResponse is the paginated list of custom attacks in a report.
type CustomAttacksListResponse struct {
	Data       []map[string]any  `json:"data"`
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
	Name                     string                   `json:"name"`
	Description              string                   `json:"description,omitempty"`
	TargetType               TargetType               `json:"target_type,omitempty"`
	ConnectionType           TargetConnectionType     `json:"connection_type,omitempty"`
	ConnectionParams         map[string]any           `json:"connection_params,omitempty"`
	APIEndpointType          APIEndpointType          `json:"api_endpoint_type,omitempty"`
	NetworkBrokerChannelUUID string                   `json:"network_broker_channel_uuid,omitempty"`
	ResponseMode             string                   `json:"response_mode,omitempty"`
	SessionSupported         bool                     `json:"session_supported"`
	ExtraInfo                map[string]any           `json:"extra_info,omitempty"`
	TargetMeta               *TargetMetadata          `json:"target_metadata,omitempty"`
	TargetBackground         *TargetBackground        `json:"target_background,omitempty"`
	AdditionalContext        *TargetAdditionalContext `json:"additional_context,omitempty"`
}

// TargetUpdateRequest is the request to update a target.
type TargetUpdateRequest struct {
	Name                     string                   `json:"name"`
	Description              string                   `json:"description,omitempty"`
	TargetType               TargetType               `json:"target_type,omitempty"`
	ConnectionType           TargetConnectionType     `json:"connection_type,omitempty"`
	ConnectionParams         map[string]any           `json:"connection_params,omitempty"`
	APIEndpointType          APIEndpointType          `json:"api_endpoint_type,omitempty"`
	NetworkBrokerChannelUUID string                   `json:"network_broker_channel_uuid,omitempty"`
	ResponseMode             ResponseMode             `json:"response_mode,omitempty"`
	SessionSupported         bool                     `json:"session_supported"`
	ExtraInfo                map[string]any           `json:"extra_info,omitempty"`
	TargetMeta               *TargetMetadata          `json:"target_metadata,omitempty"`
	TargetBackground         *TargetBackground        `json:"target_background,omitempty"`
	AdditionalContext        *TargetAdditionalContext `json:"additional_context,omitempty"`
}

// TargetContextUpdate is the request to update a target's context.
type TargetContextUpdate struct {
	TargetBackground  *TargetBackground        `json:"target_background,omitempty"`
	AdditionalContext *TargetAdditionalContext `json:"additional_context,omitempty"`
}

// TargetResponse represents a target.
type TargetResponse struct {
	UUID             string                   `json:"uuid"`
	TsgID            string                   `json:"tsg_id"`
	Name             string                   `json:"name"`
	Description      string                   `json:"description,omitempty"`
	TargetType       TargetType               `json:"target_type,omitempty"`
	Status           TargetStatus             `json:"status"`
	ConnectionType   TargetConnectionType     `json:"connection_type,omitempty"`
	ConnectionParams map[string]any           `json:"connection_params,omitempty"`
	APIEndpointType  APIEndpointType          `json:"api_endpoint_type,omitempty"`
	ResponseMode     string                   `json:"response_mode,omitempty"`
	SessionSupported bool                     `json:"session_supported"`
	ExtraInfo        map[string]any           `json:"extra_info,omitempty"`
	Active           bool                     `json:"active"`
	Validated        bool                     `json:"validated"`
	Version          int                      `json:"version,omitempty"`
	SecretVersion    string                   `json:"secret_version,omitempty"`
	CreatedByUserID  string                   `json:"created_by_user_id,omitempty"`
	UpdatedByUserID  string                   `json:"updated_by_user_id,omitempty"`
	CreatedAt        string                   `json:"created_at"`
	UpdatedAt        string                   `json:"updated_at"`
	TargetMeta       *TargetMetadata          `json:"target_metadata,omitempty"`
	TargetBackground *TargetBackground        `json:"target_background,omitempty"`
	ProfilingStatus  ProfilingStatus          `json:"profiling_status,omitempty"`
	AdditionalCtx    *TargetAdditionalContext `json:"additional_context,omitempty"`
}

// TargetListItem represents a target in a list response (TargetListItemSchema).
type TargetListItem struct {
	UUID             string               `json:"uuid"`
	TsgID            string               `json:"tsg_id"`
	Name             string               `json:"name"`
	Description      string               `json:"description,omitempty"`
	TargetType       TargetType           `json:"target_type,omitempty"`
	ConnectionType   TargetConnectionType `json:"connection_type,omitempty"`
	APIEndpointType  APIEndpointType      `json:"api_endpoint_type,omitempty"`
	ResponseMode     string               `json:"response_mode,omitempty"`
	SessionSupported bool                 `json:"session_supported"`
	ExtraInfo        map[string]any       `json:"extra_info,omitempty"`
	Status           TargetStatus         `json:"status"`
	Active           bool                 `json:"active"`
	Validated        bool                 `json:"validated"`
	Version          int                  `json:"version,omitempty"`
	SecretVersion    string               `json:"secret_version,omitempty"`
	CreatedByUserID  string               `json:"created_by_user_id,omitempty"`
	UpdatedByUserID  string               `json:"updated_by_user_id,omitempty"`
	CreatedAt        string               `json:"created_at"`
	UpdatedAt        string               `json:"updated_at"`
}

// TargetList is the paginated list of targets.
type TargetList struct {
	Data       []TargetListItem  `json:"data"`
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
	SessionSupported         *bool                `json:"session_supported"`
	ConnectionParams         map[string]any       `json:"connection_params,omitempty"`
	NetworkBrokerChannelUUID string               `json:"network_broker_channel_uuid,omitempty"`
	ExtraInfo                map[string]any       `json:"extra_info,omitempty"`
	TargetMetadata           map[string]any       `json:"target_metadata,omitempty"`
	TargetBackground         map[string]any       `json:"target_background,omitempty"`
	AdditionalContext        map[string]any       `json:"additional_context,omitempty"`
	UUID                     string               `json:"uuid,omitempty"`
	ProbeFields              []string             `json:"probe_fields,omitempty"`
}

// TargetProfileResponse is the target profile response.
type TargetProfileResponse struct {
	TargetID          string                   `json:"target_id"`
	TargetVersion     int                      `json:"target_version"`
	Status            string                   `json:"status"`
	TargetBackground  *TargetBackground        `json:"target_background,omitempty"`
	AdditionalContext *TargetAdditionalContext `json:"additional_context,omitempty"`
	OtherDetails      *OtherDetails            `json:"other_details,omitempty"`
	AIGeneratedFields []string                 `json:"ai_generated_fields,omitempty"`
	ProfilingStatus   ProfilingStatus          `json:"profiling_status,omitempty"`
}

// BaseResponse is a generic base response.
type BaseResponse struct {
	Message string `json:"message,omitempty"`
	Status  int    `json:"status,omitempty"`
}

// --- Custom Attack types ---

// CustomPromptSetCreateRequest is the request to create a prompt set.
type CustomPromptSetCreateRequest struct {
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	PropertyNames []string `json:"property_names,omitempty"`
}

// CustomPromptSetUpdateRequest is the request to update a prompt set.
type CustomPromptSetUpdateRequest struct {
	Name          string   `json:"name,omitempty"`
	Description   string   `json:"description,omitempty"`
	Archive       *bool    `json:"archive,omitempty"`
	PropertyNames []string `json:"property_names,omitempty"`
}

// CustomPromptSetArchiveRequest is the request to archive a prompt set.
type CustomPromptSetArchiveRequest struct {
	Archive bool `json:"archive"`
}

// CustomPromptSetResponse represents a custom prompt set.
type CustomPromptSetResponse struct {
	UUID            string          `json:"uuid"`
	Name            string          `json:"name,omitempty"`
	Description     string          `json:"description,omitempty"`
	Version         string          `json:"version,omitempty"`
	Status          string          `json:"status,omitempty"`
	Active          bool            `json:"active"`
	Archive         bool            `json:"archive"`
	Stats           *PromptSetStats `json:"stats,omitempty"`
	ExtraInfo       map[string]any  `json:"extra_info,omitempty"`
	PropertyNames   []string        `json:"property_names,omitempty"`
	CreatedAt       string          `json:"created_at,omitempty"`
	UpdatedAt       string          `json:"updated_at,omitempty"`
	CreatedByUserID string          `json:"created_by_user_id,omitempty"`
	UpdatedByUserID string          `json:"updated_by_user_id,omitempty"`
}

// CustomPromptSetList is the paginated list of prompt sets.
type CustomPromptSetList struct {
	Data       []CustomPromptSetResponse `json:"data"`
	Pagination RedTeamPagination         `json:"pagination"`
}

// CustomPromptSetListActive is the active prompt sets list.
type CustomPromptSetListActive struct {
	Data []CustomPromptSetResponse `json:"data"`
}

// CustomPromptSetReference is the reference for a prompt set.
type CustomPromptSetReference struct {
	UUID      string `json:"uuid,omitempty"`
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
	Status    string `json:"status,omitempty"`
	Active    bool   `json:"active"`
	TsgID     string `json:"tsg_id,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// CustomPromptSetVersionInfo is the version info for a prompt set.
type CustomPromptSetVersionInfo struct {
	UUID              string          `json:"uuid,omitempty"`
	Version           string          `json:"version,omitempty"`
	Status            string          `json:"status,omitempty"`
	Stats             *PromptSetStats `json:"stats,omitempty"`
	SnapshotCreatedAt string          `json:"snapshot_created_at,omitempty"`
	IsLatest          bool            `json:"is_latest"`
}

// PromptSetStats holds counts of prompts in a prompt set.
type PromptSetStats struct {
	TotalPrompts      int `json:"total_prompts"`
	ActivePrompts     int `json:"active_prompts"`
	FailedPrompts     int `json:"failed_prompts,omitempty"`
	ValidationPrompts int `json:"validation_prompts,omitempty"`
	InactivePrompts   int `json:"inactive_prompts"`
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
	UUID                string               `json:"uuid"`
	PromptSetID         string               `json:"prompt_set_id,omitempty"`
	Prompt              string               `json:"prompt,omitempty"`
	Goal                string               `json:"goal,omitempty"`
	UserDefinedGoal     bool                 `json:"user_defined_goal"`
	DetectorCategory    string               `json:"detector_category,omitempty"`
	Severity            string               `json:"severity,omitempty"`
	Properties          map[string]any       `json:"properties,omitempty"`
	PropertyAssignments []PropertyAssignment `json:"property_assignments,omitempty"`
	Active              bool                 `json:"active"`
	Status              string               `json:"status,omitempty"`
	ExtraInfo           map[string]any       `json:"extra_info,omitempty"`
	CreatedAt           string               `json:"created_at,omitempty"`
	UpdatedAt           string               `json:"updated_at,omitempty"`
}

// CustomPromptList is the paginated list of prompts.
type CustomPromptList struct {
	Data       []CustomPromptResponse `json:"data"`
	Pagination RedTeamPagination      `json:"pagination"`
}

// PropertyNamesListResponse lists property names.
type PropertyNamesListResponse struct {
	Data []string `json:"data"`
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
	Data map[string][]string `json:"data"`
}

// --- Target context types ---

// TargetMetadata holds target metadata for probing/profiling.
type TargetMetadata struct {
	MultiTurn                 bool           `json:"multi_turn"`
	MultiTurnErrorMessage     string         `json:"multi_turn_error_message,omitempty"`
	RateLimit                 *int           `json:"rate_limit,omitempty"`
	RateLimitEnabled          bool           `json:"rate_limit_enabled"`
	RateLimitErrorCode        *int           `json:"rate_limit_error_code,omitempty"`
	RateLimitErrorJSON        map[string]any `json:"rate_limit_error_json,omitempty"`
	RateLimitErrorMessage     string         `json:"rate_limit_error_message,omitempty"`
	ContentFilterEnabled      bool           `json:"content_filter_enabled"`
	ContentFilterErrorCode    *int           `json:"content_filter_error_code,omitempty"`
	ContentFilterErrorJSON    map[string]any `json:"content_filter_error_json,omitempty"`
	ContentFilterErrorMessage string         `json:"content_filter_error_message,omitempty"`
	ProbeMessage              string         `json:"probe_message,omitempty"`
	RequestTimeout            *float64       `json:"request_timeout,omitempty"`
}

// TargetBackground holds target background context.
type TargetBackground struct {
	Industry    string   `json:"industry,omitempty"`
	UseCase     string   `json:"use_case,omitempty"`
	Competitors []string `json:"competitors,omitempty"`
}

// OtherDetails holds additional profiler discoveries.
type OtherDetails struct {
	Items map[string]any `json:"items,omitempty"`
}

// TargetAdditionalContext holds additional context for a target.
type TargetAdditionalContext struct {
	BaseModel          string   `json:"base_model,omitempty"`
	CoreArchitecture   string   `json:"core_architecture,omitempty"`
	SystemPrompt       string   `json:"system_prompt,omitempty"`
	LanguagesSupported []string `json:"languages_supported,omitempty"`
	BannedKeywords     []string `json:"banned_keywords,omitempty"`
	ToolsAccessible    []string `json:"tools_accessible,omitempty"`
}

// PropertyAssignment is a property name-value pair for prompts.
type PropertyAssignment struct {
	PropertyName  string `json:"property_name"`
	PropertyValue string `json:"property_value"`
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
	TotalTargets  int           `json:"total_targets"`
	TargetsByType []CountByName `json:"targets_by_type,omitempty"`
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
