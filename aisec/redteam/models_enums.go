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

// AuthConfigType represents the type of auth configuration.
type AuthConfigType string

const (
	AuthConfigTypeHeaders   AuthConfigType = "HEADERS"
	AuthConfigTypeBasicAuth AuthConfigType = "BASIC_AUTH"
	AuthConfigTypeOAuth2    AuthConfigType = "OAUTH2"
)

// BasicAuthLocation represents where basic auth credentials are sent.
type BasicAuthLocation string

const (
	BasicAuthLocationHeader  BasicAuthLocation = "HEADER"
	BasicAuthLocationPayload BasicAuthLocation = "PAYLOAD"
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
