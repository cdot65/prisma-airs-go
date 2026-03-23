package aisec

// Version and user agent.
const (
	Version   = "0.4.0"
	UserAgent = "PAN-AIRS/" + Version + "-go-sdk"
)

// HTTP headers.
const (
	HeaderAPIKey    = "x-pan-token"
	HeaderAuthToken = "Authorization"
	PayloadHash     = "x-payload-hash"
	Bearer          = "Bearer "
)

// Default API endpoints.
const (
	DefaultEndpoint             = "https://service.api.aisecurity.paloaltonetworks.com"
	DefaultMgmtEndpoint         = "https://api.sase.paloaltonetworks.com/aisec"
	DefaultTokenEndpoint        = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
	DefaultModelSecDataEndpoint = "https://api.sase.paloaltonetworks.com/aims/data"
	DefaultModelSecMgmtEndpoint = "https://api.sase.paloaltonetworks.com/aims/mgmt"
	DefaultRedTeamDataEndpoint  = "https://api.sase.paloaltonetworks.com/ai-red-teaming/data-plane"
	DefaultRedTeamMgmtEndpoint  = "https://api.sase.paloaltonetworks.com/ai-red-teaming/mgmt-plane"
)

// RegionalEndpoints holds AIRS scan endpoints per region.
type RegionalEndpoints struct {
	US        string
	EU        string
	India     string
	Singapore string
}

// AIRSEndpoints provides regional scan API endpoints.
var AIRSEndpoints = RegionalEndpoints{
	US:        "https://service.api.aisecurity.paloaltonetworks.com",
	EU:        "https://service-de.api.aisecurity.paloaltonetworks.com",
	India:     "https://service-in.api.aisecurity.paloaltonetworks.com",
	Singapore: "https://service-sg.api.aisecurity.paloaltonetworks.com",
}

// Environment variable names — Scan API.
const (
	EnvAISecAPIKey      = "PANW_AI_SEC_API_KEY"
	EnvAISecAPIToken    = "PANW_AI_SEC_API_TOKEN"
	EnvAISecAPIEndpoint = "PANW_AI_SEC_API_ENDPOINT"
)

// Environment variable names — Management API.
const (
	EnvMgmtClientID      = "PANW_MGMT_CLIENT_ID"
	EnvMgmtClientSecret  = "PANW_MGMT_CLIENT_SECRET"
	EnvMgmtTsgID         = "PANW_MGMT_TSG_ID"
	EnvMgmtEndpoint      = "PANW_MGMT_ENDPOINT"
	EnvMgmtTokenEndpoint = "PANW_MGMT_TOKEN_ENDPOINT"
)

// Environment variable names — Model Security API.
const (
	EnvModelSecClientID      = "PANW_MODEL_SEC_CLIENT_ID"
	EnvModelSecClientSecret  = "PANW_MODEL_SEC_CLIENT_SECRET"
	EnvModelSecTsgID         = "PANW_MODEL_SEC_TSG_ID"
	EnvModelSecDataEndpoint  = "PANW_MODEL_SEC_DATA_ENDPOINT"
	EnvModelSecMgmtEndpoint  = "PANW_MODEL_SEC_MGMT_ENDPOINT"
	EnvModelSecTokenEndpoint = "PANW_MODEL_SEC_TOKEN_ENDPOINT"
)

// Environment variable names — Red Team API.
const (
	EnvRedTeamClientID      = "PANW_RED_TEAM_CLIENT_ID"
	EnvRedTeamClientSecret  = "PANW_RED_TEAM_CLIENT_SECRET"
	EnvRedTeamTsgID         = "PANW_RED_TEAM_TSG_ID"
	EnvRedTeamDataEndpoint  = "PANW_RED_TEAM_DATA_ENDPOINT"
	EnvRedTeamMgmtEndpoint  = "PANW_RED_TEAM_MGMT_ENDPOINT"
	EnvRedTeamTokenEndpoint = "PANW_RED_TEAM_TOKEN_ENDPOINT"
)

// Content length limits (bytes).
const (
	MaxContentPromptLength   = 2 * 1024 * 1024   // 2 MB
	MaxContentResponseLength = 2 * 1024 * 1024   // 2 MB
	MaxContentContextLength  = 100 * 1024 * 1024 // 100 MB
)

// Auth limits.
const (
	MaxAPIKeyLength = 2048
	MaxTokenLength  = 2048
)

// String length limits.
const (
	MaxTransactionIDLength = 100
	MaxSessionIDLength     = 100
	MaxScanIDLength        = 36
	MaxReportIDLength      = 40
	MaxAIProfileNameLength = 100
)

// Batch / query limits.
const (
	MaxNumberOfScanIDs          = 5
	MaxNumberOfReportIDs        = 5
	MaxNumberOfBatchScanObjects = 5
)

// HTTP / retry.
const (
	MaxConnectionPoolSize = 100
	MaxNumberOfRetries    = 5
)

// HTTPForceRetryStatusCodes are HTTP status codes that trigger automatic retry.
var HTTPForceRetryStatusCodes = []int{500, 502, 503, 504}

// API paths — Scan.
const (
	SyncScanPath    = "/v1/scan/sync/request"
	AsyncScanPath   = "/v1/scan/async/request"
	ScanResultsPath = "/v1/scan/results"
	ScanReportsPath = "/v1/scan/reports"
)

// API paths — Management.
const (
	MgmtProfilePath            = "/v1/mgmt/profile"
	MgmtProfilesTsgPath        = "/v1/mgmt/profiles/tsg"
	MgmtTopicPath              = "/v1/mgmt/topic"
	MgmtTopicsTsgPath          = "/v1/mgmt/topics/tsg"
	MgmtTopicForcePath         = "/v1/mgmt/topic"
	MgmtProfileForcePath       = "/v1/mgmt/profile"
	MgmtAPIKeyPath             = "/v1/mgmt/apikey"
	MgmtAPIKeysTsgPath         = "/v1/mgmt/apikeys/tsg"
	MgmtDLPProfilesPath        = "/v1/mgmt/dlpprofiles"
	MgmtDeploymentProfilesPath = "/v1/mgmt/deploymentprofiles"
	MgmtScanLogsPath           = "/v1/mgmt/scanlogs"
	MgmtCustomerAppPath        = "/v1/mgmt/customerapp"
	MgmtCustomerAppsPath       = "/v1/mgmt/customerapps"
	MgmtOAuthInvalidatePath    = "/v1/mgmt/oauth/invalidateToken"
	MgmtOAuthTokenPath         = "/v1/mgmt/oauth/client_credential/accesstoken"
)

// API paths — Model Security data plane.
const (
	ModelSecScansPath       = "/v1/scans"
	ModelSecEvaluationsPath = "/v1/evaluations"
	ModelSecViolationsPath  = "/v1/violations"
)

// API paths — Model Security management plane.
const (
	ModelSecSecurityGroupsPath = "/v1/security-groups"
	ModelSecSecurityRulesPath  = "/v1/security-rules"
	ModelSecPyPIAuthPath       = "/v1/pypi/authenticate"
)

// API paths — Red Team data plane.
const (
	RedTeamScanPath                = "/v1/scan"
	RedTeamCategoriesPath          = "/v1/categories"
	RedTeamReportStaticPath        = "/v1/report/static"
	RedTeamReportDynamicPath       = "/v1/report/dynamic"
	RedTeamReportPath              = "/v1/report"
	RedTeamCustomAttacksReportPath = "/v1/custom-attacks"
	RedTeamDashboardPath           = "/v1/dashboard"
	RedTeamQuotaPath               = "/v1/metering/quota"
	RedTeamErrorLogPath            = "/v1/error-log/job"
	RedTeamSentimentPath           = "/v1/sentiment"
)

// API paths — Red Team management plane.
const (
	RedTeamTargetPath        = "/v1/target"
	RedTeamCustomAttackPath  = "/v1/custom-attack"
	RedTeamMgmtDashboardPath = "/v1/dashboard/overview"

	// Custom attack prompt set sub-paths (management plane).
	RedTeamCustomPromptSetPath        = "/v1/custom-attack/custom-prompt-set"
	RedTeamListCustomPromptSetsPath   = "/v1/custom-attack/list-custom-prompt-sets"
	RedTeamActiveCustomPromptSetsPath = "/v1/custom-attack/active-custom-prompt-sets"

	// Report download (data plane).
	RedTeamReportDownloadPath = "/v1/report"
)
