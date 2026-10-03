package aisec

// Environment variable names and paths for the AgentGuard public preview.
// The preview does not declare server URLs; endpoints must be configured.
const (
	EnvAgentGuardClientID        = "PANW_AGENT_GUARD_CLIENT_ID"
	EnvAgentGuardClientSecret    = "PANW_AGENT_GUARD_CLIENT_SECRET"
	EnvAgentGuardTsgID           = "PANW_AGENT_GUARD_TSG_ID"
	EnvAgentGuardTokenEndpoint   = "PANW_AGENT_GUARD_TOKEN_ENDPOINT"
	EnvAgentGuardDataEndpoint    = "PANW_AGENT_GUARD_DATA_ENDPOINT"
	EnvAgentGuardMgmtEndpoint    = "PANW_AGENT_GUARD_MGMT_ENDPOINT"
	AgentGuardScansPath          = "/v1/scans"
	AgentGuardScanCSVPath        = "/v1/scans/csv"
	AgentGuardScanLookupPath     = "/v1/scans/lookup"
	AgentGuardUploadURLPath      = "/v1/scans/upload-url"
	AgentGuardRuleStatsPath      = "/v1/stats/rules"
	AgentGuardScanStatsPath      = "/v1/stats/scans"
	AgentGuardInstancesPath      = "/v1/instances"
	AgentGuardRulesPath          = "/v1/rules"
	AgentGuardRuleInstancesPath  = "/v1/rule-instances"
	AgentGuardSkillOverridesPath = "/v1/skill-overrides"
)

// Version and user agent.
const (
	Version   = "0.7.0"
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
var HTTPForceRetryStatusCodes = []int{429, 500, 502, 503, 504}

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
	RedTeamTargetPath             = "/v1/target"
	RedTeamTargetValidateAuthPath = "/v1/target/validate-auth"
	RedTeamCustomAttackPath       = "/v1/custom-attack"
	RedTeamMgmtDashboardPath      = "/v1/dashboard/overview"
	RedTeamTemplatePath           = "/v1/template"

	// Custom attack prompt set sub-paths (management plane).
	RedTeamCustomPromptSetPath        = "/v1/custom-attack/custom-prompt-set"
	RedTeamListCustomPromptSetsPath   = "/v1/custom-attack/list-custom-prompt-sets"
	RedTeamActiveCustomPromptSetsPath = "/v1/custom-attack/active-custom-prompt-sets"

	// CSV upload/download (management plane).
	RedTeamUploadPromptsCsvPath = "/v1/custom-attack/upload-custom-prompts-csv"
	RedTeamDownloadTemplatePath = "/v1/custom-attack/download-template"

	// Report download (data plane).
	RedTeamReportDownloadPath = "/v1/report"

	// Registry credentials (management plane).
	RedTeamRegistryCredentialsPath = "/v1/registry-credentials"

	// EULA (management plane).
	RedTeamEulaPath = "/v1/eula"

	// Instances/Licensing (management plane).
	RedTeamInstancesPath = "/v1/instances"
)

// Current Model Security inventory and custom-rule collections.
const (
	ModelSecModelsPath        = "/v1/models"
	ModelSecModelVersionsPath = "/v1/model-versions"
	ModelSecCustomRulesPath   = "/v1/custom-rules"
)

// Red Team adapter management and Network Broker routing.
const (
	RedTeamAdaptersPath          = "/v1/adapters"
	RedTeamChannelsPath          = "/v1/channels"
	DefaultRedTeamBrokerEndpoint = "https://api.sase.paloaltonetworks.com/ai-red-teaming/data-plane/network-broker"
	EnvRedTeamBrokerEndpoint     = "PANW_RED_TEAM_BROKER_ENDPOINT"
)

// Additional Red Team metadata, report receipts and profiling logs.
const (
	RedTeamLanguagesPath             = "/v1/languages"
	RedTeamGoalCategoriesPath        = "/v1/goal-categories"
	RedTeamReportV2Path              = "/v2/report"
	RedTeamTargetProfileErrorLogPath = "/v1/error-log/target-profile"
	RedTeamScanMetadataPath          = "/v1/scan/scan-metadata"
)

// AI Gateway management clients share SCM OAuth and route explicit CRUD planes.
const (
	DefaultGatewayDataEndpoint  = "https://api.apps.paloaltonetworks.com/ai_gw/v2"
	DefaultGatewayAdminEndpoint = "https://api.apps.paloaltonetworks.com/ai_gw/admin/v2"
	EnvGatewayDataEndpoint      = "PANW_AI_GW_DATA_ENDPOINT"
	EnvGatewayAdminEndpoint     = "PANW_AI_GW_ADMIN_ENDPOINT"
	HeaderTsgID                 = "x-tsg-id"
	GatewayGuardrailsPath       = "/guardrails"
	GatewayOrgGuardrailsPath    = "/guardrails"
	GatewayConfigsPath          = "/configs"
	GatewayIntegrationsPath     = "/integrations"
	GatewayProvidersPath        = "/providers"
	GatewayMCPIntegrationsPath  = "/mcp-integrations"
	GatewayMCPServersPath       = "/mcp-servers"
	GatewayAPIKeysPath          = "/api-keys"
	GatewayUsageLimitsPath      = "/policies/usage-limits"
	GatewayRateLimitsPath       = "/policies/rate-limits"
	GatewaySecretReferencesPath = "/secret-references"
	GatewayDeploymentsPath      = "/deployments"
	DefaultIAMEndpoint          = "https://api.apps.paloaltonetworks.com/iam/v1"
	EnvIAMEndpoint              = "PANW_IAM_ENDPOINT"
	IAMScopesPath               = "/scopes"
	GatewayWorkspacesPath       = "/workspaces"
	DefaultDLPEndpoint          = "https://api.dlp.paloaltonetworks.com"
	EnvGatewayInferenceEndpoint = "PANW_AI_GW_INFERENCE_ENDPOINT"
	EnvGatewayInferenceAPIKey   = "PANW_AI_GW_INFERENCE_API_KEY"
)

// Additional TypeScript SDK management and inference route contracts.
const (
	MgmtProfilesTokenPath       = "/v1/mgmt/profiles"
	MgmtTopicsTokenPath         = "/v1/mgmt/topics"
	MgmtAPIKeysTokenPath        = "/v1/mgmt/apikeys"
	MgmtCustomerAppsTokenPath   = "/v1/mgmt/customerapps"
	GatewayProviderCatalogPath  = "/utils/static-resources/ai-providers"
	GatewayGuardrailCatalogPath = "/utils/static-resources/schema"
)

// TypeScript parity route prefixes, outside current vendor OpenAPI coverage.
const (
	GatewayAnalyticsFilterBoundariesPath                          = "/analytics/filter-boundaries"
	GatewayAuditLogsPath                                          = "/audit-logs"
	GatewayAuthSettingsPath                                       = "/auth-settings"
	GatewayCancelPath                                             = "/cancel"
	GatewayDownloadPath                                           = "/download"
	GatewayInferenceAudioSpeechPath                               = "/audio/speech"
	GatewayInferenceAudioTranscriptionsPath                       = "/audio/transcriptions"
	GatewayInferenceAudioTranslationsPath                         = "/audio/translations"
	GatewayInferenceBatchesPath                                   = "/batches"
	GatewayInferenceCancelPath                                    = "/cancel"
	GatewayInferenceChatCompletionsPath                           = "/chat/completions"
	GatewayInferenceCheckpointsPath                               = "/checkpoints"
	GatewayInferenceCompletionsPath                               = "/completions"
	GatewayInferenceContentPath                                   = "/content"
	GatewayInferenceEmbeddingsPath                                = "/embeddings"
	GatewayInferenceEventsPath                                    = "/events"
	GatewayInferenceFeedbackPath                                  = "/feedback"
	GatewayInferenceFileBatchesPath                               = "/file_batches"
	GatewayInferenceFilesPath                                     = "/files"
	GatewayInferenceFineTuningJobsPath                            = "/fine_tuning/jobs"
	GatewayInferenceImagesEditsPath                               = "/images/edits"
	GatewayInferenceImagesGenerationsPath                         = "/images/generations"
	GatewayInferenceImagesVariationsPath                          = "/images/variations"
	GatewayInferenceInputItemsPath                                = "/input_items"
	GatewayInferenceLogsPath                                      = "/logs"
	GatewayInferenceModelsPath                                    = "/models"
	GatewayInferenceModerationsPath                               = "/moderations"
	GatewayInferenceOcrPath                                       = "/ocr"
	GatewayInferenceOutputPath                                    = "/output"
	GatewayInferencePromptsPath                                   = "/prompts"
	GatewayInferenceRealtimePath                                  = "/realtime"
	GatewayInferenceRenderPath                                    = "/render"
	GatewayInferenceRerankPath                                    = "/rerank"
	GatewayInferenceResponsesPath                                 = "/responses"
	GatewayInferenceVectorStoresPath                              = "/vector_stores"
	GatewayInfoPath                                               = "/info"
	GatewayLogsChartsCacheHitTrendPath                            = "/logs/charts/cache-hit-trend"
	GatewayLogsChartsCacheSummaryPath                             = "/logs/charts/cache-summary"
	GatewayLogsChartsCostPath                                     = "/logs/charts/cost"
	GatewayLogsChartsErrorCategoryTrendsPath                      = "/logs/charts/error-category-trends"
	GatewayLogsChartsErrorTrendsPath                              = "/logs/charts/error-trends"
	GatewayLogsChartsErrorsPath                                   = "/logs/charts/errors"
	GatewayLogsChartsFeedbackModelsPath                           = "/logs/charts/feedback-models"
	GatewayLogsChartsFeedbackScoreDistributionPath                = "/logs/charts/feedback-score-distribution"
	GatewayLogsChartsFeedbackTrendPath                            = "/logs/charts/feedback-trend"
	GatewayLogsChartsFeedbackWeightedPath                         = "/logs/charts/feedback-weighted"
	GatewayLogsChartsGroupedErrorsPath                            = "/logs/charts/grouped-errors"
	GatewayLogsChartsLatencyPath                                  = "/logs/charts/latency"
	GatewayLogsChartsRequestsPath                                 = "/logs/charts/requests"
	GatewayLogsChartsRescuedRetriesPath                           = "/logs/charts/rescued-retries"
	GatewayLogsChartsTokensPath                                   = "/logs/charts/tokens"
	GatewayLogsChartsUserTrendsPath                               = "/logs/charts/user-trends"
	GatewayLogsChartsUsersPath                                    = "/logs/charts/users"
	GatewayLogsExportsPath                                        = "/logs/exports"
	GatewayLogsGroupsPath                                         = "/logs/groups"
	GatewayLogsGroupsStatusCodePath                               = "/logs/groups/status_code"
	GatewayLogsGroupsUsersPath                                    = "/logs/groups/users"
	GatewayLogsPath                                               = "/logs"
	GatewayModelConfigsPricingPath                                = "/model-configs/pricing"
	GatewayOrganisationsPath                                      = "/organisations"
	GatewayOrganisationsSelfPath                                  = "/organisations/self"
	GatewayPluginsPath                                            = "/plugins"
	GatewayStartPath                                              = "/start"
	RuntimeV1MgmtDashboardV2AppsApplicationPath                   = "/v1/mgmt/dashboard/v2/apps/application"
	RuntimeV1MgmtDashboardV2AppsApplicationsoverviewPath          = "/v1/mgmt/dashboard/v2/apps/applicationsoverview"
	RuntimeV1MgmtDashboardV2AppsApplicationsviolationstrendPath   = "/v1/mgmt/dashboard/v2/apps/applicationsviolationstrend"
	RuntimeV1MgmtDashboardV2AppsApplicationviolationbreakdownPath = "/v1/mgmt/dashboard/v2/apps/applicationviolationbreakdown"
	RuntimeV1MgmtDashboardV2AppsAppslistPath                      = "/v1/mgmt/dashboard/v2/apps/appslist"
	RuntimeV1MgmtDashboardV2AppsTopapplicationsviolationsPath     = "/v1/mgmt/dashboard/v2/apps/topapplicationsviolations"
	RuntimeV1MgmtDashboardV2SessionsSessionPath                   = "/v1/mgmt/dashboard/v2/sessions/session"
	RuntimeV1MgmtDashboardV2SessionsSessionschartPath             = "/v1/mgmt/dashboard/v2/sessions/sessionschart"
	RuntimeV1MgmtDashboardV2SessionsSessionsoverviewPath          = "/v1/mgmt/dashboard/v2/sessions/sessionsoverview"
	RuntimeV1MgmtDashboardV2SessionsSessiontransactionPath        = "/v1/mgmt/dashboard/v2/sessions/sessiontransaction"
	RuntimeV1MgmtReportsScancontentPath                           = "/v1/mgmt/reports/scancontent"
	RuntimeV2ApiDataFilteringProfilesPath                         = "/v2/api/data-filtering-profiles"
	RuntimeV2ApiDataPatternsPath                                  = "/v2/api/data-patterns"
	RuntimeV2ApiDataProfilesPath                                  = "/v2/api/data-profiles"
	RuntimeV2ApiDictionariesPath                                  = "/v2/api/dictionaries"
)

const (
	EnvDLPEndpoint       = "PANW_MGMT_DLP_ENDPOINT"
	EnvDashboardEndpoint = "PANW_MGMT_DASHBOARD_ENDPOINT"
)

// MaxDottedArrayElements bounds allocations while building dotted configuration paths.
const MaxDottedArrayElements = 10000
