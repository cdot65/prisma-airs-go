package management

// ListOpts are common pagination options.
type ListOpts struct {
	Limit  int
	Offset int
}

// --- Policy nested types (AIProfileObject.policy) ---

// LatencyConfig holds latency configuration for an AI security profile.
type LatencyConfig struct {
	InlineTimeoutAction string `json:"inline-timeout-action,omitempty"`
	MaxInlineLatency    int32  `json:"max-inline-latency,omitempty"`
}

// ToxicCategoryConfig holds per-category toxic content configuration.
type ToxicCategoryConfig struct {
	Category string `json:"category"`
	Action   string `json:"action"`
}

// TopicRef references a custom topic by name, ID, and revision.
type TopicRef struct {
	TopicName string `json:"topic_name"`
	TopicID   string `json:"topic_id"`
	Revision  int64  `json:"revision"`
}

// TopicArrayConfig holds a topic guardrail action + topic list.
type TopicArrayConfig struct {
	Action string     `json:"action"`
	Topic  []TopicRef `json:"topic"`
}

// DataLeakMember is a DLP data leak member entry.
type DataLeakMember struct {
	Text    string `json:"text"`
	ID      string `json:"id,omitempty"`
	Version string `json:"version,omitempty"`
}

// DataLeakDetectionConfig holds data leak detection configuration.
type DataLeakDetectionConfig struct {
	Member         []DataLeakMember `json:"member"`
	Action         string           `json:"action"`
	MaskDataInline bool             `json:"mask-data-inline,omitempty"`
}

// DataProtectionConfig holds data protection configuration.
type DataProtectionConfig struct {
	DataLeakDetection *DataLeakDetectionConfig `json:"data-leak-detection,omitempty"`
}

// URLCategoryMember holds URL category member list.
type URLCategoryMember struct {
	Member []string `json:"member,omitempty"`
}

// AppProtectionConfig holds app protection URL category configuration.
type AppProtectionConfig struct {
	AlertURLCategory *URLCategoryMember `json:"alert-url-category,omitempty"`
	BlockURLCategory *URLCategoryMember `json:"block-url-category,omitempty"`
	AllowURLCategory *URLCategoryMember `json:"allow-url-category,omitempty"`
}

// ModelProtectionConfig holds model protection configuration.
type ModelProtectionConfig struct {
	Name              string                `json:"name"`
	Action            string                `json:"action"`
	ToxicCategoryList []ToxicCategoryConfig `json:"toxic-category-list,omitempty"`
	TopicList         []TopicArrayConfig    `json:"topic-list,omitempty"`
}

// AgentProtectionConfig holds agent protection configuration.
type AgentProtectionConfig struct {
	Name   string `json:"name"`
	Action string `json:"action"`
}

// ModelConfiguration holds the model-configuration section of a security profile.
type ModelConfiguration struct {
	MaskDataInStorage bool                    `json:"mask-data-in-storage,omitempty"`
	Latency           *LatencyConfig          `json:"latency,omitempty"`
	DataProtection    *DataProtectionConfig   `json:"data-protection,omitempty"`
	AppProtection     *AppProtectionConfig    `json:"app-protection,omitempty"`
	ModelProtection   []ModelProtectionConfig `json:"model-protection,omitempty"`
	AgentProtection   []AgentProtectionConfig `json:"agent-protection,omitempty"`
}

// AiSecurityProfileConfig is one entry in the ai-security-profiles array.
type AiSecurityProfileConfig struct {
	ModelType          string              `json:"model-type,omitempty"`
	ContentType        string              `json:"content-type,omitempty"`
	ModelConfiguration *ModelConfiguration `json:"model-configuration,omitempty"`
}

// DLPDataProfileConfig is one entry in the dlp-data-profiles array.
type DLPDataProfileConfig struct {
	Name         string         `json:"name,omitempty"`
	UUID         string         `json:"uuid,omitempty"`
	ID           string         `json:"id,omitempty"`
	Version      string         `json:"version,omitempty"`
	Rule1        map[string]any `json:"rule1,omitempty"`
	Rule2        map[string]any `json:"rule2,omitempty"`
	LogSeverity  string         `json:"log-severity,omitempty"`
	NonFileBased string         `json:"non-file-based,omitempty"`
	FileBased    string         `json:"file-based,omitempty"`
}

// ProfilePolicy is the typed policy object inside a SecurityProfile.
type ProfilePolicy struct {
	DlpDataProfiles    []DLPDataProfileConfig    `json:"dlp-data-profiles,omitempty"`
	AiSecurityProfiles []AiSecurityProfileConfig `json:"ai-security-profiles,omitempty"`
}

// SecurityProfile represents an AI security profile.
type SecurityProfile struct {
	ProfileID      string         `json:"profile_id,omitempty"`
	ProfileName    string         `json:"profile_name,omitempty"`
	Revision       int32          `json:"revision,omitempty"`
	Active         bool           `json:"active,omitempty"`
	Policy         *ProfilePolicy `json:"policy,omitempty"`
	CreatedBy      string         `json:"created_by,omitempty"`
	UpdatedBy      string         `json:"updated_by,omitempty"`
	LastModifiedTs string         `json:"last_modified_ts,omitempty"`
}

// SecurityProfileListResponse is the list response for profiles.
type SecurityProfileListResponse struct {
	Items      []SecurityProfile `json:"ai_profiles"`
	NextOffset int               `json:"next_offset,omitempty"`
}

// CreateProfileRequest is the request to create a profile.
type CreateProfileRequest struct {
	ProfileName string         `json:"profile_name"`
	Policy      *ProfilePolicy `json:"policy,omitempty"`
}

// UpdateProfileRequest is the request to update a profile.
type UpdateProfileRequest struct {
	ProfileName string         `json:"profile_name,omitempty"`
	Policy      *ProfilePolicy `json:"policy,omitempty"`
}

// DeleteProfileResponse is the response from deleting a profile.
type DeleteProfileResponse struct {
	Message string `json:"message,omitempty"`
}

// CustomTopic represents a custom detection topic.
type CustomTopic struct {
	TopicID        string   `json:"topic_id,omitempty"`
	TopicName      string   `json:"topic_name,omitempty"`
	Revision       int64    `json:"revision,omitempty"`
	Active         bool     `json:"active,omitempty"`
	Description    string   `json:"description,omitempty"`
	Examples       []string `json:"examples,omitempty"`
	CreatedBy      string   `json:"created_by,omitempty"`
	UpdatedBy      string   `json:"updated_by,omitempty"`
	LastModifiedTs string   `json:"last_modified_ts,omitempty"`
	CreatedTs      string   `json:"created_ts,omitempty"`
}

// CustomTopicListResponse is the list response for topics.
type CustomTopicListResponse struct {
	Items      []CustomTopic `json:"custom_topics"`
	NextOffset int           `json:"next_offset,omitempty"`
}

// CreateTopicRequest is the request to create a topic.
type CreateTopicRequest struct {
	TopicName   string   `json:"topic_name"`
	Description string   `json:"description,omitempty"`
	Examples    []string `json:"examples,omitempty"`
}

// UpdateTopicRequest is the request to update a topic.
type UpdateTopicRequest struct {
	TopicName   string   `json:"topic_name,omitempty"`
	Description string   `json:"description,omitempty"`
	Examples    []string `json:"examples,omitempty"`
}

// DeleteTopicResponse is the response from deleting a topic.
type DeleteTopicResponse struct {
	Message string `json:"message,omitempty"`
}

// ApiKey represents an API key with all spec-defined fields.
type ApiKey struct {
	ApiKeyID             string `json:"api_key_id,omitempty"`
	ApiKeyLast8          string `json:"api_key_last8,omitempty"`
	ApiKeyName           string `json:"api_key_name,omitempty"`
	AuthCode             string `json:"auth_code,omitempty"`
	CspID                string `json:"csp_id,omitempty"`
	TsgID                string `json:"tsg_id,omitempty"`
	Expiration           string `json:"expiration,omitempty"`
	Revoked              bool   `json:"revoked,omitempty"`
	RevokeReason         string `json:"revoke_reason,omitempty"`
	CustApp              string `json:"cust_app,omitempty"`
	CustEnv              string `json:"cust_env,omitempty"`
	CustAIAgentFramework string `json:"cust_ai_agent_framework,omitempty"`
	CustCloudProvider    string `json:"cust_cloud_provider,omitempty"`
	CreatedBy            string `json:"created_by,omitempty"`
	UpdatedBy            string `json:"updated_by,omitempty"`
	LastModifiedTS       string `json:"last_modified_ts,omitempty"`
	RotationTimeInterval int32  `json:"rotation_time_interval,omitempty"`
	RotationTimeUnit     string `json:"rotation_time_unit,omitempty"`
	DpName               string `json:"dp_name,omitempty"`
	Status               string `json:"status,omitempty"`
	ApiKey               string `json:"api_key,omitempty"`
	LicExpiration        string `json:"lic_expiration,omitempty"`
	AvgTextRecords       int32  `json:"avg_text_records,omitempty"`
	CreationTS           string `json:"creation_ts,omitempty"`
	CustomerAppID        string `json:"customer_appId,omitempty"`
}

// ApiKeyListResponse is the list response for API keys.
type ApiKeyListResponse struct {
	Items      []ApiKey `json:"api_keys"`
	NextOffset int      `json:"next_offset,omitempty"`
}

// CreateApiKeyRequest is the request to create an API key.
type CreateApiKeyRequest struct {
	ApiKeyName           string `json:"api_key_name"`
	AuthCode             string `json:"auth_code"`
	Revoked              bool   `json:"revoked"`
	CustApp              string `json:"cust_app"`
	CreatedBy            string `json:"created_by"`
	RotationTimeInterval int32  `json:"rotation_time_interval"`
	RotationTimeUnit     string `json:"rotation_time_unit"`
	DpName               string `json:"dp_name,omitempty"`
	CustEnv              string `json:"cust_env,omitempty"`
	CustCloudProvider    string `json:"cust_cloud_provider,omitempty"`
	CustAIAgentFramework string `json:"cust_ai_agent_framework,omitempty"`
}

// RegenerateKeyRequest is the request to regenerate an API key.
type RegenerateKeyRequest struct {
	UpdatedBy            string `json:"updated_by,omitempty"`
	RotationTimeInterval int32  `json:"rotation_time_interval"`
	RotationTimeUnit     string `json:"rotation_time_unit"`
}

// ApiKeyDeleteResponse is the response from deleting an API key.
type ApiKeyDeleteResponse struct {
	Message string `json:"message,omitempty"`
}

// CustomerApp represents a customer application.
type CustomerApp struct {
	CustomerAppID    string `json:"customer_appId,omitempty"`
	AppName          string `json:"app_name,omitempty"`
	TsgID            string `json:"tsg_id,omitempty"`
	ModelName        string `json:"model_name,omitempty"`
	CloudProvider    string `json:"cloud_provider,omitempty"`
	Environment      string `json:"environment,omitempty"`
	Status           string `json:"status,omitempty"`
	CreatedBy        string `json:"created_by,omitempty"`
	UpdatedBy        string `json:"updated_by,omitempty"`
	AiAgentFramework string `json:"ai_agent_framework,omitempty"`
}

// CustomerAppListResponse is the list response for customer apps.
type CustomerAppListResponse struct {
	Items      []CustomerApp `json:"customer_apps"`
	NextOffset int           `json:"next_offset,omitempty"`
}

// CreateAppRequest is the request to create a customer app.
type CreateAppRequest struct {
	AppName       string `json:"app_name"`
	TsgID         string `json:"tsg_id"`
	CloudProvider string `json:"cloud_provider"`
	Environment   string `json:"environment"`
}

// UpdateAppRequest is the request to update a customer app.
type UpdateAppRequest struct {
	AppName       string `json:"app_name,omitempty"`
	ModelName     string `json:"model_name,omitempty"`
	CloudProvider string `json:"cloud_provider,omitempty"`
	Environment   string `json:"environment,omitempty"`
}

// DeleteAppResponse is the response from deleting a customer app.
type DeleteAppResponse struct {
	Message string `json:"message,omitempty"`
}

// DlpProfile represents a DLP data profile.
type DlpProfile struct {
	ID           string         `json:"id,omitempty"`
	Name         string         `json:"name,omitempty"`
	Description  string         `json:"description,omitempty"`
	FileBased    string         `json:"file-based,omitempty"`
	NonFileBased string         `json:"non-file-based,omitempty"`
	LogSeverity  string         `json:"log-severity,omitempty"`
	Rule1        map[string]any `json:"rule1,omitempty"`
	Rule2        map[string]any `json:"rule2,omitempty"`
	UUID         string         `json:"uuid,omitempty"`
	Version      string         `json:"version,omitempty"`
}

// DlpProfileListResponse is the list response for DLP profiles.
type DlpProfileListResponse struct {
	Items []DlpProfile `json:"dlp_profiles"`
}

// DeploymentProfile represents a deployment profile.
type DeploymentProfile struct {
	AuthCode       string `json:"auth_code,omitempty"`
	DpName         string `json:"dp_name,omitempty"`
	TsgID          string `json:"tsg_id,omitempty"`
	Status         string `json:"status,omitempty"`
	ExpirationDate string `json:"expiration_date,omitempty"`
	AveTextRecords int32  `json:"ave_text_records,omitempty"`
}

// DeploymentProfileListResponse is the list response for deployment profiles.
type DeploymentProfileListResponse struct {
	Items  []DeploymentProfile `json:"deployment_profiles"`
	Status string              `json:"status,omitempty"`
}

// ScanLog represents a scan activity log entry with all spec-defined fields.
type ScanLog struct {
	CspID                 string `json:"csp_id,omitempty"`
	TsgID                 string `json:"tsg_id,omitempty"`
	ScanID                string `json:"scan_id,omitempty"`
	ScanSubReqID          int32  `json:"scan_sub_req_id,omitempty"`
	TransactionID         string `json:"transaction_id,omitempty"`
	ApiKeyName            string `json:"api_key_name,omitempty"`
	ProfileID             string `json:"profile_id,omitempty"`
	ProfileName           string `json:"profile_name,omitempty"`
	AppName               string `json:"app_name,omitempty"`
	ModelName             string `json:"model_name,omitempty"`
	User                  string `json:"user,omitempty"`
	Environment           string `json:"environment,omitempty"`
	CloudProvider         string `json:"cloud_provider,omitempty"`
	AgentFramework        string `json:"agent_framework,omitempty"`
	Tokens                int32  `json:"tokens,omitempty"`
	TextRecords           int32  `json:"text_records,omitempty"`
	ReportID              string `json:"report_id,omitempty"`
	ReceivedTS            string `json:"received_ts,omitempty"`
	CompletedTS           string `json:"completed_ts,omitempty"`
	Status                string `json:"status,omitempty"`
	Verdict               string `json:"verdict,omitempty"`
	Action                string `json:"action,omitempty"`
	IsPrompt              bool   `json:"is_prompt,omitempty"`
	IsResponse            bool   `json:"is_response,omitempty"`
	PIFinalVerdict        string `json:"pi_final_verdict,omitempty"`
	UFFinalVerdict        string `json:"uf_final_verdict,omitempty"`
	DLPFinalVerdict       string `json:"dlp_final_verdict,omitempty"`
	DBSFinalVerdict       string `json:"dbs_final_verdict,omitempty"`
	TCFinalVerdict        string `json:"tc_final_verdict,omitempty"`
	MCFinalVerdict        string `json:"mc_final_verdict,omitempty"`
	AgentFinalVerdict     string `json:"agent_final_verdict,omitempty"`
	CGFinalVerdict        string `json:"cg_final_verdict,omitempty"`
	TGFinalVerdict        string `json:"tg_final_verdict,omitempty"`
	PromptPIVerdict       string `json:"prompt_pi_verdict,omitempty"`
	PromptUFVerdict       string `json:"prompt_uf_verdict,omitempty"`
	PromptDLPVerdict      string `json:"prompt_dlp_verdict,omitempty"`
	PromptTCVerdict       string `json:"prompt_tc_verdict,omitempty"`
	PromptMCVerdict       string `json:"prompt_mc_verdict,omitempty"`
	PromptAgentVerdict    string `json:"prompt_agent_verdict,omitempty"`
	PromptTGVerdict       string `json:"prompt_tg_verdict,omitempty"`
	PromptVerdict         string `json:"prompt_verdict,omitempty"`
	PromptPIAction        string `json:"prompt_pi_action,omitempty"`
	PromptUFAction        string `json:"prompt_uf_action,omitempty"`
	PromptDLPAction       string `json:"prompt_dlp_action,omitempty"`
	PromptTCAction        string `json:"prompt_tc_action,omitempty"`
	PromptMCAction        string `json:"prompt_mc_action,omitempty"`
	PromptAgentAction     string `json:"prompt_agent_action,omitempty"`
	PromptTGAction        string `json:"prompt_tg_action,omitempty"`
	ResponseUFVerdict     string `json:"response_uf_verdict,omitempty"`
	ResponseDLPVerdict    string `json:"response_dlp_verdict,omitempty"`
	ResponseDBSVerdict    string `json:"response_dbs_verdict,omitempty"`
	ResponseTCVerdict     string `json:"response_tc_verdict,omitempty"`
	ResponseMCVerdict     string `json:"response_mc_verdict,omitempty"`
	ResponseAgentVerdict  string `json:"response_agent_verdict,omitempty"`
	ResponseCGVerdict     string `json:"response_cg_verdict,omitempty"`
	ResponseTGVerdict     string `json:"response_tg_verdict,omitempty"`
	ResponseUFAction      string `json:"response_uf_action,omitempty"`
	ResponseDLPAction     string `json:"response_dlp_action,omitempty"`
	ResponseDBSAction     string `json:"response_dbs_action,omitempty"`
	ResponseTCAction      string `json:"response_tc_action,omitempty"`
	ResponseMCAction      string `json:"response_mc_action,omitempty"`
	ResponseAgentAction   string `json:"response_agent_action,omitempty"`
	ResponseCGAction      string `json:"response_cg_action,omitempty"`
	ResponseTGAction      string `json:"response_tg_action,omitempty"`
	ResponseVerdict       string `json:"response_verdict,omitempty"`
	DetectionServiceFlags int32  `json:"detection_service_flags,omitempty"`
	ContentMasked         bool   `json:"content_masked,omitempty"`
	UserIP                string `json:"user_ip,omitempty"`
}

// ScanLogListOpts are options for listing scan logs (spec: POST /v1/mgmt/scanlogs).
type ScanLogListOpts struct {
	TimeInterval int64  // required: time_interval query param
	TimeUnit     string // required: time_unit query param (hour, day, etc.)
	PageNumber   int32  // required: pageNumber query param
	PageSize     int32  // required: pageSize query param
	Filter       string // required: filter query param (all|benign|threat)
	PageToken    string // optional: sent in request body as PageTokenJsonObject
}

// PageTokenRequest is the request body for paginated scan log queries.
type PageTokenRequest struct {
	PageToken string `json:"page_token,omitempty"`
}

// ScanResultForDashboard contains dashboard-level scan result summary.
type ScanResultForDashboard struct {
	TextRecordsCount       int32     `json:"text_records_count,omitempty"`
	APICallsCount          int32     `json:"api_calls_count,omitempty"`
	ThreatsCount           int32     `json:"threats_count,omitempty"`
	AllTransactionsCount   int32     `json:"all_transactions_count,omitempty"`
	BenignTransactionCount int32     `json:"benign_transaction_count,omitempty"`
	ScanResultEntries      []ScanLog `json:"scan_result_entries,omitempty"`
}

// ScanLogListResponse is the list response for scan logs matching PaginatedScanResultsObject.
type ScanLogListResponse struct {
	ScanResultForDashboard *ScanResultForDashboard `json:"scan_result_for_dashboard,omitempty"`
	TotalPages             int32                   `json:"total_pages,omitempty"`
	PageNumber             int32                   `json:"page_number,omitempty"`
	PageSize               int32                   `json:"page_size,omitempty"`
	PageToken              string                  `json:"page_token,omitempty"`
	Revision               int32                   `json:"revision,omitempty"`
}

// OAuthTokenRequest is the request body for getting an OAuth token via the management API.
type OAuthTokenRequest struct {
	ClientID    string `json:"client_id"`
	CustomerApp string `json:"customer_app,omitempty"`
}

// OAuthToken represents an OAuth token from the management API.
type OAuthToken struct {
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	ExpiresIn   string `json:"expires_in,omitempty"`
	IssuedAt    string `json:"issued_at,omitempty"`
	ClientID    string `json:"client_id,omitempty"`
	Status      string `json:"status,omitempty"`
}

// DeleteConflictResponse is the 409 conflict response when deleting a profile/topic in use.
type DeleteConflictResponse struct {
	Message string            `json:"message,omitempty"`
	Payload []SecurityProfile `json:"payload,omitempty"`
}

// APIKeyDPInfo holds API key + deployment profile info within a customer app.
type APIKeyDPInfo struct {
	ApiKeyName string `json:"api_key_name"`
	DpName     string `json:"dp_name"`
	AuthCode   string `json:"auth_code"`
}

// CustomerAppWithKeyInfo extends CustomerApp with associated API key/DP info.
type CustomerAppWithKeyInfo struct {
	CustomerAppID    string         `json:"customer_appId,omitempty"`
	AppName          string         `json:"app_name,omitempty"`
	TsgID            string         `json:"tsg_id,omitempty"`
	ModelName        string         `json:"model_name,omitempty"`
	CloudProvider    string         `json:"cloud_provider,omitempty"`
	Environment      string         `json:"environment,omitempty"`
	Status           string         `json:"status,omitempty"`
	CreatedBy        string         `json:"created_by,omitempty"`
	UpdatedBy        string         `json:"updated_by,omitempty"`
	AiAgentFramework string         `json:"ai_agent_framework,omitempty"`
	ApiKeysDPInfo    []APIKeyDPInfo `json:"api_keys_dp_info,omitempty"`
}

// InvalidateTokenResponse is the response from invalidating a token.
type InvalidateTokenResponse struct {
	Message string `json:"message,omitempty"`
}
