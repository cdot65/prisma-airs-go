package scan

// AiProfile identifies the security profile for scanning.
type AiProfile struct {
	ProfileID   string `json:"profile_id,omitempty"`
	ProfileName string `json:"profile_name,omitempty"`
}

// Metadata holds application metadata attached to scan requests.
type Metadata struct {
	AppName   string     `json:"app_name,omitempty"`
	AppUser   string     `json:"app_user,omitempty"`
	AIModel   string     `json:"ai_model,omitempty"`
	UserIP    string     `json:"user_ip,omitempty"`
	AgentMeta *AgentMeta `json:"agent_meta,omitempty"`
}

// AgentMeta holds AI agent metadata.
type AgentMeta struct {
	AgentID      string `json:"agent_id,omitempty"`
	AgentVersion string `json:"agent_version,omitempty"`
	AgentARN     string `json:"agent_arn,omitempty"`
}

// ToolEvent represents a tool/function call event.
type ToolEvent struct {
	Metadata *ToolEventMetadata `json:"metadata,omitempty"`
	Input    string             `json:"input,omitempty"`
	Output   string             `json:"output,omitempty"`
}

// ToolEventMetadata holds tool event metadata.
type ToolEventMetadata struct {
	Ecosystem   string `json:"ecosystem"`
	Method      string `json:"method"`
	ServerName  string `json:"server_name"`
	ToolInvoked string `json:"tool_invoked,omitempty"`
}

// ContentInner is the API wire format for a single content item.
type ContentInner struct {
	Prompt       string     `json:"prompt,omitempty"`
	Response     string     `json:"response,omitempty"`
	Context      string     `json:"context,omitempty"`
	CodePrompt   string     `json:"code_prompt,omitempty"`
	CodeResponse string     `json:"code_response,omitempty"`
	ToolEvent    *ToolEvent `json:"tool_event,omitempty"`
}

// ScanRequest is the complete scan request payload.
type ScanRequest struct {
	AiProfile AiProfile      `json:"ai_profile"`
	Contents  []ContentInner `json:"contents"`
	TrID      string         `json:"tr_id,omitempty"`
	SessionID string         `json:"session_id,omitempty"`
	Metadata  *Metadata      `json:"metadata,omitempty"`
}

// ScanResponse is the complete scan response from the AIRS API.
type ScanResponse struct {
	Source                   string            `json:"source,omitempty"`
	ReportID                 string            `json:"report_id"`
	ScanID                   string            `json:"scan_id"`
	TrID                     string            `json:"tr_id,omitempty"`
	SessionID                string            `json:"session_id,omitempty"`
	ProfileID                string            `json:"profile_id,omitempty"`
	ProfileName              string            `json:"profile_name,omitempty"`
	Category                 string            `json:"category"`
	Action                   string            `json:"action"`
	Timeout                  bool              `json:"timeout,omitempty"`
	Error                    bool              `json:"error,omitempty"`
	Errors                   []ContentError    `json:"errors,omitempty"`
	PromptDetected           *PromptDetected   `json:"prompt_detected,omitempty"`
	ResponseDetected         *ResponseDetected `json:"response_detected,omitempty"`
	PromptMaskedData         *MaskedData       `json:"prompt_masked_data,omitempty"`
	ResponseMaskedData       *MaskedData       `json:"response_masked_data,omitempty"`
	PromptDetectionDetails   map[string]any    `json:"prompt_detection_details,omitempty"`
	ResponseDetectionDetails map[string]any    `json:"response_detection_details,omitempty"`
	ToolDetected             *ToolDetected     `json:"tool_detected,omitempty"`
	CreatedAt                string            `json:"created_at,omitempty"`
	CompletedAt              string            `json:"completed_at,omitempty"`
}

// PromptDetected holds detection flags for the prompt.
type PromptDetected struct {
	URLCats        *bool `json:"url_cats,omitempty"`
	DLP            *bool `json:"dlp,omitempty"`
	Injection      *bool `json:"injection,omitempty"`
	ToxicContent   *bool `json:"toxic_content,omitempty"`
	MaliciousCode  *bool `json:"malicious_code,omitempty"`
	Agent          *bool `json:"agent,omitempty"`
	TopicViolation *bool `json:"topic_violation,omitempty"`
}

// ResponseDetected holds detection flags for the response.
type ResponseDetected struct {
	URLCats        *bool `json:"url_cats,omitempty"`
	DLP            *bool `json:"dlp,omitempty"`
	DBSecurity     *bool `json:"db_security,omitempty"`
	ToxicContent   *bool `json:"toxic_content,omitempty"`
	MaliciousCode  *bool `json:"malicious_code,omitempty"`
	Agent          *bool `json:"agent,omitempty"`
	Ungrounded     *bool `json:"ungrounded,omitempty"`
	TopicViolation *bool `json:"topic_violation,omitempty"`
}

// MaskedData holds redacted content and pattern detections.
type MaskedData struct {
	Data              string             `json:"data,omitempty"`
	PatternDetections []PatternDetection `json:"pattern_detections,omitempty"`
}

// PatternDetection represents a detected pattern in content.
// Locations is an array of [start, end] offset pairs.
type PatternDetection struct {
	Pattern   string  `json:"pattern,omitempty"`
	Locations [][]int `json:"locations,omitempty"`
}

// ContentErrorType is the type of content that encountered an error.
type ContentErrorType string

const (
	ContentErrorTypePrompt   ContentErrorType = "prompt"
	ContentErrorTypeResponse ContentErrorType = "response"
)

// DetectionServiceName identifies a detection service.
type DetectionServiceName string

const (
	DetectionServiceDLP            DetectionServiceName = "dlp"
	DetectionServiceInjection      DetectionServiceName = "injection"
	DetectionServiceURLCats        DetectionServiceName = "url_cats"
	DetectionServiceToxicContent   DetectionServiceName = "toxic_content"
	DetectionServiceMaliciousCode  DetectionServiceName = "malicious_code"
	DetectionServiceAgent          DetectionServiceName = "agent"
	DetectionServiceTopicViolation DetectionServiceName = "topic_violation"
	DetectionServiceDBSecurity     DetectionServiceName = "db_security"
	DetectionServiceUngrounded     DetectionServiceName = "ungrounded"
)

// ErrorStatus indicates error or timeout.
type ErrorStatus string

const (
	ErrorStatusError   ErrorStatus = "error"
	ErrorStatusTimeout ErrorStatus = "timeout"
)

// ContentError represents an error during content scanning.
type ContentError struct {
	ContentType ContentErrorType     `json:"content_type,omitempty"`
	Feature     DetectionServiceName `json:"feature,omitempty"`
	Status      ErrorStatus          `json:"status,omitempty"`
}

// ToolDetectionFlags holds boolean detection flags per service.
type ToolDetectionFlags struct {
	Injection      bool `json:"injection,omitempty"`
	URLCats        bool `json:"url_cats,omitempty"`
	DLP            bool `json:"dlp,omitempty"`
	DBSecurity     bool `json:"db_security,omitempty"`
	ToxicContent   bool `json:"toxic_content,omitempty"`
	MaliciousCode  bool `json:"malicious_code,omitempty"`
	Agent          bool `json:"agent,omitempty"`
	TopicViolation bool `json:"topic_violation,omitempty"`
}

// TopicGuardRails holds topic guardrail details.
type TopicGuardRails struct {
	AllowedTopics []string `json:"allowed_topics,omitempty"`
	BlockedTopics []string `json:"blocked_topics,omitempty"`
}

// ToolDetectionDetails holds additional detection details.
type ToolDetectionDetails struct {
	TopicGuardrailsDetails *TopicGuardRails `json:"topic_guardrails_details,omitempty"`
}

// ToolDetectionEntry is a single detection entry for tool I/O.
type ToolDetectionEntry struct {
	ToolInvoked string                `json:"tool_invoked,omitempty"`
	Detections  *ToolDetectionFlags   `json:"detections,omitempty"`
	Threats     []string              `json:"threats,omitempty"`
	Details     *ToolDetectionDetails `json:"details,omitempty"`
	MaskedData  *MaskedData           `json:"masked_data,omitempty"`
}

// IODetected holds I/O detection results as an array of detection entries.
type IODetected struct {
	DetectionEntries []ToolDetectionEntry `json:"detection_entries,omitempty"`
}

// ScanSummary holds aggregated detection flags and threats.
type ScanSummary struct {
	Detections *ToolDetectionFlags `json:"detections,omitempty"`
	Threats    []string            `json:"threats,omitempty"`
}

// ToolDetected holds detection results for tool/agent interactions.
type ToolDetected struct {
	Verdict        string             `json:"verdict,omitempty"`
	Metadata       *ToolEventMetadata `json:"metadata,omitempty"`
	Summary        *ScanSummary       `json:"summary,omitempty"`
	InputDetected  *IODetected        `json:"input_detected,omitempty"`
	OutputDetected *IODetected        `json:"output_detected,omitempty"`
}

// AsyncScanObject is a batch item for async scanning.
// Each object wraps a ScanRequest with a unique request ID.
type AsyncScanObject struct {
	ReqID   uint32      `json:"req_id"`
	ScanReq ScanRequest `json:"scan_req"`
}

// AsyncScanResponse is the async scan API response.
type AsyncScanResponse struct {
	Received string `json:"received,omitempty"`
	ScanID   string `json:"scan_id,omitempty"`
	ReportID string `json:"report_id,omitempty"`
	Source   string `json:"source,omitempty"`
}

// ScanIDResult is the result of querying a scan by ID.
type ScanIDResult struct {
	Source string        `json:"source,omitempty"`
	ReqID  int           `json:"req_id,omitempty"`
	Status string        `json:"status,omitempty"`
	ScanID string        `json:"scan_id,omitempty"`
	Result *ScanResponse `json:"result,omitempty"`
}

// DSResultMetadata holds metadata for a detection service result.
type DSResultMetadata struct {
	Ecosystem   string `json:"ecosystem,omitempty"`
	Method      string `json:"method,omitempty"`
	ServerName  string `json:"server_name,omitempty"`
	ToolInvoked string `json:"tool_invoked,omitempty"`
	Direction   string `json:"direction,omitempty"`
}

// UrlfEntry is a URL filter report entry.
type UrlfEntry struct {
	URL       string `json:"url,omitempty"`
	RiskLevel string `json:"risk_level,omitempty"`
	Action    string `json:"action,omitempty"`
}

// DlpReport holds DLP detection report details.
type DlpReport struct {
	DlpReportID       string `json:"dlp_report_id,omitempty"`
	DlpProfileName    string `json:"dlp_profile_name,omitempty"`
	DlpProfileID      string `json:"dlp_profile_id,omitempty"`
	DlpProfileVersion int    `json:"dlp_profile_version,omitempty"`
}

// DbsEntry is a database security report entry.
type DbsEntry struct {
	SubType string `json:"sub_type,omitempty"`
	Verdict string `json:"verdict,omitempty"`
	Action  string `json:"action,omitempty"`
}

// TcReport holds toxic content report details.
type TcReport struct {
	Confidence string `json:"confidence,omitempty"`
	Verdict    string `json:"verdict,omitempty"`
}

// McEntry is a malicious code analysis entry.
type McEntry struct {
	CodeType string `json:"code_type,omitempty"`
	Verdict  string `json:"verdict,omitempty"`
	Action   string `json:"action,omitempty"`
}

// McReport holds malicious code report details.
type McReport struct {
	AllCodeBlocks       []string       `json:"all_code_blocks,omitempty"`
	CodeAnalysisByType  []McEntry      `json:"code_analysis_by_type,omitempty"`
	Verdict             string         `json:"verdict,omitempty"`
	MalwareScriptReport map[string]any `json:"malware_script_report,omitempty"`
}

// AgentEntry is an agent detection pattern entry.
type AgentEntry struct {
	Pattern string `json:"pattern,omitempty"`
	Verdict string `json:"verdict,omitempty"`
}

// AgentReport holds agent detection report details.
type AgentReport struct {
	ModelVerdict   string       `json:"model_verdict,omitempty"`
	AgentFramework string       `json:"agent_framework,omitempty"`
	AgentPatterns  []AgentEntry `json:"agent_patterns,omitempty"`
}

// TgReport holds topic guardrails report details.
type TgReport struct {
	AllowedTopicList string   `json:"allowed_topic_list,omitempty"`
	BlockedTopicList string   `json:"blocked_topic_list,omitempty"`
	AllowedTopics    []string `json:"allowedTopics,omitempty"`
	BlockedTopics    []string `json:"blockedTopics,omitempty"`
}

// CgReport holds contextual grounding report details.
type CgReport struct {
	Status      string `json:"status,omitempty"`
	Explanation string `json:"explanation,omitempty"`
	Category    string `json:"category,omitempty"`
}

// DSDetailResult holds detailed results from each detection service.
type DSDetailResult struct {
	UrlfReport            []UrlfEntry  `json:"urlf_report,omitempty"`
	DlpReport             *DlpReport   `json:"dlp_report,omitempty"`
	DbsReport             []DbsEntry   `json:"dbs_report,omitempty"`
	TcReport              *TcReport    `json:"tc_report,omitempty"`
	McReport              *McReport    `json:"mc_report,omitempty"`
	AgentReport           *AgentReport `json:"agent_report,omitempty"`
	TopicGuardrailsReport *TgReport    `json:"topic_guardrails_report,omitempty"`
	CgReport              *CgReport    `json:"cg_report,omitempty"`
}

// DetectionServiceResult holds results from a single detection service.
type DetectionServiceResult struct {
	DataType         string            `json:"data_type,omitempty"`
	DetectionService string            `json:"detection_service,omitempty"`
	Verdict          string            `json:"verdict,omitempty"`
	Action           string            `json:"action,omitempty"`
	Metadata         *DSResultMetadata `json:"metadata,omitempty"`
	ResultDetail     *DSDetailResult   `json:"result_detail,omitempty"`
}

// ThreatScanReport is a detailed threat scan report.
type ThreatScanReport struct {
	Source           string                   `json:"source,omitempty"`
	ReportID         string                   `json:"report_id,omitempty"`
	ScanID           string                   `json:"scan_id,omitempty"`
	ReqID            int                      `json:"req_id,omitempty"`
	TransactionID    string                   `json:"transaction_id,omitempty"`
	SessionID        string                   `json:"session_id,omitempty"`
	DetectionResults []DetectionServiceResult `json:"detection_results,omitempty"`
}

// Enums as string constants.
const (
	VerdictBenign    = "benign"
	VerdictMalicious = "malicious"
	VerdictUnknown   = "unknown"

	ActionAllow = "allow"
	ActionBlock = "block"
	ActionAlert = "alert"

	CategoryBenign    = "benign"
	CategoryMalicious = "malicious"
	CategoryUnknown   = "unknown"
)
