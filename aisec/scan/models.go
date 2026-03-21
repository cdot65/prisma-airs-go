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
type PatternDetection struct {
	Pattern string `json:"pattern,omitempty"`
	Start   int    `json:"start,omitempty"`
	End     int    `json:"end,omitempty"`
}

// ContentError represents an error that occurred during content scanning.
type ContentError struct {
	Type   string `json:"type,omitempty"`
	Status string `json:"status,omitempty"`
}

// ToolDetected holds detection results for tool/agent interactions.
type ToolDetected struct {
	Verdict        string             `json:"verdict,omitempty"`
	Metadata       *ToolEventMetadata `json:"metadata,omitempty"`
	Summary        *ScanSummary       `json:"summary,omitempty"`
	InputDetected  *IODetected        `json:"input_detected,omitempty"`
	OutputDetected *IODetected        `json:"output_detected,omitempty"`
}

// ScanSummary holds verdict and action.
type ScanSummary struct {
	Verdict string `json:"verdict,omitempty"`
	Action  string `json:"action,omitempty"`
}

// IODetected holds I/O detection flags.
type IODetected struct {
	URLCats       *bool `json:"url_cats,omitempty"`
	DLP           *bool `json:"dlp,omitempty"`
	Injection     *bool `json:"injection,omitempty"`
	ToxicContent  *bool `json:"toxic_content,omitempty"`
	MaliciousCode *bool `json:"malicious_code,omitempty"`
}

// AsyncScanObject is a batch item for async scanning.
type AsyncScanObject struct {
	AiProfile AiProfile      `json:"ai_profile"`
	Contents  []ContentInner `json:"contents"`
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

// DetectionServiceResult holds results from a single detection service.
type DetectionServiceResult struct {
	ServiceName string         `json:"service_name,omitempty"`
	Verdict     string         `json:"verdict,omitempty"`
	Action      string         `json:"action,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
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

	DetectionServiceDLP            = "dlp"
	DetectionServiceInjection      = "injection"
	DetectionServiceURLCats        = "url_cats"
	DetectionServiceToxicContent   = "toxic_content"
	DetectionServiceMaliciousCode  = "malicious_code"
	DetectionServiceAgent          = "agent"
	DetectionServiceTopicViolation = "topic_violation"
	DetectionServiceDBSecurity     = "db_security"
	DetectionServiceUngrounded     = "ungrounded"
)
