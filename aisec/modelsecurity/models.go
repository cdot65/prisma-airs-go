package modelsecurity

// Enums matching TS SDK model-security-enums.ts

// EvalOutcome represents the outcome of a scan evaluation.
type EvalOutcome string

const (
	EvalOutcomePending EvalOutcome = "PENDING"
	EvalOutcomeAllowed EvalOutcome = "ALLOWED"
	EvalOutcomeBlocked EvalOutcome = "BLOCKED"
	EvalOutcomeError   EvalOutcome = "ERROR"
)

// RuleEvaluationResult represents a rule evaluation result.
type RuleEvaluationResult string

const (
	RuleEvaluationResultPassed RuleEvaluationResult = "PASSED"
	RuleEvaluationResultFailed RuleEvaluationResult = "FAILED"
	RuleEvaluationResultError  RuleEvaluationResult = "ERROR"
)

// RuleState represents the state of a rule instance.
type RuleState string

const (
	RuleStateDisabled RuleState = "DISABLED"
	RuleStateAllowing RuleState = "ALLOWING"
	RuleStateBlocking RuleState = "BLOCKING"
)

// SourceType represents the source type of a scan.
type SourceType string

const (
	SourceTypeLocal       SourceType = "LOCAL"
	SourceTypeHuggingFace SourceType = "HUGGING_FACE"
	SourceTypeS3          SourceType = "S3"
	SourceTypeGCS         SourceType = "GCS"
	SourceTypeAzure       SourceType = "AZURE"
	SourceTypeArtifactory SourceType = "ARTIFACTORY"
	SourceTypeGitLab      SourceType = "GITLAB"
	SourceTypeAll         SourceType = "ALL"
)

// ModelSecurityGroupState represents the state of a security group.
type ModelSecurityGroupState string

const (
	ModelSecurityGroupStatePending ModelSecurityGroupState = "PENDING"
	ModelSecurityGroupStateActive  ModelSecurityGroupState = "ACTIVE"
)

// RuleType represents the type of a security rule.
type RuleType string

const (
	RuleTypeMetadata RuleType = "METADATA"
	RuleTypeArtifact RuleType = "ARTIFACT"
)

// FileType represents file or directory.
type FileType string

const (
	FileTypeDirectory FileType = "DIRECTORY"
	FileTypeFile      FileType = "FILE"
)

// FileScanResult represents file scan result.
type FileScanResult string

const (
	FileScanResultSkipped FileScanResult = "SKIPPED"
	FileScanResultSuccess FileScanResult = "SUCCESS"
	FileScanResultError   FileScanResult = "ERROR"
	FileScanResultFailed  FileScanResult = "FAILED"
)

// ModelScanStatus represents model scan status.
type ModelScanStatus string

const (
	ModelScanStatusScanned ModelScanStatus = "SCANNED"
	ModelScanStatusSkipped ModelScanStatus = "SKIPPED"
	ModelScanStatusError   ModelScanStatus = "ERROR"
)

// ScanOrigin represents the origin of a scan.
type ScanOrigin string

const (
	ScanOriginModelSecuritySDK ScanOrigin = "MODEL_SECURITY_SDK"
	ScanOriginHuggingFace      ScanOrigin = "HUGGING_FACE"
)

// SortDirection represents sort direction.
type SortDirection string

const (
	SortDirectionAsc  SortDirection = "asc"
	SortDirectionDesc SortDirection = "desc"
)

// RuleEditableFieldType represents editable field types.
type RuleEditableFieldType string

const (
	RuleEditableFieldTypeSelect RuleEditableFieldType = "SELECT"
	RuleEditableFieldTypeList   RuleEditableFieldType = "LIST"
)

// --- Pagination ---

// PaginationMeta holds pagination metadata.
type PaginationMeta struct {
	Total int `json:"total"`
	Skip  int `json:"skip"`
	Limit int `json:"limit"`
}

// --- Scan types ---

// ScanCreateRequest is the request to create a model security scan.
type ScanCreateRequest struct {
	Name              string            `json:"name"`
	SourceType        SourceType        `json:"source_type"`
	SecurityGroupUUID string            `json:"security_group_uuid,omitempty"`
	Source            map[string]any    `json:"source,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
}

// EvaluationSummary is the summary of evaluation outcomes.
type EvaluationSummary struct {
	Passed int `json:"passed"`
	Failed int `json:"failed"`
	Error  int `json:"error"`
}

// ScanBaseResponse is the base scan response.
type ScanBaseResponse struct {
	UUID              string             `json:"uuid"`
	Name              string             `json:"name"`
	SourceType        SourceType         `json:"source_type,omitempty"`
	SecurityGroupUUID string             `json:"security_group_uuid,omitempty"`
	EvalOutcome       EvalOutcome        `json:"eval_outcome,omitempty"`
	EvalSummary       *EvaluationSummary `json:"eval_summary,omitempty"`
	Labels            map[string]string  `json:"labels,omitempty"`
	CreatedAt         string             `json:"created_at,omitempty"`
	UpdatedAt         string             `json:"updated_at,omitempty"`
}

// ScanList is the paginated list of scans.
type ScanList struct {
	Items    []ScanBaseResponse `json:"items"`
	Metadata PaginationMeta     `json:"metadata"`
}

// --- Rule Evaluation types ---

// RuleEvaluationResponse represents a single rule evaluation.
type RuleEvaluationResponse struct {
	UUID             string               `json:"uuid"`
	ScanUUID         string               `json:"scan_uuid,omitempty"`
	RuleInstanceUUID string               `json:"rule_instance_uuid,omitempty"`
	RuleName         string               `json:"rule_name,omitempty"`
	Result           RuleEvaluationResult `json:"result,omitempty"`
	Details          map[string]any       `json:"details,omitempty"`
	CreatedAt        string               `json:"created_at,omitempty"`
}

// RuleEvaluationList is the paginated list of rule evaluations.
type RuleEvaluationList struct {
	Items    []RuleEvaluationResponse `json:"items"`
	Metadata PaginationMeta           `json:"metadata"`
}

// --- File types ---

// FileResponse represents a file in a scan.
type FileResponse struct {
	UUID    string         `json:"uuid"`
	Path    string         `json:"path,omitempty"`
	Type    FileType       `json:"type,omitempty"`
	Result  FileScanResult `json:"result,omitempty"`
	Size    int64          `json:"size,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

// FileList is the paginated list of files.
type FileList struct {
	Items    []FileResponse `json:"items"`
	Metadata PaginationMeta `json:"metadata"`
}

// --- Violation types ---

// ViolationResponse represents a rule violation.
type ViolationResponse struct {
	UUID      string         `json:"uuid"`
	ScanUUID  string         `json:"scan_uuid,omitempty"`
	RuleName  string         `json:"rule_name,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
	CreatedAt string         `json:"created_at,omitempty"`
}

// ViolationList is the paginated list of violations.
type ViolationList struct {
	Items    []ViolationResponse `json:"items"`
	Metadata PaginationMeta      `json:"metadata"`
}

// --- Label types ---

// LabelsCreateRequest is the request to add/set labels.
type LabelsCreateRequest struct {
	Labels map[string]string `json:"labels"`
}

// LabelsResponse is the response from label operations.
type LabelsResponse struct {
	Labels map[string]string `json:"labels"`
}

// LabelKeyList is the paginated list of label keys.
type LabelKeyList struct {
	Items    []string       `json:"items"`
	Metadata PaginationMeta `json:"metadata"`
}

// LabelValueList is the paginated list of label values.
type LabelValueList struct {
	Items    []string       `json:"items"`
	Metadata PaginationMeta `json:"metadata"`
}

// --- Security Group types ---

// ModelSecurityGroupCreateRequest is the request to create a security group.
type ModelSecurityGroupCreateRequest struct {
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	SourceType  SourceType `json:"source_type,omitempty"`
}

// ModelSecurityGroupUpdateRequest is the request to update a security group.
type ModelSecurityGroupUpdateRequest struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// ModelSecurityGroupResponse is a security group.
type ModelSecurityGroupResponse struct {
	UUID        string                  `json:"uuid"`
	Name        string                  `json:"name,omitempty"`
	Description string                  `json:"description,omitempty"`
	SourceType  SourceType              `json:"source_type,omitempty"`
	State       ModelSecurityGroupState `json:"state,omitempty"`
	CreatedAt   string                  `json:"created_at,omitempty"`
	UpdatedAt   string                  `json:"updated_at,omitempty"`
}

// ListModelSecurityGroupsResponse is the paginated list of security groups.
type ListModelSecurityGroupsResponse struct {
	Items    []ModelSecurityGroupResponse `json:"items"`
	Metadata PaginationMeta               `json:"metadata"`
}

// --- Rule Instance types ---

// ModelSecurityRuleInstanceUpdateRequest is the request to update a rule instance.
type ModelSecurityRuleInstanceUpdateRequest struct {
	State  RuleState      `json:"state,omitempty"`
	Config map[string]any `json:"config,omitempty"`
}

// ModelSecurityRuleInstanceResponse is a rule instance within a security group.
type ModelSecurityRuleInstanceResponse struct {
	UUID             string         `json:"uuid"`
	SecurityRuleUUID string         `json:"security_rule_uuid,omitempty"`
	State            RuleState      `json:"state,omitempty"`
	Config           map[string]any `json:"config,omitempty"`
	RuleName         string         `json:"rule_name,omitempty"`
	CreatedAt        string         `json:"created_at,omitempty"`
	UpdatedAt        string         `json:"updated_at,omitempty"`
}

// ListModelSecurityRuleInstancesResponse is the paginated list of rule instances.
type ListModelSecurityRuleInstancesResponse struct {
	Items    []ModelSecurityRuleInstanceResponse `json:"items"`
	Metadata PaginationMeta                      `json:"metadata"`
}

// --- Security Rule types ---

// ModelSecurityRuleResponse is a security rule (read-only).
type ModelSecurityRuleResponse struct {
	UUID        string     `json:"uuid"`
	Name        string     `json:"name,omitempty"`
	Description string     `json:"description,omitempty"`
	SourceType  SourceType `json:"source_type,omitempty"`
	RuleType    RuleType   `json:"rule_type,omitempty"`
	CreatedAt   string     `json:"created_at,omitempty"`
}

// ListModelSecurityRulesResponse is the paginated list of security rules.
type ListModelSecurityRulesResponse struct {
	Items    []ModelSecurityRuleResponse `json:"items"`
	Metadata PaginationMeta              `json:"metadata"`
}

// --- PyPI Auth ---

// PyPIAuthResponse is the PyPI authentication response.
type PyPIAuthResponse struct {
	URL       string `json:"url,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// --- List Options ---

// ScanListOpts are options for listing scans.
type ScanListOpts struct {
	Skip              int
	Limit             int
	SortBy            string
	SortOrder         string
	SearchQuery       string
	EvalOutcomes      []string
	SourceTypes       []string
	SecurityGroupUUID string
	StartTime         string
	EndTime           string
	LabelsQuery       string
}

// EvaluationListOpts are options for listing evaluations.
type EvaluationListOpts struct {
	Skip             int
	Limit            int
	SortField        string
	SortOrder        string
	Result           string
	RuleInstanceUUID string
}

// FileListOpts are options for listing files.
type FileListOpts struct {
	Skip      int
	Limit     int
	SortField string
	SortDir   string
	Type      string
	Result    string
	QueryPath string
}

// LabelListOpts are options for listing label keys/values.
type LabelListOpts struct {
	Skip   int
	Limit  int
	Search string
}

// ViolationListOpts are options for listing violations.
type ViolationListOpts struct {
	Skip  int
	Limit int
}

// GroupListOpts are options for listing security groups.
type GroupListOpts struct {
	Skip         int
	Limit        int
	SortField    string
	SortDir      string
	SourceTypes  []string
	SearchQuery  string
	EnabledRules []string
}

// RuleInstanceListOpts are options for listing rule instances.
type RuleInstanceListOpts struct {
	Skip             int
	Limit            int
	SecurityRuleUUID string
	State            string
}

// RuleListOpts are options for listing security rules.
type RuleListOpts struct {
	Skip        int
	Limit       int
	SourceType  string
	SearchQuery string
}
