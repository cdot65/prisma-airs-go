package modelsecurity

// Enums matching API spec

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

// ThreatCategory represents threat categories for model scan issues.
type ThreatCategory string

const (
	ThreatCategoryPAITARV100        ThreatCategory = "PAIT-ARV-100"
	ThreatCategoryPAITGGUF100       ThreatCategory = "PAIT-GGUF-100"
	ThreatCategoryPAITGGUF101       ThreatCategory = "PAIT-GGUF-101"
	ThreatCategoryPAITKERAS100      ThreatCategory = "PAIT-KERAS-100"
	ThreatCategoryPAITKERAS101      ThreatCategory = "PAIT-KERAS-101"
	ThreatCategoryPAITKERAS102      ThreatCategory = "PAIT-KERAS-102"
	ThreatCategoryPAITJOBLIB100     ThreatCategory = "PAIT-JOBLIB-100"
	ThreatCategoryPAITJOBLIB101     ThreatCategory = "PAIT-JOBLIB-101"
	ThreatCategoryPAITPKL100        ThreatCategory = "PAIT-PKL-100"
	ThreatCategoryPAITPKL101        ThreatCategory = "PAIT-PKL-101"
	ThreatCategoryPAITPYTCH100      ThreatCategory = "PAIT-PYTCH-100"
	ThreatCategoryPAITPYTCH101      ThreatCategory = "PAIT-PYTCH-101"
	ThreatCategoryPAITEXDIR100      ThreatCategory = "PAIT-EXDIR-100"
	ThreatCategoryPAITEXDIR101      ThreatCategory = "PAIT-EXDIR-101"
	ThreatCategoryPAITONNX200       ThreatCategory = "PAIT-ONNX-200"
	ThreatCategoryPAITTF200         ThreatCategory = "PAIT-TF-200"
	ThreatCategoryPAITLMAFL300      ThreatCategory = "PAIT-LMAFL-300"
	ThreatCategoryPAITLITERT300     ThreatCategory = "PAIT-LITERT-300"
	ThreatCategoryPAITLITERT301     ThreatCategory = "PAIT-LITERT-301"
	ThreatCategoryPAITLITERT302     ThreatCategory = "PAIT-LITERT-302"
	ThreatCategoryPAITKERAS300      ThreatCategory = "PAIT-KERAS-300"
	ThreatCategoryPAITKERAS301      ThreatCategory = "PAIT-KERAS-301"
	ThreatCategoryPAITTCHST300      ThreatCategory = "PAIT-TCHST-300"
	ThreatCategoryPAITTCHST301      ThreatCategory = "PAIT-TCHST-301"
	ThreatCategoryPAITTF300         ThreatCategory = "PAIT-TF-300"
	ThreatCategoryPAITTF301         ThreatCategory = "PAIT-TF-301"
	ThreatCategoryPAITTF302         ThreatCategory = "PAIT-TF-302"
	ThreatCategoryPAITTMT300        ThreatCategory = "PAIT-TMT-300"
	ThreatCategoryPAITTMT301        ThreatCategory = "PAIT-TMT-301"
	ThreatCategoryUnapprovedFormats ThreatCategory = "UNAPPROVED_FORMATS"
)

// ErrorCode represents error codes for scans.
type ErrorCode string

const (
	ErrorCodeUnknownError              ErrorCode = "UNKNOWN_ERROR"
	ErrorCodeScanError                 ErrorCode = "SCAN_ERROR"
	ErrorCodeInvalidResponse           ErrorCode = "INVALID_RESPONSE"
	ErrorCodeAccessDenied              ErrorCode = "ACCESS_DENIED"
	ErrorCodeMissingCredentials        ErrorCode = "MISSING_CREDENTIALS"
	ErrorCodeNoSuchKey                 ErrorCode = "NO_SUCH_KEY"
	ErrorCodeNoSuchBucket              ErrorCode = "NO_SUCH_BUCKET"
	ErrorCodeInvalidBucketName         ErrorCode = "INVALID_BUCKET_NAME"
	ErrorCodeInternalError             ErrorCode = "INTERNAL_ERROR"
	ErrorCodeServiceUnavailable        ErrorCode = "SERVICE_UNAVAILABLE"
	ErrorCodeInvalidObjectState        ErrorCode = "INVALID_OBJECT_STATE"
	ErrorCodeUnknownRemoteServiceError ErrorCode = "UNKNOWN_REMOTE_SERVICE_ERROR"
	ErrorCodeUnsupportedRemoteStorage  ErrorCode = "UNSUPPORTED_REMOTE_STORAGE"
	ErrorCodeMissingArtifacts          ErrorCode = "MISSING_ARTIFACTS"
	ErrorCodeWorkerError               ErrorCode = "WORKER_ERROR"
	ErrorCodePolicyEvalError           ErrorCode = "POLICY_EVAL_ERROR"
)

// RuleFieldValueKey is a valid key for rule field values.
type RuleFieldValueKey string

const (
	RuleFieldValueKeyApprovedFormats   RuleFieldValueKey = "approved_formats"
	RuleFieldValueKeyApprovedLocations RuleFieldValueKey = "approved_locations"
	RuleFieldValueKeyApprovedLicenses  RuleFieldValueKey = "approved_licenses"
	RuleFieldValueKeyDenyOrgs          RuleFieldValueKey = "deny_orgs"
	RuleFieldValueKeyDeniedOrgModels   RuleFieldValueKey = "denied_org_models"
	RuleFieldValueKeyApprovedOrgModels RuleFieldValueKey = "approved_org_models"
)

// --- Pagination ---

// PaginationMeta holds pagination metadata.
type PaginationMeta struct {
	TotalItems *int `json:"total_items,omitempty"`
}

// --- Common types ---

// Label is a key-value label for scans.
type Label struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// RuleRemediation holds remediation info for a security rule.
type RuleRemediation struct {
	Description string   `json:"description"`
	Steps       []string `json:"steps"`
	URL         string   `json:"url"`
}

// RuleEditableFieldDropdown is a dropdown option for editable fields.
type RuleEditableFieldDropdown struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// RuleEditableField describes an editable field on a rule.
type RuleEditableField struct {
	AttributeName  string                      `json:"attribute_name"`
	Type           string                      `json:"type"`
	DisplayName    string                      `json:"display_name"`
	DisplayType    RuleEditableFieldType       `json:"display_type"`
	Description    string                      `json:"description,omitempty"`
	DropdownValues []RuleEditableFieldDropdown `json:"dropdown_values,omitempty"`
}

// RuleConfiguration holds per-rule config in a security group create request.
type RuleConfiguration struct {
	FieldValues map[string]any `json:"field_values,omitempty"`
	State       RuleState      `json:"state,omitempty"`
}

// EvalSummary is the summary of evaluation outcomes.
type EvalSummary struct {
	RulesPassed int `json:"rules_passed"`
	RulesFailed int `json:"rules_failed"`
	TotalRules  int `json:"total_rules"`
}

// ScanDetails holds scanner details for a scan create request.
type ScanDetails struct {
	ScannerVersion    string         `json:"scanner_version"`
	TimeStarted       string         `json:"time_started"`
	Files             []FileScanData `json:"files"`
	TotalFilesScanned int            `json:"total_files_scanned"`
	TotalFilesSkipped int            `json:"total_files_skipped"`
	ModelFormats      []string       `json:"model_formats"`
	ModelSizeBytes    int64          `json:"model_size_bytes"`
	ScanDurationMs    int64          `json:"scan_duration_ms"`
	ErrorCode         string         `json:"error_code,omitempty"`
	ErrorMessage      string         `json:"error_message,omitempty"`
}

// FileScanData holds per-file scan data.
type FileScanData struct {
	FilePath        string           `json:"file_path"`
	ModelscanStatus ModelScanStatus  `json:"modelscan_status"`
	BlobID          string           `json:"blob_id"`
	ErrorMessage    string           `json:"error_message,omitempty"`
	Formats         []string         `json:"formats,omitempty"`
	IssuesDetected  []ModelScanIssue `json:"issues_detected,omitempty"`
}

// ModelScanIssue is a detected issue in a model file.
type ModelScanIssue struct {
	Description string `json:"description"`
	Source      string `json:"source"`
	Module      string `json:"module,omitempty"`
	Operator    string `json:"operator,omitempty"`
	Threat      string `json:"threat,omitempty"`
}

// --- Scan types ---

// ScanCreateRequest is the request to create a model security scan.
type ScanCreateRequest struct {
	ModelURI          string       `json:"model_uri"`
	SecurityGroupUUID string       `json:"security_group_uuid"`
	ScanOrigin        ScanOrigin   `json:"scan_origin"`
	AllowPatterns     []string     `json:"allow_patterns,omitempty"`
	IgnorePatterns    []string     `json:"ignore_patterns,omitempty"`
	Labels            []Label      `json:"labels,omitempty"`
	ModelAuthor       string       `json:"model_author,omitempty"`
	ModelName         string       `json:"model_name,omitempty"`
	ModelVersion      string       `json:"model_version,omitempty"`
	ScanDetails       *ScanDetails `json:"scan_details,omitempty"`
}

// ScanBaseResponse is the base scan response.
type ScanBaseResponse struct {
	UUID                     string       `json:"uuid"`
	TsgID                    string       `json:"tsg_id,omitempty"`
	CreatedAt                string       `json:"created_at,omitempty"`
	UpdatedAt                string       `json:"updated_at,omitempty"`
	ModelURI                 string       `json:"model_uri,omitempty"`
	Owner                    string       `json:"owner,omitempty"`
	ScanOrigin               ScanOrigin   `json:"scan_origin,omitempty"`
	SecurityGroupUUID        string       `json:"security_group_uuid,omitempty"`
	SecurityGroupName        string       `json:"security_group_name,omitempty"`
	ModelVersionUUID         string       `json:"model_version_uuid,omitempty"`
	EvalOutcome              EvalOutcome  `json:"eval_outcome,omitempty"`
	SourceType               SourceType   `json:"source_type,omitempty"`
	CreatedBy                string       `json:"created_by,omitempty"`
	EnabledRuleCountSnapshot *int         `json:"enabled_rule_count_snapshot,omitempty"`
	ErrorCode                string       `json:"error_code,omitempty"`
	ErrorMessage             string       `json:"error_message,omitempty"`
	EvalSummary              *EvalSummary `json:"eval_summary,omitempty"`
	Labels                   []Label      `json:"labels,omitempty"`
	ModelFormats             []string     `json:"model_formats,omitempty"`
	ScannerVersion           string       `json:"scanner_version,omitempty"`
	TimeStarted              string       `json:"time_started,omitempty"`
	TotalFilesScanned        *int         `json:"total_files_scanned,omitempty"`
	TotalFilesSkipped        *int         `json:"total_files_skipped,omitempty"`
}

// ScanList is the paginated list of scans.
type ScanList struct {
	Items    []ScanBaseResponse `json:"scans"`
	Metadata PaginationMeta     `json:"pagination"`
}

// --- Rule Evaluation types ---

// RuleEvaluationResponse represents a single rule evaluation.
type RuleEvaluationResponse struct {
	UUID              string               `json:"uuid"`
	TsgID             string               `json:"tsg_id,omitempty"`
	CreatedAt         string               `json:"created_at,omitempty"`
	UpdatedAt         string               `json:"updated_at,omitempty"`
	Result            RuleEvaluationResult `json:"result,omitempty"`
	ViolationCount    int                  `json:"violation_count,omitempty"`
	RuleInstanceUUID  string               `json:"rule_instance_uuid,omitempty"`
	ScanUUID          string               `json:"scan_uuid,omitempty"`
	RuleName          string               `json:"rule_name,omitempty"`
	RuleDescription   string               `json:"rule_description,omitempty"`
	RuleInstanceState RuleState            `json:"rule_instance_state,omitempty"`
}

// RuleEvaluationList is the paginated list of rule evaluations.
type RuleEvaluationList struct {
	Items    []RuleEvaluationResponse `json:"evaluations"`
	Metadata PaginationMeta           `json:"pagination"`
}

// --- File types ---

// FileResponse represents a file in a scan.
type FileResponse struct {
	UUID             string         `json:"uuid"`
	TsgID            string         `json:"tsg_id,omitempty"`
	CreatedAt        string         `json:"created_at,omitempty"`
	UpdatedAt        string         `json:"updated_at,omitempty"`
	Path             string         `json:"path,omitempty"`
	ParentPath       string         `json:"parent_path,omitempty"`
	Type             FileType       `json:"type,omitempty"`
	Result           FileScanResult `json:"result,omitempty"`
	ModelVersionUUID string         `json:"model_version_uuid,omitempty"`
	BlobID           string         `json:"blob_id,omitempty"`
	Formats          []string       `json:"formats,omitempty"`
	ScanUUID         string         `json:"scan_uuid,omitempty"`
}

// FileList is the paginated list of files.
type FileList struct {
	Items    []FileResponse `json:"files"`
	Metadata PaginationMeta `json:"pagination"`
}

// --- Violation types ---

// ViolationResponse represents a rule violation.
type ViolationResponse struct {
	UUID              string    `json:"uuid"`
	TsgID             string    `json:"tsg_id,omitempty"`
	CreatedAt         string    `json:"created_at,omitempty"`
	UpdatedAt         string    `json:"updated_at,omitempty"`
	Description       string    `json:"description,omitempty"`
	RuleInstanceUUID  string    `json:"rule_instance_uuid,omitempty"`
	RuleName          string    `json:"rule_name,omitempty"`
	RuleDescription   string    `json:"rule_description,omitempty"`
	RuleInstanceState RuleState `json:"rule_instance_state,omitempty"`
	File              string    `json:"file,omitempty"`
	Hash              string    `json:"hash,omitempty"`
	Module            string    `json:"module,omitempty"`
	Operator          string    `json:"operator,omitempty"`
	Threat            string    `json:"threat,omitempty"`
	ThreatDescription string    `json:"threat_description,omitempty"`
}

// ViolationList is the paginated list of violations.
type ViolationList struct {
	Items    []ViolationResponse `json:"violations"`
	Metadata PaginationMeta      `json:"pagination"`
}

// --- Label types ---

// LabelsCreateRequest is the request to add/set labels.
type LabelsCreateRequest struct {
	Labels []Label `json:"labels"`
}

// LabelsResponse is the response from label operations.
type LabelsResponse struct {
	Labels []Label `json:"labels,omitempty"`
}

// LabelKeyList is the paginated list of label keys.
type LabelKeyList struct {
	Items    []string       `json:"keys"`
	Metadata PaginationMeta `json:"pagination"`
}

// LabelValueList is the paginated list of label values.
type LabelValueList struct {
	Items    []string       `json:"values"`
	Metadata PaginationMeta `json:"pagination"`
}

// --- Security Group types ---

// ModelSecurityGroupCreateRequest is the request to create a security group.
type ModelSecurityGroupCreateRequest struct {
	Name               string                       `json:"name"`
	SourceType         SourceType                   `json:"source_type"`
	Description        string                       `json:"description,omitempty"`
	RuleConfigurations map[string]RuleConfiguration `json:"rule_configurations,omitempty"`
}

// ModelSecurityGroupUpdateRequest is the request to update a security group.
type ModelSecurityGroupUpdateRequest struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// ModelSecurityGroupResponse is a security group.
type ModelSecurityGroupResponse struct {
	UUID        string                  `json:"uuid"`
	TsgID       string                  `json:"tsg_id,omitempty"`
	CreatedAt   string                  `json:"created_at,omitempty"`
	UpdatedAt   string                  `json:"updated_at,omitempty"`
	Name        string                  `json:"name,omitempty"`
	Description string                  `json:"description,omitempty"`
	SourceType  SourceType              `json:"source_type,omitempty"`
	State       ModelSecurityGroupState `json:"state,omitempty"`
	IsTombstone bool                    `json:"is_tombstone,omitempty"`
}

// ListModelSecurityGroupsResponse is the paginated list of security groups.
type ListModelSecurityGroupsResponse struct {
	Items    []ModelSecurityGroupResponse `json:"security_groups"`
	Metadata PaginationMeta               `json:"pagination"`
}

// --- Rule Instance types ---

// ModelSecurityRuleInstanceUpdateRequest is the request to update a rule instance.
type ModelSecurityRuleInstanceUpdateRequest struct {
	SecurityGroupUUID string         `json:"security_group_uuid"`
	State             RuleState      `json:"state,omitempty"`
	FieldValues       map[string]any `json:"field_values,omitempty"`
}

// ModelSecurityRuleInstanceResponse is a rule instance within a security group.
type ModelSecurityRuleInstanceResponse struct {
	UUID              string                     `json:"uuid"`
	TsgID             string                     `json:"tsg_id,omitempty"`
	CreatedAt         string                     `json:"created_at,omitempty"`
	UpdatedAt         string                     `json:"updated_at,omitempty"`
	SecurityGroupUUID string                     `json:"security_group_uuid,omitempty"`
	SecurityRuleUUID  string                     `json:"security_rule_uuid,omitempty"`
	State             RuleState                  `json:"state,omitempty"`
	FieldValues       map[string]any             `json:"field_values,omitempty"`
	Rule              *ModelSecurityRuleResponse `json:"rule,omitempty"`
}

// ListModelSecurityRuleInstancesResponse is the paginated list of rule instances.
type ListModelSecurityRuleInstancesResponse struct {
	Items    []ModelSecurityRuleInstanceResponse `json:"rule_instances"`
	Metadata PaginationMeta                      `json:"pagination"`
}

// --- Security Rule types ---

// ModelSecurityRuleResponse is a security rule (read-only).
type ModelSecurityRuleResponse struct {
	UUID              string              `json:"uuid"`
	Name              string              `json:"name,omitempty"`
	Description       string              `json:"description,omitempty"`
	RuleType          RuleType            `json:"rule_type,omitempty"`
	CompatibleSources []SourceType        `json:"compatible_sources,omitempty"`
	DefaultState      RuleState           `json:"default_state,omitempty"`
	Remediation       *RuleRemediation    `json:"remediation,omitempty"`
	EditableFields    []RuleEditableField `json:"editable_fields,omitempty"`
	ConstantValues    map[string]any      `json:"constant_values,omitempty"`
	DefaultValues     map[string]any      `json:"default_values,omitempty"`
}

// ListModelSecurityRulesResponse is the paginated list of security rules.
type ListModelSecurityRulesResponse struct {
	Items    []ModelSecurityRuleResponse `json:"rules"`
	Metadata PaginationMeta              `json:"pagination"`
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
