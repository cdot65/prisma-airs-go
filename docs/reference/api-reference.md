# API Reference

Complete reference for all public types, functions, and methods in the SDK.

## Package `aisec`

### Configuration

```go
// NewConfig creates a new SDK configuration.
func NewConfig(opts ...ConfigOption) *Config

// ConfigOption functions
func WithAPIKey(key string) ConfigOption
func WithAPIToken(token string) ConfigOption
func WithEndpoint(endpoint string) ConfigOption
```

### Error Types

```go
// AISecSDKError is the base error type for all SDK errors.
type AISecSDKError struct {
    ErrorType ErrorType
    Message   string
    Err       error // wrapped error
}

// ErrorType enum
const (
    ServerSideError        ErrorType = iota
    ClientSideError
    UserRequestPayloadError
    MissingVariableError
    AISecSDKInternalError
    OAuthError
)
```

### Constants

```go
const Version = "0.1.0"

// Content limits
const (
    MaxContentPromptLength   = 2 * 1024 * 1024   // 2 MB
    MaxContentResponseLength = 2 * 1024 * 1024   // 2 MB
    MaxContentContextLength  = 100 * 1024 * 1024 // 100 MB
)

// Batch limits
const (
    MaxNumberOfScanIDs          = 5
    MaxNumberOfReportIDs        = 5
    MaxNumberOfBatchScanObjects = 5
)

// Retry
const MaxNumberOfRetries = 5
var HTTPForceRetryStatusCodes = []int{500, 502, 503, 504}
```

---

## Package `scan`

### Scanner

```go
func NewScanner(cfg *aisec.Config) *Scanner

func (s *Scanner) SyncScan(ctx context.Context, profile AiProfile, content *Content, opts ...SyncScanOpts) (*ScanResponse, error)
func (s *Scanner) AsyncScan(ctx context.Context, objects []AsyncScanObject) (*AsyncScanResponse, error)
func (s *Scanner) QueryByScanIDs(ctx context.Context, scanIDs []string) ([]ScanIDResult, error)
func (s *Scanner) QueryByReportIDs(ctx context.Context, reportIDs []string) ([]ThreatScanReport, error)
```

### Content

```go
func NewContent(opts ContentOpts) (*Content, error)

type ContentOpts struct {
    Prompt       string
    Response     string
    Context      string
    CodePrompt   string
    CodeResponse string
    ToolEvent    *ToolEvent
}

func (c *Content) ByteLength() int
```

### Types

```go
type AiProfile struct {
    ProfileName string `json:"profile_name"`
}

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
    Timeout                  bool              `json:"timeout"`
    Error                    bool              `json:"error"`
    Errors                   []ContentError    `json:"errors"`
    PromptDetected           *PromptDetected   `json:"prompt_detected,omitempty"`
    ResponseDetected         *ResponseDetected `json:"response_detected,omitempty"`
    PromptMaskedData         *MaskedData       `json:"prompt_masked_data,omitempty"`
    ResponseMaskedData       *MaskedData       `json:"response_masked_data,omitempty"`
    PromptDetectionDetails   *DetectionDetails `json:"prompt_detection_details,omitempty"`
    ResponseDetectionDetails *DetectionDetails `json:"response_detection_details,omitempty"`
    ToolDetected             *ToolDetected     `json:"tool_detected,omitempty"`
    CreatedAt                string            `json:"created_at,omitempty"`
    CompletedAt              string            `json:"completed_at,omitempty"`
}

type AsyncScanObject struct {
    ReqID   uint32      `json:"req_id"`
    ScanReq ScanRequest `json:"scan_req"`
}

type AsyncScanResponse struct {
    Received string `json:"received"`
    ScanID   string `json:"scan_id"`
    ReportID string `json:"report_id,omitempty"`
    Source   string `json:"source,omitempty"`
}

type ToolEvent struct {
    Metadata *ToolEventMetadata `json:"metadata,omitempty"`
    Input    string             `json:"input,omitempty"`
    Output   string             `json:"output,omitempty"`
}

type ToolEventMetadata struct {
    Ecosystem   string `json:"ecosystem"`
    Method      string `json:"method"`
    ServerName  string `json:"server_name"`
    ToolInvoked string `json:"tool_invoked,omitempty"`
}
```

---

## Package `management`

### Client

```go
func NewClient(opts Opts) (*Client, error)

type Opts struct {
    ClientID      string
    ClientSecret  string
    TsgID         string
    APIEndpoint   string
    TokenEndpoint string
    NumRetries    int
}

type Client struct {
    Profiles           *ProfilesClient
    Topics             *TopicsClient
    ApiKeys            *ApiKeysClient
    CustomerApps       *CustomerAppsClient
    DlpProfiles        *DlpProfilesClient
    DeploymentProfiles *DeploymentProfilesClient
    ScanLogs           *ScanLogsClient
    OAuth              *OAuthManagementClient
}
```

### ProfilesClient

```go
func (c *ProfilesClient) Create(ctx context.Context, req CreateProfileRequest) (*SecurityProfile, error)
func (c *ProfilesClient) List(ctx context.Context, opts ListOpts) (*SecurityProfileListResponse, error)
func (c *ProfilesClient) GetByID(ctx context.Context, profileID string) (*SecurityProfile, error)
func (c *ProfilesClient) GetByName(ctx context.Context, name string) (*SecurityProfile, error)
func (c *ProfilesClient) Update(ctx context.Context, profileID string, req UpdateProfileRequest) (*SecurityProfile, error)
func (c *ProfilesClient) Delete(ctx context.Context, profileID string) (*DeleteProfileResponse, error)
func (c *ProfilesClient) ForceDelete(ctx context.Context, profileID string, updatedBy string) (*DeleteProfileResponse, error)
```

### TopicsClient

```go
func (c *TopicsClient) Create(ctx context.Context, req CreateTopicRequest) (*CustomTopic, error)
func (c *TopicsClient) List(ctx context.Context, opts ListOpts) (*CustomTopicListResponse, error)
func (c *TopicsClient) Update(ctx context.Context, topicID string, req UpdateTopicRequest) (*CustomTopic, error)
func (c *TopicsClient) Delete(ctx context.Context, topicID string) (*DeleteTopicResponse, error)
func (c *TopicsClient) ForceDelete(ctx context.Context, topicID string, updatedBy string) (*DeleteTopicResponse, error)
```

### ApiKeysClient

```go
func (c *ApiKeysClient) Create(ctx context.Context, req CreateApiKeyRequest) (*ApiKey, error)
func (c *ApiKeysClient) List(ctx context.Context, opts ListOpts) (*ApiKeyListResponse, error)
func (c *ApiKeysClient) Delete(ctx context.Context, keyName string, updatedBy string) (*ApiKeyDeleteResponse, error)
func (c *ApiKeysClient) Regenerate(ctx context.Context, keyID string, req RegenerateKeyRequest) (*ApiKey, error)
```

### CustomerAppsClient

```go
func (c *CustomerAppsClient) Create(ctx context.Context, req CreateAppRequest) (*CustomerApp, error)
func (c *CustomerAppsClient) List(ctx context.Context, opts ListOpts) (*CustomerAppListResponse, error)
func (c *CustomerAppsClient) Get(ctx context.Context, appName string) (*CustomerApp, error)
func (c *CustomerAppsClient) Update(ctx context.Context, appID string, req UpdateAppRequest) (*CustomerApp, error)
func (c *CustomerAppsClient) Delete(ctx context.Context, appName string, updatedBy string) (*DeleteAppResponse, error)
```

### ScanLogsClient

```go
func (c *ScanLogsClient) List(ctx context.Context, opts ScanLogListOpts) (*ScanLogListResponse, error)
```

### OAuthManagementClient

```go
func (c *OAuthManagementClient) GetToken(ctx context.Context, req OAuthTokenRequest) (*OAuthToken, error)
func (c *OAuthManagementClient) InvalidateToken(ctx context.Context) (*InvalidateTokenResponse, error)
```

### Action Enums

```go
type ProfileAction string

const (
    ProfileActionAllow    ProfileAction = "allow"
    ProfileActionBlock    ProfileAction = "block"
    ProfileActionAlert    ProfileAction = "alert"
    ProfileActionDisabled ProfileAction = ""
)

type ToxicContentAction string

const (
    ToxicContentHighBlockModerateAllow ToxicContentAction = "high:block, moderate:allow"
    ToxicContentHighBlockModerateBlock ToxicContentAction = "high:block, moderate:block"
    ToxicContentHighAllowModerateAllow ToxicContentAction = "high:allow, moderate:allow"
)
```

---

## Package `modelsecurity`

### Client

```go
func NewClient(opts Opts) (*Client, error)

type Opts struct {
    ClientID      string
    ClientSecret  string
    TsgID         string
    DataEndpoint  string
    MgmtEndpoint  string
    TokenEndpoint string
    NumRetries    int
}

type Client struct {
    Scans          *ScansClient
    SecurityGroups *SecurityGroupsClient
    SecurityRules  *SecurityRulesClient
}

func (c *Client) GetPyPIAuth(ctx context.Context) (*PyPIAuthResponse, error)
```

---

## Package `redteam`

### Client

```go
func NewClient(opts Opts) (*Client, error)

type Opts struct {
    ClientID      string
    ClientSecret  string
    TsgID         string
    DataEndpoint  string
    MgmtEndpoint  string
    TokenEndpoint string
    NumRetries    int
}

type Client struct {
    Scans               *ScansClient
    Reports             *ReportsClient
    CustomAttackReports *CustomAttackReportsClient
    Targets             *TargetsClient
    CustomAttacks       *CustomAttacksClient
}

// Convenience methods
func (c *Client) GetScanStatistics(ctx context.Context, params map[string]string) (*ScanStatisticsResponse, error)
func (c *Client) GetScoreTrend(ctx context.Context, targetID string) (*ScoreTrendResponse, error)
func (c *Client) GetQuota(ctx context.Context) (*QuotaSummary, error)
func (c *Client) GetErrorLogs(ctx context.Context, jobID string, opts ListOpts) (*ErrorLogListResponse, error)
func (c *Client) UpdateSentiment(ctx context.Context, req SentimentRequest) (*SentimentResponse, error)
func (c *Client) GetSentiment(ctx context.Context, jobID string) (*SentimentResponse, error)
func (c *Client) GetDashboardOverview(ctx context.Context) (*DashboardOverviewResponse, error)
```

---

## Enums

### Scan API

```go
// Verdict
const (
    VerdictBenign    = "benign"
    VerdictMalicious = "malicious"
    VerdictUnknown   = "unknown"
)

// Action
const (
    ActionAllow = "allow"
    ActionBlock = "block"
    ActionAlert = "alert"
)

// Category
const (
    CategoryBenign    = "benign"
    CategoryMalicious = "malicious"
    CategoryUnknown   = "unknown"
)
```

### Detection Services

```go
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
```
