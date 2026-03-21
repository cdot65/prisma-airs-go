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
    MaxScanIDs         = 5
    MaxReportIDs       = 5
    MaxBatchScanObjects = 5
)

// Retry
const (
    MaxRetries             = 5
    ForceRetryStatusCodes  = []int{500, 502, 503, 504}
)
```

---

## Package `scan`

### Scanner

```go
func NewScanner(cfg *aisec.Config) *Scanner

func (s *Scanner) SyncScan(ctx context.Context, profile AiProfile, content *Content, opts ...SyncScanOption) (*ScanResponse, error)
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
    Category         string            `json:"category"`
    Action           string            `json:"action"`
    ScanID           string            `json:"scan_id"`
    ReportID         string            `json:"report_id"`
    PromptDetected   *PromptDetected   `json:"prompt_detected,omitempty"`
    ResponseDetected *ResponseDetected `json:"response_detected,omitempty"`
}
```

---

## Package `management`

### Client

```go
func NewClient(opts Opts) *Client

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
func (c *ProfilesClient) Update(ctx context.Context, profileID string, req UpdateProfileRequest) (*SecurityProfile, error)
func (c *ProfilesClient) Delete(ctx context.Context, profileID string) (*DeleteProfileResponse, error)
func (c *ProfilesClient) GetByName(ctx context.Context, name string) (*SecurityProfile, error)
```

### TopicsClient

```go
func (c *TopicsClient) Create(ctx context.Context, req CreateTopicRequest) (*CustomTopic, error)
func (c *TopicsClient) List(ctx context.Context, opts ListOpts) (*CustomTopicListResponse, error)
func (c *TopicsClient) Update(ctx context.Context, topicID string, req UpdateTopicRequest) (*CustomTopic, error)
func (c *TopicsClient) Delete(ctx context.Context, topicID string) (*DeleteTopicResponse, error)
func (c *TopicsClient) ForceDelete(ctx context.Context, topicID string) (*DeleteTopicResponse, error)
```

### ApiKeysClient

```go
func (c *ApiKeysClient) Create(ctx context.Context, req CreateApiKeyRequest) (*ApiKey, error)
func (c *ApiKeysClient) List(ctx context.Context, opts ListOpts) (*ApiKeyListResponse, error)
func (c *ApiKeysClient) Delete(ctx context.Context, keyName string, updatedBy string) (*ApiKeyDeleteResponse, error)
func (c *ApiKeysClient) Regenerate(ctx context.Context, keyID string, req RegenerateKeyRequest) (*ApiKey, error)
```

---

## Package `modelsecurity`

### Client

```go
func NewClient(opts Opts) *Client

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
func NewClient(opts Opts) *Client

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
    Scans              *ScansClient
    Reports            *ReportsClient
    CustomAttackReports *CustomAttackReportsClient
    Targets            *TargetsClient
    CustomAttacks      *CustomAttacksClient
}

// Convenience methods
func (c *Client) GetScanStatistics(ctx context.Context, params StatsParams) (*ScanStatisticsResponse, error)
func (c *Client) GetScoreTrend(ctx context.Context, targetID string) (*ScoreTrendResponse, error)
func (c *Client) GetQuota(ctx context.Context) (*QuotaSummary, error)
func (c *Client) GetErrorLogs(ctx context.Context, jobID string, opts ErrorLogOpts) (*ErrorLogListResponse, error)
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
)

// Action
const (
    ActionAllow = "allow"
    ActionBlock = "block"
)

// Category
const (
    CategoryPromptInjection = "prompt_injection"
    CategoryJailbreak       = "jailbreak"
    CategorySQLInjection    = "sql_injection"
    CategoryXSS             = "xss"
    // ... (see source for complete list)
)
```

### Detection Services

```go
const (
    DetectionServiceDLP   = "DLP"
    DetectionServiceTC    = "TC"
    DetectionServiceDBS   = "DBS"
    DetectionServiceCI    = "CI"
    DetectionServiceURLF  = "URLF"
    DetectionServiceTG    = "TG"
    DetectionServiceCG    = "CG"
    DetectionServiceAGENT = "AGENT"
)
```
