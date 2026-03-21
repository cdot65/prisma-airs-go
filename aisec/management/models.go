package management

import "time"

// ListOpts are common pagination options.
type ListOpts struct {
	Limit  int
	Offset int
}

// SecurityProfile represents an AI security profile.
type SecurityProfile struct {
	ProfileID   string         `json:"profile_id,omitempty"`
	ProfileName string         `json:"profile_name,omitempty"`
	Active      bool           `json:"active,omitempty"`
	Policy      map[string]any `json:"policy,omitempty"`
	CreatedAt   string         `json:"created_at,omitempty"`
	UpdatedAt   string         `json:"updated_at,omitempty"`
}

// SecurityProfileListResponse is the list response for profiles.
type SecurityProfileListResponse struct {
	Items      []SecurityProfile `json:"items"`
	TotalCount int               `json:"total_count,omitempty"`
}

// CreateProfileRequest is the request to create a profile.
type CreateProfileRequest struct {
	ProfileName string         `json:"profile_name"`
	Policy      map[string]any `json:"policy,omitempty"`
}

// UpdateProfileRequest is the request to update a profile.
type UpdateProfileRequest struct {
	ProfileName string         `json:"profile_name,omitempty"`
	Policy      map[string]any `json:"policy,omitempty"`
}

// DeleteProfileResponse is the response from deleting a profile.
type DeleteProfileResponse struct {
	Message string `json:"message,omitempty"`
}

// CustomTopic represents a custom detection topic.
type CustomTopic struct {
	TopicID     string   `json:"topic_id,omitempty"`
	TopicName   string   `json:"topic_name,omitempty"`
	Description string   `json:"description,omitempty"`
	Examples    []string `json:"examples,omitempty"`
	CreatedAt   string   `json:"created_at,omitempty"`
	UpdatedAt   string   `json:"updated_at,omitempty"`
}

// CustomTopicListResponse is the list response for topics.
type CustomTopicListResponse struct {
	Items      []CustomTopic `json:"items"`
	TotalCount int           `json:"total_count,omitempty"`
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

// ApiKey represents an API key.
type ApiKey struct {
	ApiKeyID   string    `json:"api_key_id,omitempty"`
	ApiKeyName string    `json:"api_key_name,omitempty"`
	ApiKey     string    `json:"api_key,omitempty"`
	Active     bool      `json:"active,omitempty"`
	CreatedAt  string    `json:"created_at,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
}

// ApiKeyListResponse is the list response for API keys.
type ApiKeyListResponse struct {
	Items      []ApiKey `json:"items"`
	TotalCount int      `json:"total_count,omitempty"`
}

// CreateApiKeyRequest is the request to create an API key.
type CreateApiKeyRequest struct {
	ApiKeyName string `json:"api_key_name"`
	UpdatedBy  string `json:"updated_by,omitempty"`
}

// RegenerateKeyRequest is the request to regenerate an API key.
type RegenerateKeyRequest struct {
	UpdatedBy string `json:"updated_by,omitempty"`
}

// ApiKeyDeleteResponse is the response from deleting an API key.
type ApiKeyDeleteResponse struct {
	Message string `json:"message,omitempty"`
}

// CustomerApp represents a customer application.
type CustomerApp struct {
	AppID       string `json:"app_id,omitempty"`
	AppName     string `json:"app_name,omitempty"`
	Description string `json:"description,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

// CustomerAppListResponse is the list response for customer apps.
type CustomerAppListResponse struct {
	Items      []CustomerApp `json:"items"`
	TotalCount int           `json:"total_count,omitempty"`
}

// CreateAppRequest is the request to create a customer app.
type CreateAppRequest struct {
	AppName     string `json:"app_name"`
	Description string `json:"description,omitempty"`
}

// UpdateAppRequest is the request to update a customer app.
type UpdateAppRequest struct {
	AppName     string `json:"app_name,omitempty"`
	Description string `json:"description,omitempty"`
}

// DeleteAppResponse is the response from deleting a customer app.
type DeleteAppResponse struct {
	Message string `json:"message,omitempty"`
}

// DlpProfile represents a DLP data profile.
type DlpProfile struct {
	ProfileID   string         `json:"profile_id,omitempty"`
	ProfileName string         `json:"profile_name,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
}

// DlpProfileListResponse is the list response for DLP profiles.
type DlpProfileListResponse struct {
	Items      []DlpProfile `json:"items"`
	TotalCount int          `json:"total_count,omitempty"`
}

// DeploymentProfile represents a deployment profile.
type DeploymentProfile struct {
	ProfileID   string         `json:"profile_id,omitempty"`
	ProfileName string         `json:"profile_name,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
}

// DeploymentProfileListResponse is the list response for deployment profiles.
type DeploymentProfileListResponse struct {
	Items      []DeploymentProfile `json:"items"`
	TotalCount int                 `json:"total_count,omitempty"`
}

// ScanLog represents a scan activity log entry.
type ScanLog struct {
	LogID     string         `json:"log_id,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
	CreatedAt string         `json:"created_at,omitempty"`
}

// ScanLogListOpts are options for listing scan logs.
type ScanLogListOpts struct {
	Limit  int
	Offset int
}

// ScanLogListResponse is the list response for scan logs.
type ScanLogListResponse struct {
	Items      []ScanLog `json:"items"`
	TotalCount int       `json:"total_count,omitempty"`
}

// OAuthToken represents an OAuth token from the management API.
type OAuthToken struct {
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
}

// InvalidateTokenResponse is the response from invalidating a token.
type InvalidateTokenResponse struct {
	Message string `json:"message,omitempty"`
}
