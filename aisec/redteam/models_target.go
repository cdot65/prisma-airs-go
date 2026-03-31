package redteam

// --- Target types ---

// TargetCreateRequest is the request to create a target.
type TargetCreateRequest struct {
	Name                     string                   `json:"name"`
	Description              string                   `json:"description,omitempty"`
	TargetType               TargetType               `json:"target_type,omitempty"`
	ConnectionType           TargetConnectionType     `json:"connection_type,omitempty"`
	ConnectionParams         map[string]any           `json:"connection_params,omitempty"`
	APIEndpointType          APIEndpointType          `json:"api_endpoint_type,omitempty"`
	NetworkBrokerChannelUUID string                   `json:"network_broker_channel_uuid,omitempty"`
	ResponseMode             string                   `json:"response_mode,omitempty"`
	SessionSupported         bool                     `json:"session_supported"`
	ExtraInfo                map[string]any           `json:"extra_info,omitempty"`
	TargetMeta               *TargetMetadata          `json:"target_metadata,omitempty"`
	TargetBackground         *TargetBackground        `json:"target_background,omitempty"`
	AdditionalContext        *TargetAdditionalContext `json:"additional_context,omitempty"`
	AuthConfigType           AuthConfigType           `json:"auth_config_type,omitempty"`
	AuthConfig               any                      `json:"auth_config,omitempty"`
}

// TargetUpdateRequest is the request to update a target.
type TargetUpdateRequest struct {
	Name                     string                   `json:"name"`
	Description              string                   `json:"description,omitempty"`
	TargetType               TargetType               `json:"target_type,omitempty"`
	ConnectionType           TargetConnectionType     `json:"connection_type,omitempty"`
	ConnectionParams         map[string]any           `json:"connection_params,omitempty"`
	APIEndpointType          APIEndpointType          `json:"api_endpoint_type,omitempty"`
	NetworkBrokerChannelUUID string                   `json:"network_broker_channel_uuid,omitempty"`
	ResponseMode             ResponseMode             `json:"response_mode,omitempty"`
	SessionSupported         bool                     `json:"session_supported"`
	ExtraInfo                map[string]any           `json:"extra_info,omitempty"`
	TargetMeta               *TargetMetadata          `json:"target_metadata,omitempty"`
	TargetBackground         *TargetBackground        `json:"target_background,omitempty"`
	AdditionalContext        *TargetAdditionalContext `json:"additional_context,omitempty"`
	AuthConfigType           AuthConfigType           `json:"auth_config_type,omitempty"`
	AuthConfig               any                      `json:"auth_config,omitempty"`
}

// TargetContextUpdate is the request to update a target's context.
type TargetContextUpdate struct {
	TargetBackground  *TargetBackground        `json:"target_background,omitempty"`
	AdditionalContext *TargetAdditionalContext `json:"additional_context,omitempty"`
}

// TargetResponse represents a target.
type TargetResponse struct {
	UUID                     string                   `json:"uuid"`
	TsgID                    string                   `json:"tsg_id"`
	Name                     string                   `json:"name"`
	Description              string                   `json:"description,omitempty"`
	TargetType               TargetType               `json:"target_type,omitempty"`
	Status                   TargetStatus             `json:"status"`
	ConnectionType           TargetConnectionType     `json:"connection_type,omitempty"`
	ConnectionParams         map[string]any           `json:"connection_params,omitempty"`
	APIEndpointType          APIEndpointType          `json:"api_endpoint_type,omitempty"`
	NetworkBrokerChannelUUID string                   `json:"network_broker_channel_uuid,omitempty"`
	ResponseMode             string                   `json:"response_mode,omitempty"`
	SessionSupported         bool                     `json:"session_supported"`
	ExtraInfo                map[string]any           `json:"extra_info,omitempty"`
	Active                   bool                     `json:"active"`
	Validated                bool                     `json:"validated"`
	Version                  int                      `json:"version,omitempty"`
	SecretVersion            string                   `json:"secret_version,omitempty"`
	CreatedByUserID          string                   `json:"created_by_user_id,omitempty"`
	UpdatedByUserID          string                   `json:"updated_by_user_id,omitempty"`
	CreatedAt                string                   `json:"created_at"`
	UpdatedAt                string                   `json:"updated_at"`
	TargetMeta               *TargetMetadata          `json:"target_metadata,omitempty"`
	TargetBackground         *TargetBackground        `json:"target_background,omitempty"`
	ProfilingStatus          ProfilingStatus          `json:"profiling_status,omitempty"`
	AdditionalCtx            *TargetAdditionalContext `json:"additional_context,omitempty"`
	AuthConfigType           AuthConfigType           `json:"auth_config_type,omitempty"`
	AuthConfig               any                      `json:"auth_config,omitempty"`
}

// TargetListItem represents a target in a list response (TargetListItemSchema).
type TargetListItem struct {
	UUID             string               `json:"uuid"`
	TsgID            string               `json:"tsg_id"`
	Name             string               `json:"name"`
	Description      string               `json:"description,omitempty"`
	TargetType       TargetType           `json:"target_type,omitempty"`
	ConnectionType   TargetConnectionType `json:"connection_type,omitempty"`
	APIEndpointType  APIEndpointType      `json:"api_endpoint_type,omitempty"`
	ResponseMode     string               `json:"response_mode,omitempty"`
	SessionSupported bool                 `json:"session_supported"`
	ExtraInfo        map[string]any       `json:"extra_info,omitempty"`
	Status           TargetStatus         `json:"status"`
	Active           bool                 `json:"active"`
	Validated        bool                 `json:"validated"`
	Version          int                  `json:"version,omitempty"`
	SecretVersion    string               `json:"secret_version,omitempty"`
	CreatedByUserID  string               `json:"created_by_user_id,omitempty"`
	UpdatedByUserID  string               `json:"updated_by_user_id,omitempty"`
	CreatedAt        string               `json:"created_at"`
	UpdatedAt        string               `json:"updated_at"`
}

// TargetList is the paginated list of targets.
type TargetList struct {
	Data       []TargetListItem  `json:"data"`
	Pagination RedTeamPagination `json:"pagination"`
}

// TargetProbeRequest is the request to probe a target.
type TargetProbeRequest struct {
	Name                     string                   `json:"name"`
	Description              string                   `json:"description,omitempty"`
	TargetType               TargetType               `json:"target_type,omitempty"`
	ConnectionType           TargetConnectionType     `json:"connection_type,omitempty"`
	APIEndpointType          APIEndpointType          `json:"api_endpoint_type,omitempty"`
	ResponseMode             ResponseMode             `json:"response_mode,omitempty"`
	SessionSupported         *bool                    `json:"session_supported"`
	ConnectionParams         map[string]any           `json:"connection_params,omitempty"`
	NetworkBrokerChannelUUID string                   `json:"network_broker_channel_uuid,omitempty"`
	ExtraInfo                map[string]any           `json:"extra_info,omitempty"`
	TargetMetadata           *TargetMetadata          `json:"target_metadata,omitempty"`
	TargetBackground         *TargetBackground        `json:"target_background,omitempty"`
	AdditionalContext        *TargetAdditionalContext `json:"additional_context,omitempty"`
	UUID                     string                   `json:"uuid,omitempty"`
	ProbeFields              []string                 `json:"probe_fields,omitempty"`
}

// TargetProfileResponse is the target profile response.
type TargetProfileResponse struct {
	TargetID          string                   `json:"target_id"`
	TargetVersion     int                      `json:"target_version"`
	Status            string                   `json:"status"`
	TargetBackground  *TargetBackground        `json:"target_background,omitempty"`
	AdditionalContext *TargetAdditionalContext `json:"additional_context,omitempty"`
	OtherDetails      *OtherDetails            `json:"other_details,omitempty"`
	AIGeneratedFields []string                 `json:"ai_generated_fields,omitempty"`
	ProfilingStatus   ProfilingStatus          `json:"profiling_status,omitempty"`
}

// --- Target context types ---

// HeadersAuthConfig is auth config using custom headers.
type HeadersAuthConfig struct {
	AuthHeader map[string]string `json:"auth_header"`
}

// BasicAuthAuthConfig is auth config using basic authentication.
type BasicAuthAuthConfig struct {
	BasicAuthLocation BasicAuthLocation `json:"basic_auth_location,omitempty"`
	BasicAuthHeader   map[string]string `json:"basic_auth_header,omitempty"`
}

// OAuth2AuthConfig is auth config using OAuth2 client credentials.
type OAuth2AuthConfig struct {
	OAuth2TokenURL         string            `json:"oauth2_token_url"`
	OAuth2ExpiryMinutes    int               `json:"oauth2_expiry_minutes,omitempty"`
	OAuth2Headers          map[string]string `json:"oauth2_headers,omitempty"`
	OAuth2BodyParams       map[string]string `json:"oauth2_body_params,omitempty"`
	OAuth2TokenResponseKey string            `json:"oauth2_token_response_key,omitempty"`
	OAuth2InjectHeader     map[string]string `json:"oauth2_inject_header"`
}

// TargetAuthValidationRequest is the request to validate target auth.
type TargetAuthValidationRequest struct {
	AuthType                 AuthConfigType `json:"auth_type"`
	AuthConfig               any            `json:"auth_config"`
	TargetID                 string         `json:"target_id,omitempty"`
	NetworkBrokerChannelUUID string         `json:"network_broker_channel_uuid,omitempty"`
}

// TargetAuthValidationResponse is the response from auth validation.
type TargetAuthValidationResponse struct {
	Validated    bool   `json:"validated"`
	TokenPreview string `json:"token_preview,omitempty"`
	ExpiresIn    *int   `json:"expires_in,omitempty"`
}

// TargetMetadata holds target metadata for probing/profiling.
type TargetMetadata struct {
	MultiTurn                 bool           `json:"multi_turn"`
	MultiTurnErrorMessage     string         `json:"multi_turn_error_message,omitempty"`
	RateLimit                 *int           `json:"rate_limit,omitempty"`
	RateLimitEnabled          bool           `json:"rate_limit_enabled"`
	RateLimitErrorCode        *int           `json:"rate_limit_error_code,omitempty"`
	RateLimitErrorJSON        map[string]any `json:"rate_limit_error_json,omitempty"`
	RateLimitErrorMessage     string         `json:"rate_limit_error_message,omitempty"`
	ContentFilterEnabled      bool           `json:"content_filter_enabled"`
	ContentFilterErrorCode    *int           `json:"content_filter_error_code,omitempty"`
	ContentFilterErrorJSON    map[string]any `json:"content_filter_error_json,omitempty"`
	ContentFilterErrorMessage string         `json:"content_filter_error_message,omitempty"`
	ProbeMessage              string         `json:"probe_message,omitempty"`
	RequestTimeout            *float64       `json:"request_timeout,omitempty"`
}

// TargetBackground holds target background context.
type TargetBackground struct {
	Industry    string   `json:"industry,omitempty"`
	UseCase     string   `json:"use_case,omitempty"`
	Competitors []string `json:"competitors,omitempty"`
}

// OtherDetails holds additional profiler discoveries.
type OtherDetails struct {
	Items map[string]any `json:"items,omitempty"`
}

// TargetAdditionalContext holds additional context for a target.
type TargetAdditionalContext struct {
	BaseModel          string   `json:"base_model,omitempty"`
	CoreArchitecture   string   `json:"core_architecture,omitempty"`
	SystemPrompt       string   `json:"system_prompt,omitempty"`
	LanguagesSupported []string `json:"languages_supported,omitempty"`
	BannedKeywords     []string `json:"banned_keywords,omitempty"`
	ToolsAccessible    []string `json:"tools_accessible,omitempty"`
}
