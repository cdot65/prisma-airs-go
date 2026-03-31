package redteam

// --- Custom Attack types ---

// CustomPromptSetCreateRequest is the request to create a prompt set.
type CustomPromptSetCreateRequest struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Properties  map[string]any `json:"properties,omitempty"`
}

// CustomPromptSetUpdateRequest is the request to update a prompt set.
type CustomPromptSetUpdateRequest struct {
	Name        string         `json:"name,omitempty"`
	Description string         `json:"description,omitempty"`
	Properties  map[string]any `json:"properties,omitempty"`
}

// CustomPromptSetArchiveRequest is the request to archive a prompt set.
type CustomPromptSetArchiveRequest struct {
	Archive bool `json:"archive"`
}

// CustomPromptSetResponse represents a custom prompt set.
type CustomPromptSetResponse struct {
	UUID            string         `json:"uuid"`
	Name            string         `json:"name,omitempty"`
	Description     string         `json:"description,omitempty"`
	Version         string         `json:"version,omitempty"`
	Status          string         `json:"status,omitempty"`
	Active          bool           `json:"active"`
	Archive         bool           `json:"archive"`
	Stats           map[string]any `json:"stats,omitempty"`
	ExtraInfo       map[string]any `json:"extra_info,omitempty"`
	PropertyNames   []string       `json:"property_names,omitempty"`
	CreatedAt       string         `json:"created_at,omitempty"`
	UpdatedAt       string         `json:"updated_at,omitempty"`
	CreatedByUserID string         `json:"created_by_user_id,omitempty"`
	UpdatedByUserID string         `json:"updated_by_user_id,omitempty"`
}

// CustomPromptSetList is the paginated list of prompt sets.
type CustomPromptSetList struct {
	Data       []CustomPromptSetResponse `json:"data"`
	Pagination RedTeamPagination         `json:"pagination"`
}

// CustomPromptSetListActive is the active prompt sets list.
type CustomPromptSetListActive struct {
	Data []CustomPromptSetResponse `json:"data"`
}

// CustomPromptSetReference is the reference for a prompt set.
type CustomPromptSetReference struct {
	UUID      string `json:"uuid,omitempty"`
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
	Status    string `json:"status,omitempty"`
	Active    bool   `json:"active"`
	TsgID     string `json:"tsg_id,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// CustomPromptSetVersionInfo is the version info for a prompt set.
type CustomPromptSetVersionInfo struct {
	UUID    string         `json:"uuid,omitempty"`
	Version map[string]any `json:"version,omitempty"`
}

// CustomPromptCreateRequest is the request to create a prompt.
type CustomPromptCreateRequest struct {
	PromptSetID string         `json:"prompt_set_id"`
	Prompt      string         `json:"prompt"`
	Goal        string         `json:"goal,omitempty"`
	Properties  map[string]any `json:"properties,omitempty"`
}

// CustomPromptUpdateRequest is the request to update a prompt.
type CustomPromptUpdateRequest struct {
	Prompt     string         `json:"prompt,omitempty"`
	Goal       string         `json:"goal,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

// CustomPromptResponse represents a custom prompt.
type CustomPromptResponse struct {
	UUID                string               `json:"uuid"`
	PromptSetID         string               `json:"prompt_set_id,omitempty"`
	Prompt              string               `json:"prompt,omitempty"`
	Goal                string               `json:"goal,omitempty"`
	UserDefinedGoal     bool                 `json:"user_defined_goal"`
	DetectorCategory    string               `json:"detector_category,omitempty"`
	Severity            string               `json:"severity,omitempty"`
	Properties          map[string]any       `json:"properties,omitempty"`
	PropertyAssignments []PropertyAssignment `json:"property_assignments,omitempty"`
	Active              bool                 `json:"active"`
	Status              string               `json:"status,omitempty"`
	ExtraInfo           map[string]any       `json:"extra_info,omitempty"`
	CreatedAt           string               `json:"created_at,omitempty"`
	UpdatedAt           string               `json:"updated_at,omitempty"`
}

// CustomPromptList is the paginated list of prompts.
type CustomPromptList struct {
	Data       []CustomPromptResponse `json:"data"`
	Pagination RedTeamPagination      `json:"pagination"`
}

// PropertyNamesListResponse lists property names.
type PropertyNamesListResponse struct {
	Data []string `json:"data"`
}

// PropertyNameCreateRequest is the request to create a property name.
type PropertyNameCreateRequest struct {
	Name string `json:"name"`
}

// PropertyValueCreateRequest is the request to create a property value.
type PropertyValueCreateRequest struct {
	PropertyName string `json:"property_name"`
	Value        string `json:"value"`
}

// PropertyValuesResponse lists values for a property.
type PropertyValuesResponse struct {
	Values []string `json:"values"`
}

// PropertyValuesMultipleResponse lists values for multiple properties.
type PropertyValuesMultipleResponse struct {
	Data map[string][]string `json:"data"`
}

// PropertyAssignment is a property name-value pair for prompts.
type PropertyAssignment struct {
	PropertyName  string `json:"property_name"`
	PropertyValue string `json:"property_value"`
}

// PropertyStatistic represents property statistics.
type PropertyStatistic struct {
	PropertyName string           `json:"property_name,omitempty"`
	Values       []map[string]any `json:"values,omitempty"`
}

// --- Custom Attack Report types ---

// CustomAttackReportResponse is the custom attack report.
type CustomAttackReportResponse struct {
	JobID   string         `json:"job_id,omitempty"`
	Stats   map[string]any `json:"stats,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

// PromptSetsReportResponse is the prompt sets report.
type PromptSetsReportResponse struct {
	Data []map[string]any `json:"data"`
}

// PromptDetailResponse is the detail of a single prompt.
type PromptDetailResponse struct {
	ID      string         `json:"id,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

// CustomAttacksListResponse is the paginated list of custom attacks in a report.
type CustomAttacksListResponse struct {
	Data       []map[string]any  `json:"data"`
	Pagination RedTeamPagination `json:"pagination"`
}

// CustomAttackOutput represents a custom attack output.
type CustomAttackOutput struct {
	ID      string         `json:"id,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}
