package redteam

// --- EULA types ---

// EulaContentResponse is the EULA content response.
type EulaContentResponse struct {
	Content string `json:"content"`
}

// EulaResponse is the EULA status response.
type EulaResponse struct {
	UUID             string `json:"uuid,omitempty"`
	IsAccepted       bool   `json:"is_accepted"`
	AcceptedAt       string `json:"accepted_at,omitempty"`
	AcceptedByUserID string `json:"accepted_by_user_id,omitempty"`
}

// EulaAcceptRequest is the request to accept the EULA.
type EulaAcceptRequest struct {
	EulaContent string `json:"eula_content"`
	AcceptedAt  string `json:"accepted_at,omitempty"`
}
