package gateway

import (
	"context"
	"net/http"

	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
)

// WorkspaceClearSettingsRequest selects supported settings to clear. Only true
// fields are sent. These explicit null/empty bodies were verified against SCM
// on 2026-10-03; they extend the recovered non-nullable update contract.
// Defaults covers config_id and metadata only; unreadable controls such as
// allow_config_override are outside this clear contract. Description is absent:
// SCM preserves the previous description for observed blank writes.
type WorkspaceClearSettingsRequest struct {
	Defaults    bool // Clears default config selection and the complete default metadata map.
	UsageLimits bool // Sends the verified null clear rather than an empty array.
	RateLimits  bool // Sends an empty array.
	Icon        bool // Sends an empty string.
}

// ClearSettings removes selected workspace settings on the admin plane.
// Call Get afterwards to verify normalization and the resulting state. This
// does not delete a routing config or standalone policy owned elsewhere.
func (c *WorkspacesClient) ClearSettings(ctx context.Context, ref string, req WorkspaceClearSettingsRequest) error {
	if !workspaceRefPattern.MatchString(ref) {
		return invalidInput("expected a workspace UUID or slug")
	}
	body := map[string]any{}
	if req.Defaults {
		body["defaults"] = map[string]any{"config_id": nil, "metadata": map[string]any{}}
	}
	if req.UsageLimits {
		body["usage_limits"] = nil
	}
	if req.RateLimits {
		body["rate_limits"] = []any{}
	}
	if req.Icon {
		body["icon"] = ""
	}
	if len(body) == 0 {
		return invalidInput("at least one workspace setting must be selected")
	}
	_, err := internal.DoMgmtRequest[any](ctx, c.adminCfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.GatewayWorkspacesPath + "/" + seg(ref), Body: body, ResponsePolicy: internal.AllowEmptyJSON})
	return err
}
