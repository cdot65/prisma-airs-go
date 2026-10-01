package redteam

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// Older Terraform consumers still construct Properties; retain its historical
// wire representation alongside the current property_names field.
func TestLegacyPromptSetPropertiesCompatibility(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			token, api := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != method {
					t.Errorf("method=%s", r.Method)
				}
				var body struct {
					Properties    map[string]any `json:"properties"`
					PropertyNames []string       `json:"property_names"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if body.Properties["legacy"] != "value" || len(body.PropertyNames) != 1 || body.PropertyNames[0] != "current" {
					t.Error("legacy/current fields lost")
				}
				_, _ = w.Write([]byte(`{"uuid":"id"}`))
			})
			defer token.Close()
			defer api.Close()
			c := newTestClient(t, token.URL, api.URL, api.URL)
			if method == http.MethodPost {
				if _, err := c.CustomAttacks.CreatePromptSet(context.Background(), CustomPromptSetCreateRequest{Name: "test", Properties: map[string]any{"legacy": "value"}, PropertyNames: []string{"current"}}); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := c.CustomAttacks.UpdatePromptSet(context.Background(), "id", CustomPromptSetUpdateRequest{Properties: map[string]any{"legacy": "value"}, PropertyNames: []string{"current"}}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
