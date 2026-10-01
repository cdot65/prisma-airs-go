package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/cdot65/prisma-airs-go/aisec"
)

func TestDeleteResponseCompatibility(t *testing.T) {
	for _, contentType := range []string{"text/plain", "application/json", "application/vnd.airs+json"} {
		for _, body := range []string{`Profile deleted`, `"Profile deleted"`} {
			for _, operation := range []string{"profile force", "topic", "topic force"} {
				t.Run(operation+"/"+contentType+"/"+body, func(t *testing.T) {
					token, api := newTestMgmtServer(t, func(w http.ResponseWriter, _ *http.Request) {
						w.Header().Set("Content-Type", contentType)
						_, _ = w.Write([]byte(body))
					})
					defer token.Close()
					defer api.Close()
					client := newTestClient(t, token.URL, api.URL)
					var err error
					switch operation {
					case "profile force":
						_, err = client.Profiles.ForceDelete(context.Background(), "p", "me")
					case "topic":
						_, err = client.Topics.Delete(context.Background(), "t")
					case "topic force":
						_, err = client.Topics.ForceDelete(context.Background(), "t", "me")
					}
					if err != nil {
						t.Fatalf("successful deletion with Content-Type=%q body=%q returned %v", contentType, body, err)
					}
				})
			}
		}
	}
}

func TestProfiles_RejectInvalidStructuredSuccess(t *testing.T) {
	for _, body := range []string{
		`{"profile_id":`,
		`{"profile_id":"partial","revision":"wrong"}`,
		`[]`, `"OK"`, `null`, "", " \n\t ", `OK`,
	} {
		t.Run(body, func(t *testing.T) {
			token, api := newTestMgmtServer(t, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(body))
			})
			defer token.Close()
			defer api.Close()
			client := newTestClient(t, token.URL, api.URL)
			profile, err := client.Profiles.Create(context.Background(), CreateProfileRequest{ProfileName: "test"})
			var sdkErr *aisec.AISecSDKError
			if profile != nil || !errors.As(err, &sdkErr) {
				t.Fatalf("profile=%+v error=%v; want nil result and SDK error", profile, err)
			}
			if sdkErr.ErrorType != aisec.AISecSDKInternalError || sdkErr.StatusCode != http.StatusOK {
				t.Errorf("error=%+v; want decoding error carrying HTTP 200", sdkErr)
			}
			if body == `{"profile_id":"partial","revision":"wrong"}` {
				var typeErr *json.UnmarshalTypeError
				if !errors.As(err, &typeErr) {
					t.Errorf("decode cause lost: %v", err)
				}
			}
			if body == `{"profile_id":` {
				var syntaxErr *json.SyntaxError
				if !errors.As(err, &syntaxErr) {
					t.Errorf("decode cause lost: %v", err)
				}
			}
		})
	}
}

func TestProfiles_UnknownResponseFieldsRemainAccepted(t *testing.T) {
	token, api := newTestMgmtServer(t, func(w http.ResponseWriter, _ *http.Request) {
		// Decode the body, even if the server's content type is inaccurate.
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(`{"profile_id":"p-1","new_upstream_field":true}`))
	})
	defer token.Close()
	defer api.Close()
	profile, err := newTestClient(t, token.URL, api.URL).Profiles.Create(context.Background(), CreateProfileRequest{})
	if err != nil || profile == nil || profile.ProfileID != "p-1" {
		t.Fatalf("profile=%+v error=%v", profile, err)
	}
}

func TestDeleteResponseExpectations(t *testing.T) {
	cases := []struct {
		name, body, contentType string
		call                    func(*Client) error
		wantError               bool
	}{
		{"profile force text", "deleted", "", func(c *Client) error { _, err := c.Profiles.ForceDelete(context.Background(), "p", "me"); return err }, false},
		{"profile force empty", "", "", func(c *Client) error { _, err := c.Profiles.ForceDelete(context.Background(), "p", "me"); return err }, false},
		{"profile force malformed", `{"message":`, "", func(c *Client) error { _, err := c.Profiles.ForceDelete(context.Background(), "p", "me"); return err }, true},
		{"profile force wrong type", `{"message":42}`, "", func(c *Client) error { _, err := c.Profiles.ForceDelete(context.Background(), "p", "me"); return err }, true},
		{"profile force null", "null", "", func(c *Client) error { _, err := c.Profiles.ForceDelete(context.Background(), "p", "me"); return err }, true},
		{"profile force JSON header", "deleted", "application/json", func(c *Client) error { _, err := c.Profiles.ForceDelete(context.Background(), "p", "me"); return err }, false},
		{"profile force JSON suffix", "deleted", "application/vnd.airs+json; charset=utf-8", func(c *Client) error { _, err := c.Profiles.ForceDelete(context.Background(), "p", "me"); return err }, false},
		{"profile force HTML", "<html>Proxy error</html>", "text/html", func(c *Client) error { _, err := c.Profiles.ForceDelete(context.Background(), "p", "me"); return err }, true},
		{"profile force HTML with BOM", "\ufeff  <html>Proxy error</html>", "text/html", func(c *Client) error { _, err := c.Profiles.ForceDelete(context.Background(), "p", "me"); return err }, true},
		{"profile force JSON scalar", "42", "text/plain", func(c *Client) error { _, err := c.Profiles.ForceDelete(context.Background(), "p", "me"); return err }, true},
		{"ordinary profile delete text", "deleted", "", func(c *Client) error { _, err := c.Profiles.Delete(context.Background(), "p"); return err }, true},
		{"ordinary profile delete empty", "", "", func(c *Client) error { _, err := c.Profiles.Delete(context.Background(), "p"); return err }, true},
		{"topic text", "deleted", "", func(c *Client) error { _, err := c.Topics.Delete(context.Background(), "t"); return err }, false},
		{"topic force empty", "", "", func(c *Client) error { _, err := c.Topics.ForceDelete(context.Background(), "t", "me"); return err }, false},
		{"topic malformed", `"unfinished`, "", func(c *Client) error { _, err := c.Topics.Delete(context.Background(), "t"); return err }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token, api := newTestMgmtServer(t, func(w http.ResponseWriter, _ *http.Request) {
				if tc.contentType != "" {
					w.Header().Set("Content-Type", tc.contentType)
				}
				_, _ = w.Write([]byte(tc.body))
			})
			defer token.Close()
			defer api.Close()
			err := tc.call(newTestClient(t, token.URL, api.URL))
			if (err != nil) != tc.wantError {
				t.Fatalf("error=%v; wantError=%v", err, tc.wantError)
			}
		})
	}
}

func TestTopics_DeleteDecodesBothDocumentedJSONShapes(t *testing.T) {
	for _, body := range []string{`"deleted"`, `{"message":"deleted","new_field":true}`} {
		for _, force := range []bool{false, true} {
			name := body + "/delete"
			if force {
				name = body + "/force"
			}
			t.Run(name, func(t *testing.T) {
				token, api := newTestMgmtServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) })
				defer token.Close()
				defer api.Close()
				client := newTestClient(t, token.URL, api.URL)
				var result *DeleteTopicResponse
				var err error
				if force {
					result, err = client.Topics.ForceDelete(context.Background(), "t", "me")
				} else {
					result, err = client.Topics.Delete(context.Background(), "t")
				}
				if err != nil || result == nil || result.Message != "deleted" {
					t.Fatalf("result=%+v error=%v", result, err)
				}
			})
		}
	}
}
