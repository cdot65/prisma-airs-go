package internal

import (
	"github.com/cdot65/prisma-airs-go/aisec"
	"net/url"
)

// ValidateEndpoint rejects URLs that expose credentials through plaintext or URL components.
func ValidateEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return aisec.NewAISecSDKError("endpoint must be an absolute URL without credentials, query or fragment", aisec.UserRequestPayloadError)
	}
	loopback := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return aisec.NewAISecSDKError("endpoint requires HTTPS except on loopback", aisec.UserRequestPayloadError)
	}
	return nil
}
