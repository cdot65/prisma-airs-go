package gateway

import (
	"context"
	"encoding/json"
	"github.com/cdot65/prisma-airs-go/aisec/gateway/schema"
	"os"
	"strings"
	"testing"
)

func TestAPIKeyScopedContracts(t *testing.T) {
	ctx := context.Background()
	var original map[string]contractFixture
	b, err := os.ReadFile("testdata/contracts.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &original); err != nil {
		t.Fatal(err)
	}
	var cases []contractCase
	fixtures := map[string]contractFixture{}
	for _, kind := range []APIKeyKind{APIKeyService, APIKeyUser} {
		for _, method := range []string{"List", "Get", "Update", "Delete", "Rotate"} {
			name := "APIKeys" + method + "ForKind" + string(kind)
			f := original["APIKeys"+method]
			fixtures[name] = f
			path := "/api-keys/" + string(kind)
			verb := "GET"
			if method != "List" {
				path += "/id%2Fpart"
			}
			switch method {
			case "Update":
				verb = "PUT"
			case "Delete":
				verb = "DELETE"
			case "Rotate":
				verb = "POST"
				path += "/rotate"
			}
			k := kind
			m := method
			cases = append(cases, contractCase{name, "data", verb, "", path, func(t *testing.T, c *Client, f contractFixture) (any, error) {
				switch m {
				case "List":
					return contractResult(c.APIKeys.ListForKind(ctx, k, contractValue[schema.APIKeysListOptions](t, f.Options)))
				case "Get":
					return contractResult(c.APIKeys.GetForKind(ctx, k, "id/part"))
				case "Update":
					return contractResult(c.APIKeys.UpdateForKind(ctx, k, "id/part", contractValue[schema.UpdateAPIKeyObject](t, f.Request)))
				case "Delete":
					return contractResult(c.APIKeys.DeleteForKind(ctx, k, "id/part"))
				default:
					return contractResult(c.APIKeys.RotateForKind(ctx, k, "id/part", contractValue[schema.RotateAPIKeyRequest](t, f.Request)))
				}
			}})
		}
	}
	runContracts(t, cases, fixtures)
	for _, tc := range cases {
		if !strings.HasPrefix(tc.path, "/api-keys/service") && !strings.HasPrefix(tc.path, "/api-keys/user") {
			t.Error("unexpected collection")
		}
	}
}
