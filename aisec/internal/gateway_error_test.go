package internal

import (
	"context"
	"errors"
	"github.com/cdot65/prisma-airs-go/aisec"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGatewayHTTPErrorIncludesEnvelopeMessage(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"success":false,"data":{"message":"Invalid request. Please check and try again.","errorCode":"bad_request"}}`))
	}))
	defer api.Close()
	cfg, _ := newOAuthFixture(t, api.URL, 0)
	result, err := DoMgmtRequest[map[string]any](context.Background(), cfg, MgmtRequestOptions{Method: http.MethodPost, Path: "/integrations"})
	if result != nil {
		t.Fatal("partial result")
	}
	var sdk *aisec.AISecSDKError
	if !errors.As(err, &sdk) || sdk.StatusCode != 400 || sdk.Message != "Invalid request. Please check and try again." {
		t.Fatalf("error=%v", err)
	}
}
