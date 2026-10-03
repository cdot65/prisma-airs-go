package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/cdot65/prisma-airs-go/aisec"
	parity "github.com/cdot65/prisma-airs-go/aisec/parity/schema"
)

func TestPricingPreservesRetainedUnauthenticatedCatalog(t *testing.T) {
	data, err := os.ReadFile("testdata/typescript-pricing.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Raw json.RawMessage `json:"raw"`
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/model-configs/pricing/provider%2Fname/model%2Fname" || r.Method != "GET" {
			t.Error(r.URL)
		}
		for _, h := range []string{"Authorization", "x-portkey-api-key", "x-tsg-id"} {
			if r.Header.Get(h) != "" {
				t.Error("pricing sent credentials")
			}
		}
		_, _ = w.Write(fixture.Raw)
	}))
	defer server.Close()
	c, err := NewModelPricingClient(ModelPricingOpts{Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Get(context.Background(), "provider/name", "model/name")
	if err != nil {
		t.Fatal(err)
	}
	marshaled, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var a, b any
	_ = json.Unmarshal(marshaled, &a)
	_ = json.Unmarshal(fixture.Raw, &b)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("pricing altered catalog rates or unevaluated expressions")
	}
}

func TestFeedbackRejectsNonUUIDBeforeTransport(t *testing.T) {
	c := inferenceTestClient(t, func(http.ResponseWriter, *http.Request) { t.Error("invalid ID reached transport") })
	_, err := c.UpdateFeedback(context.Background(), "not-a-uuid", parity.GatewayInferenceInputFeedbackUpdateRequest{}, InferenceRequestOptions{})
	if err == nil {
		t.Fatal("accepted invalid feedback ID")
	}
}

func TestResponseStreamRequiresTypedTerminator(t *testing.T) {
	c := inferenceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	})
	var body parity.GatewayInferenceInputCreateResponse
	if err := json.Unmarshal([]byte(`{"model":"test","input":"hello"}`), &body); err != nil {
		t.Fatal(err)
	}
	stream, err := c.StreamResponse(context.Background(), body, InferenceRequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Next(); err == nil || err == io.EOF {
		t.Fatal("accepted untyped Responses termination")
	}
}

func TestRealtimeTransportFailureIsStickyAndDiscardsQueue(t *testing.T) {
	conn, socket := realtimeTestConnection(t, RealtimeOptions{})
	socket.frames <- WebSocketFrame{Data: []byte(`{"type":"session.created"}`)}
	socket.frames <- WebSocketFrame{Data: []byte(`invalid`)}
	select {
	case <-conn.done:
	case <-time.After(time.Second):
		t.Fatal("transport failure did not close connection")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, first := conn.Next(ctx)
	_, second := conn.Next(ctx)
	if first == nil || first == io.EOF || first != second {
		t.Fatal("transport failure must take precedence over queued events, matching TypeScript")
	}
}

func TestEmptyInferenceResponsePolicy(t *testing.T) {
	c := inferenceTestClient(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	if _, err := c.ListModels(context.Background(), parity.GatewayInferenceInputListModelsQuery{}, InferenceRequestOptions{}); err == nil {
		t.Fatal("required typed response accepted empty body")
	}
	if err := c.DeleteResponse(context.Background(), "response", InferenceRequestOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestMultipartPreservesNativeOptionalNumbers(t *testing.T) {
	body := struct {
		Large aisec.Optional[int64] `json:"large,omitempty"`
		Small float32               `json:"small"`
	}{aisec.Value[int64](9007199254740993), 0.1}
	data, kind, err := runtimeMultipart(body)
	if err != nil {
		t.Fatal(err)
	}
	_, params, err := mime.ParseMediaType(kind)
	if err != nil {
		t.Fatal(err)
	}
	reader := multipart.NewReader(bytes.NewReader(data), params["boundary"])
	got := map[string]string{}
	for {
		part, e := reader.NextPart()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		b, e := io.ReadAll(part)
		if e != nil {
			t.Fatal(e)
		}
		got[part.FormName()] = string(b)
	}
	if got["large"] != "9007199254740993" || got["small"] != "0.1" {
		t.Fatal(got)
	}
}
