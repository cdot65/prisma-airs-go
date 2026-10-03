package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	parity "github.com/cdot65/prisma-airs-go/aisec/parity/schema"
)

func inferenceTestClient(t *testing.T, handler http.HandlerFunc) *InferenceClient {
	t.Helper()
	s := httptest.NewServer(handler)
	t.Cleanup(s.Close)
	c, err := NewInferenceClient(InferenceOpts{Endpoint: s.URL, APIKey: "runtime-secret"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func chatRequest(t *testing.T) parity.GatewayInferenceInputCreateChatCompletionRequest {
	t.Helper()
	body, err := NewChatRequest("test", ChatTextMessage{Role: "user", Content: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	return body
}
func TestSSEFramingAndTerminal(t *testing.T) {
	event := `{"id":"chat","choices":[],"created":1,"model":"test","object":"chat.completion.chunk","future":{"keep":true}}`
	for _, newline := range []string{"\n", "\r", "\r\n"} {
		t.Run(strings.ReplaceAll(newline, "\r", "CR"), func(t *testing.T) {
			c := inferenceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, ": comment"+newline+"event: message"+newline+"data: "+event+newline+newline+"data: [DONE]"+newline+newline)
			})
			stream, err := c.StreamChatCompletion(context.Background(), chatRequest(t), InferenceRequestOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stream.Close() }()
			value, err := stream.Next()
			if err != nil || value == nil || value.ID != "chat" || value.AdditionalFields["future"] == nil {
				t.Fatalf("value=%#v err=%v", value, err)
			}
			if _, err = stream.Next(); err != io.EOF {
				t.Fatalf("terminator: %v", err)
			}
		})
	}
}
func TestSSERejectsTruncationErrorsAndOversizedEvents(t *testing.T) {
	for _, payload := range []string{"", "event: error\ndata: {\"message\":\"confidential\"}\n\n", "data: " + strings.Repeat("x", 2048) + "\n\n", "data: {}\n\n"} {
		t.Run(payload[:min(len(payload), 20)], func(t *testing.T) {
			c := inferenceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, payload)
			})
			c.maxEventBytes = 1024
			stream, err := c.StreamChatCompletion(context.Background(), chatRequest(t), InferenceRequestOptions{})
			if err != nil {
				t.Fatal(err)
			}
			_, err = stream.Next()
			if err == nil || err == io.EOF || strings.Contains(err.Error(), "confidential") {
				t.Fatalf("unsafe/silent stream error: %v", err)
			}
		})
	}
}

type readStarted struct {
	io.Reader
	started chan struct{}
	once    sync.Once
}

func (r *readStarted) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	return r.Reader.Read(p)
}
func TestSSECloseUnblocksRead(t *testing.T) {
	for _, operation := range []string{"close", "cancel"} {
		t.Run(operation, func(t *testing.T) {
			c := inferenceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stream, err := c.StreamChatCompletion(ctx, chatRequest(t), InferenceRequestOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stream.Close() }()
			started := make(chan struct{})
			stream.reader = bufio.NewReader(&readStarted{Reader: stream.body, started: started})
			done := make(chan error, 1)
			go func() { _, err := stream.Next(); done <- err }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("Next did not start its read")
			}
			if operation == "close" {
				_ = stream.Close()
			} else {
				cancel()
			}
			select {
			case err = <-done:
			case <-time.After(time.Second):
				t.Fatal("read was not unblocked")
			}
			if operation == "close" && err != io.EOF {
				t.Fatalf("explicit Close must return EOF: %v", err)
			}
			if operation == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatalf("caller cancellation must remain an error: %v", err)
			}
			_, again := stream.Next()
			if again != err {
				t.Fatalf("termination changed: %v -> %v", err, again)
			}
		})
	}
}
func TestRuntimeRedirectNeverLeaksKey(t *testing.T) {
	var reached atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Store(true) }))
	defer target.Close()
	c := inferenceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	})
	_, err := c.ListModels(context.Background(), parity.GatewayInferenceInputListModelsQuery{}, InferenceRequestOptions{})
	if err == nil || reached.Load() {
		t.Fatal("runtime redirect followed")
	}
	if strings.Contains(c.String(), "runtime-secret") {
		t.Fatal("credential exposed")
	}
}
func TestMultipartAudioAndRequiredBinary(t *testing.T) {
	var calls atomic.Int32
	c := inferenceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Error(err)
		}
		file, h, err := r.FormFile("file")
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = file.Close() }()
		data, _ := io.ReadAll(file)
		if h.Filename != "sample.wav" || string(data) != "sound" || r.FormValue("model") != "whisper-1" || r.FormValue("response_format") != "text" {
			t.Error("multipart wire mismatch")
		}
		_, _ = io.WriteString(w, "transcribed words")
	})
	format := "text"
	body := parity.GatewayInferenceInputCreateTranscriptionRequest{File: RuntimeFile{Filename: "sample.wav", ContentType: "audio/wav", Data: []byte("sound")}, Model: "whisper-1", ResponseFormat: &format}
	result, err := c.CreateTranscription(context.Background(), body, InferenceRequestOptions{})
	if err != nil || result.Text != "transcribed words" {
		t.Fatalf("audio=%#v err=%v", result, err)
	}
	body.File = nil
	if _, err = c.CreateTranscription(context.Background(), body, InferenceRequestOptions{}); err == nil || calls.Load() != 1 {
		t.Fatal("missing binary reached transport")
	}
}
func TestRuntimeRejectsAuthenticationOverrideBeforeTransport(t *testing.T) {
	var calls atomic.Int32
	c := inferenceTestClient(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1) })
	for _, header := range []string{"Authorization", "x-portkey-api-key", "x-tsg-id"} {
		_, err := c.ListModels(context.Background(), parity.GatewayInferenceInputListModelsQuery{}, InferenceRequestOptions{Headers: http.Header{header: {"secret"}}})
		if err == nil {
			t.Fatal("accepted authentication override")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request reached network")
	}
}

type mockSocket struct {
	frames chan WebSocketFrame
	closed chan struct{}
	once   sync.Once
	writes chan []byte
}

func (s *mockSocket) Read(ctx context.Context) (WebSocketFrame, error) {
	select {
	case f, ok := <-s.frames:
		if !ok {
			return WebSocketFrame{}, io.EOF
		}
		return f, nil
	case <-ctx.Done():
		return WebSocketFrame{}, ctx.Err()
	case <-s.closed:
		return WebSocketFrame{}, io.EOF
	}
}
func (s *mockSocket) Write(ctx context.Context, b []byte) error {
	select {
	case s.writes <- b:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.closed:
		return io.ErrClosedPipe
	}
}
func (s *mockSocket) Close() error { s.once.Do(func() { close(s.closed) }); return nil }
func realtimeTestConnection(t *testing.T, opts RealtimeOptions) (*RealtimeConnection, *mockSocket) {
	t.Helper()
	c, err := NewInferenceClient(InferenceOpts{Endpoint: "https://gateway.example/v1", APIKey: "runtime-key"})
	if err != nil {
		t.Fatal(err)
	}
	socket := &mockSocket{frames: make(chan WebSocketFrame, 8), closed: make(chan struct{}), writes: make(chan []byte, 8)}
	opts.WebSocketFactory = func(ctx context.Context, u string, d WebSocketDialOptions) (WebSocket, error) {
		if u != "wss://gateway.example/v1/realtime?model=test" || d.Headers.Get("x-portkey-api-key") != "runtime-key" || d.Headers.Get("Authorization") != "" || d.FollowRedirects || d.Compression {
			t.Error("incorrect realtime handshake")
		}
		return socket, nil
	}
	conn, err := c.ConnectRealtime(context.Background(), RealtimeConnectRequest{Model: "test"}, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, socket
}
func TestRealtimeProviderErrorIsEventAndCloseCancels(t *testing.T) {
	conn, socket := realtimeTestConnection(t, RealtimeOptions{})
	socket.frames <- WebSocketFrame{Data: []byte(`{"type":"error","error":{"code":"unsupported"}}`)}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	e, err := conn.Next(ctx)
	if err != nil || e.Type != "error" || e.Fields["error"] == nil {
		t.Fatalf("event=%#v err=%v", e, err)
	}
	if err = conn.Send(ctx, RealtimeEvent{Type: "session.update", Fields: map[string]any{"type": "cannot overwrite", "session": map[string]any{}}}); err != nil {
		t.Fatal(err)
	}
	if b := <-socket.writes; !strings.Contains(string(b), `"type":"session.update"`) {
		t.Fatalf("send=%s", b)
	}
	_ = conn.Close()
	if _, err = conn.Next(ctx); err != io.EOF {
		t.Fatalf("Close=%v", err)
	}
}
func TestRealtimeBoundsAndIdleDeadline(t *testing.T) {
	conn, socket := realtimeTestConnection(t, RealtimeOptions{MaxEventBytes: 16})
	socket.frames <- WebSocketFrame{Data: []byte(`{"type":"session.created"}`)}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := conn.Next(ctx); err == nil || err == io.EOF {
		t.Fatalf("event bound=%v", err)
	}
	conn, _ = realtimeTestConnection(t, RealtimeOptions{Timeout: 20 * time.Millisecond})
	if _, err := conn.Next(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("idle deadline=%v", err)
	}
}

func TestRemainingMultipartAndBinaryOperations(t *testing.T) {
	for _, operation := range []string{"file", "edit", "variation", "translation", "speech"} {
		t.Run(operation, func(t *testing.T) {
			c := inferenceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" || r.Header.Get("x-portkey-api-key") != "runtime-secret" {
					t.Error("incorrect inference authentication")
				}
				if operation == "speech" {
					if r.URL.Path != "/audio/speech" {
						t.Error(r.URL.Path)
					}
					w.Header().Set("Content-Type", "audio/mpeg")
					_, _ = w.Write([]byte{0, 1, 2, 255})
					return
				}
				if err := r.ParseMultipartForm(1 << 20); err != nil {
					t.Error(err)
					return
				}
				field := "image"
				if operation == "file" || operation == "translation" {
					field = "file"
				}
				file, h, err := r.FormFile(field)
				if err != nil {
					t.Error(err)
					return
				}
				defer func() { _ = file.Close() }()
				b, _ := io.ReadAll(file)
				if string(b) != "bytes" || h.Filename != "payload.bin" {
					t.Error("binary upload differs")
				}
				switch operation {
				case "file":
					if r.URL.Path != "/files" || r.FormValue("purpose") != "assistants" {
						t.Error("file route/purpose")
					}
					_, _ = io.WriteString(w, `{"id":"file1","object":"file","bytes":5,"created_at":1,"filename":"payload.bin","purpose":"assistants","status":"processed","status_details":null}`)
				case "translation":
					if r.URL.Path != "/audio/translations" {
						t.Error(r.URL.Path)
					}
					_, _ = io.WriteString(w, `{"text":"translated"}`)
				default:
					if operation == "edit" && r.URL.Path != "/images/edits" || operation == "variation" && r.URL.Path != "/images/variations" {
						t.Error(r.URL.Path)
					}
					_, _ = io.WriteString(w, `{"created":1,"data":[{"url":"https://example.com/image.png"}]}`)
				}
			})
			file := RuntimeFile{Filename: "payload.bin", Data: []byte("bytes")}
			var err error
			switch operation {
			case "file":
				_, err = c.CreateFile(context.Background(), parity.GatewayInferenceInputCreateFileRequest{File: file, Purpose: "assistants"}, InferenceRequestOptions{})
			case "edit":
				_, err = c.CreateImageEdit(context.Background(), parity.GatewayInferenceInputCreateImageEditRequest{Image: file, Prompt: "edit"}, InferenceRequestOptions{})
			case "variation":
				_, err = c.CreateImageVariation(context.Background(), parity.GatewayInferenceInputCreateImageVariationRequest{Image: file}, InferenceRequestOptions{})
			case "translation":
				var result *AudioResponse
				result, err = c.CreateTranslation(context.Background(), parity.GatewayInferenceInputCreateTranslationRequest{File: file, Model: "whisper-1"}, InferenceRequestOptions{})
				if err == nil && string(result.JSON) != `{"text":"translated"}` {
					t.Fatal(result)
				}
			case "speech":
				model, e := parity.NewGatewayInferenceInputCreateSpeechRequestModelFromString("tts-1")
				if e != nil {
					t.Fatal(e)
				}
				var result *BinaryResponse
				result, err = c.CreateSpeech(context.Background(), parity.GatewayInferenceInputCreateSpeechRequest{Model: model, Input: "hello", Voice: "alloy"}, InferenceRequestOptions{})
				if err == nil && (len(result.Body) != 4 || result.Body[3] != 255 || result.Headers.Get("Content-Type") != "audio/mpeg") {
					t.Fatal(result)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRealtimeNormalEOFDrainsBufferedEvents(t *testing.T) {
	conn, socket := realtimeTestConnection(t, RealtimeOptions{})
	socket.frames <- WebSocketFrame{Data: []byte(`{"type":"one"}`)}
	socket.frames <- WebSocketFrame{Data: []byte(`{"type":"two"}`)}
	close(socket.frames)
	select {
	case <-socket.closed:
	case <-time.After(time.Second):
		t.Fatal("reader did not close socket")
	}
	for _, typ := range []string{"one", "two"} {
		event, err := conn.Next(context.Background())
		if err != nil || event.Type != typ {
			t.Fatalf("event=%v err=%v", event, err)
		}
	}
	if _, err := conn.Next(context.Background()); err != io.EOF {
		t.Fatal(err)
	}
}

func TestOtherStreamingEntrypointsAndTypedTerminators(t *testing.T) {
	const completion = `{"id":"completion","object":"text_completion","created":1,"model":"test","choices":[]}`
	for _, kind := range []string{"completion", "prompt"} {
		t.Run(kind, func(t *testing.T) {
			c := inferenceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				expected := "/completions"
				if kind == "prompt" {
					expected = "/prompts/saved/completions"
				}
				if r.URL.Path != expected {
					t.Error(r.URL.Path)
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: "+completion+"\n\ndata: [DONE]\n\n")
			})
			if kind == "completion" {
				var body parity.GatewayInferenceInputCreateCompletionRequest
				if err := json.Unmarshal([]byte(`{"model":"test","prompt":"hello"}`), &body); err != nil {
					t.Fatal(err)
				}
				stream, err := c.StreamCompletion(context.Background(), body, InferenceRequestOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if _, err = stream.Next(); err != nil {
					t.Fatal(err)
				}
				if _, err = stream.Next(); err != io.EOF {
					t.Fatal(err)
				}
			} else {
				var body parity.GatewayInferenceInputCreatePromptCompletionRequest
				if err := json.Unmarshal([]byte(`{"prompt":"hello","variables":{}}`), &body); err != nil {
					t.Fatal(err)
				}
				stream, err := c.StreamPromptCompletion(context.Background(), "saved", body, InferenceRequestOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if _, err = stream.Next(); err != nil {
					t.Fatal(err)
				}
				if _, err = stream.Next(); err != io.EOF {
					t.Fatal(err)
				}
			}
		})
	}
	raw, err := os.ReadFile("testdata/response-terminal-events.json")
	if err != nil {
		t.Fatal(err)
	}
	var events map[string]json.RawMessage
	if err = json.Unmarshal(raw, &events); err != nil {
		t.Fatal(err)
	}
	for typ, event := range events {
		t.Run(typ, func(t *testing.T) {
			var compact bytes.Buffer
			if err := json.Compact(&compact, event); err != nil {
				t.Fatal(err)
			}
			c := inferenceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/responses" {
					t.Error(r.URL.Path)
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: "+compact.String()+"\n\n")
			})
			var body parity.GatewayInferenceInputCreateResponse
			if err = json.Unmarshal([]byte(`{"model":"test","input":"hello"}`), &body); err != nil {
				t.Fatal(err)
			}
			stream, err := c.StreamResponse(context.Background(), body, InferenceRequestOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = stream.Next(); err != nil {
				t.Fatal(err)
			}
			if _, err = stream.Next(); err != io.EOF {
				t.Fatal(err)
			}
		})
	}
}
func TestStreamErrorFieldMatchesTypeScriptTruthiness(t *testing.T) {
	for _, field := range []string{`""`, `0`, `false`, `null`} {
		c := inferenceTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, `data: {"id":"chat","choices":[],"created":1,"model":"test","object":"chat.completion.chunk","error":`+field+"}\n\ndata: [DONE]\n\n")
		})
		stream, err := c.StreamChatCompletion(context.Background(), chatRequest(t), InferenceRequestOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = stream.Next(); err != nil {
			t.Fatal("falsy error rejected:", err)
		}
		_ = stream.Close()
	}
}
