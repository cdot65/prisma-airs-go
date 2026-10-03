package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/cdot65/prisma-airs-go/aisec"
	parity "github.com/cdot65/prisma-airs-go/aisec/parity/schema"
)

// Stream is a bounded SSE reader. Call Close when ending consumption before the terminal event.
// Next calls are serialized; Close may cancel a blocked read concurrently.
type Stream[T any] struct {
	reader        *bufio.Reader
	body          io.ReadCloser
	cancel        context.CancelFunc
	schema        string
	limit         int
	typedTerminal bool
	nextMu        sync.Mutex
	once          sync.Once
	closed        chan struct{}
	skipLF        bool
	failure       error
}

// Close releases the response body and deadline, even before the first Next.
func (s *Stream[T]) Close() error {
	s.once.Do(func() { close(s.closed); s.cancel(); _ = s.body.Close() })
	return nil
}

// Next returns one validated event, or io.EOF after the expected terminator.
func (s *Stream[T]) Next() (*T, error) {
	s.nextMu.Lock()
	defer s.nextMu.Unlock()
	if s.failure != nil {
		return nil, s.failure
	}
	select {
	case <-s.closed:
		return nil, io.EOF
	default:
	}
	fail := func(err error) (*T, error) { s.failure = err; _ = s.Close(); return nil, err }
	data := []string{}
	eventName := ""
	size := 0
	for {
		var line bytes.Buffer
		for {
			b, err := s.reader.ReadByte()
			if err != nil {
				select {
				case <-s.closed:
					return nil, io.EOF
				default:
				}
				if err == io.EOF {
					return fail(aisec.NewAISecSDKError("event stream ended before its terminator", aisec.AISecSDKInternalError))
				}
				return fail(aisec.WrapError("event stream read failed", aisec.ClientSideError, err))
			}
			if s.skipLF {
				s.skipLF = false
				if b == '\n' {
					continue
				}
			}
			size++
			if size > s.limit {
				return fail(aisec.NewAISecSDKError("SSE event exceeded its configured byte limit", aisec.AISecSDKInternalError))
			}
			if b == '\r' {
				s.skipLF = true
				break
			}
			if b == '\n' {
				break
			}
			line.WriteByte(b)
		}
		if !utf8.Valid(line.Bytes()) {
			return fail(aisec.NewAISecSDKError("event stream is not valid UTF-8", aisec.AISecSDKInternalError))
		}
		text := line.String()
		if text == "" {
			payload := strings.Join(data, "\n")
			name := eventName
			data = nil
			eventName = ""
			size = 0
			if payload == "" {
				continue
			}
			if payload == "[DONE]" {
				if s.typedTerminal {
					return fail(aisec.NewAISecSDKError("Responses stream ended before its typed terminator", aisec.AISecSDKInternalError))
				}
				_ = s.Close()
				return nil, io.EOF
			}
			if name == "error" {
				return fail(aisec.NewAISecSDKError("Gateway returned an error event", aisec.ServerSideError))
			}
			var fields map[string]json.RawMessage
			_ = json.Unmarshal([]byte(payload), &fields)
			if e, ok := fields["error"]; ok && eventErrorTruthy(e) {
				return fail(aisec.NewAISecSDKError("Gateway returned an error event", aisec.ServerSideError))
			}
			if err := parity.ValidateJSON(s.schema, []byte(payload)); err != nil {
				return fail(aisec.WrapError("invalid SSE response event", aisec.AISecSDKInternalError, err))
			}
			var value T
			if err := json.Unmarshal([]byte(payload), &value); err != nil {
				return fail(aisec.WrapError("invalid SSE JSON event", aisec.AISecSDKInternalError, err))
			}
			if s.typedTerminal {
				var typ string
				_ = json.Unmarshal(fields["type"], &typ)
				if typ == "response.completed" || typ == "response.failed" || typ == "response.incomplete" {
					_ = s.Close()
				}
			}
			return &value, nil
		}
		if strings.HasPrefix(text, ":") {
			continue
		}
		field, value, found := strings.Cut(text, ":")
		if !found {
			value = ""
		}
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "data":
			data = append(data, value)
		case "event":
			eventName = value
		}
	}
}
func hasStream(body any) bool {
	b, err := json.Marshal(body)
	if err != nil {
		return false
	}
	var fields map[string]any
	if json.Unmarshal(b, &fields) != nil {
		return false
	}
	return fields["stream"] == true
}
func inferenceStream[T any](ctx context.Context, c *InferenceClient, path string, body any, requestSchema, eventSchema string, terminal bool, opts InferenceRequestOptions) (*Stream[T], error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, aisec.WrapError("invalid stream request", aisec.UserRequestPayloadError, err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(encoded, &fields); err != nil {
		return nil, aisec.WrapError("stream request must be an object", aisec.UserRequestPayloadError, err)
	}
	fields["stream"] = json.RawMessage("true")
	encoded, err = json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	if err := parity.ValidateJSON(requestSchema, encoded); err != nil {
		return nil, aisec.WrapError("invalid stream request", aisec.UserRequestPayloadError, err)
	}
	r, cancel, err := c.open(ctx, http.MethodPost, path, nil, encoded, "application/json", opts)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "text/event-stream") {
		cancel()
		_ = r.Body.Close()
		return nil, aisec.NewAISecSDKError("expected text/event-stream response", aisec.AISecSDKInternalError)
	}
	return &Stream[T]{reader: bufio.NewReader(r.Body), body: r.Body, cancel: cancel, schema: eventSchema, limit: c.maxEventBytes, typedTerminal: terminal, closed: make(chan struct{})}, nil
}

// StreamChatCompletion streams typed chat deltas, terminating at [DONE].
func (c *InferenceClient) StreamChatCompletion(ctx context.Context, body parity.GatewayInferenceInputCreateChatCompletionRequest, opts InferenceRequestOptions) (*Stream[parity.GatewayInferenceCreateChatCompletionStreamResponse], error) {
	return inferenceStream[parity.GatewayInferenceCreateChatCompletionStreamResponse](ctx, c, aisec.GatewayInferenceChatCompletionsPath, body, "GatewayInferenceInputCreateChatCompletionRequestSchema", "GatewayInferenceCreateChatCompletionStreamResponseSchema", false, opts)
}

// StreamCompletion streams legacy text completion events.
func (c *InferenceClient) StreamCompletion(ctx context.Context, body parity.GatewayInferenceInputCreateCompletionRequest, opts InferenceRequestOptions) (*Stream[parity.GatewayInferenceCreateCompletionResponse], error) {
	return inferenceStream[parity.GatewayInferenceCreateCompletionResponse](ctx, c, aisec.GatewayInferenceCompletionsPath, body, "GatewayInferenceInputCreateCompletionRequestSchema", "GatewayInferenceCreateCompletionResponseSchema", false, opts)
}

// StreamPromptCompletion streams a saved prompt's native chat or completion events.
func (c *InferenceClient) StreamPromptCompletion(ctx context.Context, id string, body parity.GatewayInferenceInputCreatePromptCompletionRequest, opts InferenceRequestOptions) (*Stream[parity.GatewayInferenceCreatePromptCompletionStreamResponse], error) {
	if err := validateResourceID(id); err != nil {
		return nil, err
	}
	return inferenceStream[parity.GatewayInferenceCreatePromptCompletionStreamResponse](ctx, c, aisec.GatewayInferencePromptsPath+"/"+seg(id)+aisec.GatewayInferenceCompletionsPath, body, "GatewayInferenceInputCreatePromptCompletionRequestSchema", "GatewayInferenceCreatePromptCompletionStreamResponseSchema", false, opts)
}

// StreamResponse emits Responses events through response.completed/failed/incomplete, then releases the body.
func (c *InferenceClient) StreamResponse(ctx context.Context, body parity.GatewayInferenceInputCreateResponse, opts InferenceRequestOptions) (*Stream[parity.GatewayInferenceResponseStreamEvent], error) {
	return inferenceStream[parity.GatewayInferenceResponseStreamEvent](ctx, c, aisec.GatewayInferenceResponsesPath, body, "GatewayInferenceInputCreateResponseSchema", "GatewayInferenceResponseStreamEventSchema", true, opts)
}

func eventErrorTruthy(data json.RawMessage) bool {
	var value any
	if json.Unmarshal(data, &value) != nil {
		return true
	}
	switch v := value.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return v != ""
	case float64:
		return v != 0
	}
	return true
}
