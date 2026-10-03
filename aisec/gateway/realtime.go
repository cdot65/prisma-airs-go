package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/cdot65/prisma-airs-go/aisec"
	parity "github.com/cdot65/prisma-airs-go/aisec/parity/schema"
)

// WebSocketFrame distinguishes unsupported binary frames from UTF-8 JSON events.
type WebSocketFrame struct {
	Data   []byte
	Binary bool
}

// WebSocket is a caller-owned adapter. Read/Write must honor context; Close must unblock outstanding reads.
// Dial must reject redirects and compression and enforce the supplied maximum payload.
type WebSocket interface {
	Read(context.Context) (WebSocketFrame, error)
	Write(context.Context, []byte) error
	Close() error
}

// WebSocketDialOptions explicitly disables redirects/compression and limits the handshake and frames.
type WebSocketDialOptions struct {
	Headers                      http.Header
	HandshakeTimeout             time.Duration
	MaxPayload                   int
	FollowRedirects, Compression bool
}

// WebSocketFactory completes the HTTP upgrade; an upgrade does not prove provider session readiness.
// Its context covers dialing only. The returned socket uses the contexts passed to Read/Write.
type WebSocketFactory func(context.Context, string, WebSocketDialOptions) (WebSocket, error)

// RealtimeOptions requires an explicit adapter, leaving the SDK dependency-free.
type RealtimeOptions struct {
	Headers                                            http.Header
	Timeout, HandshakeTimeout                          time.Duration
	MaxEventBytes, MaxBufferedEvents, MaxBufferedBytes int
	WebSocketFactory                                   WebSocketFactory
}

// RealtimeConnectRequest preserves provider-specific string query parameters.
type RealtimeConnectRequest struct {
	Model      string
	Parameters map[string]string
}

// RealtimeEvent is an extensible, finite JSON event with a required Type.
// Fields cannot overwrite the event type.
type RealtimeEvent struct {
	Type   string
	Fields map[string]any
}

func (e RealtimeEvent) MarshalJSON() ([]byte, error) {
	if e.Type == "" {
		return nil, invalidInput("realtime event type is required")
	}
	fields := map[string]any{}
	for k, v := range e.Fields {
		if k != "type" {
			fields[k] = v
		}
	}
	fields["type"] = e.Type
	return json.Marshal(fields)
}
func (e *RealtimeEvent) UnmarshalJSON(data []byte) error {
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	typ, ok := fields["type"].(string)
	if !ok || typ == "" {
		return invalidInput("realtime event type is required")
	}
	delete(fields, "type")
	e.Type = typ
	e.Fields = fields
	return nil
}

// RealtimeConnection owns a bounded event queue and closes its socket on deadline, cancellation or overflow.
// Provider errors remain events; the SDK does not convert an upgrade into a successful model session.
type RealtimeConnection struct {
	socket                                    WebSocket
	ctx                                       context.Context
	cancel                                    context.CancelFunc
	events                                    chan realtimeQueued
	done                                      chan struct{}
	once                                      sync.Once
	mu, writeMu                               sync.Mutex
	failure                                   error
	closed                                    bool
	buffered, maxBufferedBytes, maxEventBytes int
}
type realtimeQueued struct {
	event *RealtimeEvent
	size  int
}

// ConnectRealtime uses runtime-key authentication and no retries or SCM OAuth.
func (c *InferenceClient) ConnectRealtime(ctx context.Context, req RealtimeConnectRequest, opts RealtimeOptions) (*RealtimeConnection, error) {
	if opts.WebSocketFactory == nil {
		return nil, invalidInput("realtime requires an explicit WebSocketFactory")
	}
	if err := inferenceHeaders(opts.Headers); err != nil {
		return nil, err
	}
	if opts.Timeout < 0 || opts.HandshakeTimeout < 0 || opts.MaxEventBytes < 0 || opts.MaxBufferedEvents < 0 || opts.MaxBufferedBytes < 0 {
		return nil, invalidInput("realtime limits must be nonnegative")
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = c.timeout
	}
	handshake := opts.HandshakeTimeout
	if handshake == 0 {
		handshake = 10 * time.Second
	}
	maxEvent := opts.MaxEventBytes
	if maxEvent == 0 {
		maxEvent = c.maxEventBytes
	}
	maxEvents := opts.MaxBufferedEvents
	if maxEvents == 0 {
		maxEvents = 256
	}
	maxBytes := opts.MaxBufferedBytes
	if maxBytes == 0 {
		maxBytes = 4 << 20
	}
	if maxEvents > 1000000 {
		return nil, invalidInput("realtime event queue exceeds its supported bound")
	}
	u, err := url.Parse(c.baseURL + aisec.GatewayInferenceRealtimePath)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	q := u.Query()
	for k, v := range req.Parameters {
		if !utf8.ValidString(k) || !utf8.ValidString(v) {
			return nil, invalidInput("realtime query must be valid UTF-8")
		}
		q.Set(k, v)
	}
	if req.Model != "" {
		q.Set("model", req.Model)
	}
	fields := map[string]string{}
	for k, v := range q {
		fields[k] = v[0]
	}
	if err := parity.Validate("GatewayRealtimeConnectRequestSchema", fields); err != nil {
		return nil, aisec.WrapError("invalid realtime query", aisec.UserRequestPayloadError, err)
	}
	u.RawQuery = q.Encode()
	headers := opts.Headers.Clone()
	if headers == nil {
		headers = http.Header{}
	}
	c.authenticate(headers)
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	handCtx, handCancel := context.WithTimeout(callCtx, handshake)
	socket, err := opts.WebSocketFactory(handCtx, u.String(), WebSocketDialOptions{Headers: headers, HandshakeTimeout: handshake, MaxPayload: maxEvent, FollowRedirects: false, Compression: false})
	handCancel()
	if err != nil {
		cancel()
		return nil, aisec.WrapError("realtime upgrade failed", aisec.ClientSideError, err)
	}
	if socket == nil {
		cancel()
		return nil, invalidInput("WebSocketFactory returned a nil socket")
	}
	connection := &RealtimeConnection{socket: socket, ctx: callCtx, cancel: cancel, events: make(chan realtimeQueued, maxEvents), done: make(chan struct{}), maxBufferedBytes: maxBytes, maxEventBytes: maxEvent}
	go connection.readLoop()
	go func() {
		select {
		case <-callCtx.Done():
			connection.fail(aisec.WrapError("realtime deadline or cancellation", aisec.ClientSideError, callCtx.Err()))
		case <-connection.done:
		}
	}()
	return connection, nil
}
func (c *RealtimeConnection) fail(err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	if c.failure == nil {
		c.failure = err
	}
	c.mu.Unlock()
	_ = c.Close()
}

func (c *RealtimeConnection) readLoop() {
	defer close(c.events)
	for {
		frame, err := c.socket.Read(c.ctx)
		if err != nil {
			select {
			case <-c.done:
				return
			default:
			}
			if err == io.EOF {
				_ = c.Close()
				return
			}
			c.fail(aisec.WrapError("realtime read failed", aisec.ClientSideError, err))
			return
		}
		if frame.Binary || len(frame.Data) > c.maxEventBytes || !utf8.Valid(frame.Data) {
			c.fail(aisec.NewAISecSDKError("invalid realtime frame or exceeded event limit", aisec.AISecSDKInternalError))
			return
		}
		var event RealtimeEvent
		if err := json.Unmarshal(frame.Data, &event); err != nil {
			c.fail(aisec.WrapError("invalid realtime JSON event", aisec.AISecSDKInternalError, err))
			return
		}
		c.mu.Lock()
		overflow := c.buffered+len(frame.Data) > c.maxBufferedBytes
		if !overflow {
			c.buffered += len(frame.Data)
		}
		c.mu.Unlock()
		if overflow {
			c.fail(aisec.NewAISecSDKError("realtime byte queue exceeded its bound", aisec.AISecSDKInternalError))
			return
		}
		select {
		case c.events <- realtimeQueued{event: &event, size: len(frame.Data)}:
		case <-c.done:
			return
		default:
			c.fail(aisec.NewAISecSDKError("realtime event queue exceeded its bound", aisec.AISecSDKInternalError))
			return
		}
	}
}

// Next reads one queued event; io.EOF follows draining a normally closed socket.
// Transport failures are sticky and discard queued events, matching the TypeScript client.
func (c *RealtimeConnection) Next(ctx context.Context) (*RealtimeEvent, error) {
	c.mu.Lock()
	failure := c.failure
	c.mu.Unlock()
	if failure != nil {
		return nil, failure
	}
	take := func(item realtimeQueued, ok bool) (*RealtimeEvent, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if ok {
			c.buffered -= item.size
		}
		if c.failure != nil {
			return nil, c.failure
		}
		if !ok {
			return nil, io.EOF
		}
		return item.event, nil
	}
	// Drain already queued events before reporting a normal socket close.
	select {
	case item, ok := <-c.events:
		return take(item, ok)
	default:
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case item, ok := <-c.events:
		return take(item, ok)
	case <-c.done:
		select {
		case item, ok := <-c.events:
			return take(item, ok)
		default:
		}
		c.mu.Lock()
		failure = c.failure
		c.mu.Unlock()
		if failure != nil {
			return nil, failure
		}
		return nil, io.EOF
	}
}

// Send validates one finite JSON event and reports transport failures through both Send and Next.
func (c *RealtimeConnection) Send(ctx context.Context, event RealtimeEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return aisec.WrapError("invalid realtime send event", aisec.UserRequestPayloadError, err)
	}
	if len(data) > c.maxEventBytes {
		return invalidInput("realtime send event exceeded its byte limit")
	}
	select {
	case <-c.done:
		return io.ErrClosedPipe
	default:
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	sendCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	if err := c.socket.Write(sendCtx, data); err != nil {
		wrapped := aisec.WrapError("realtime write failed", aisec.ClientSideError, err)
		c.fail(wrapped)
		return wrapped
	}
	return nil
}

// Close cancels the owned socket, even if event consumption has not started.
func (c *RealtimeConnection) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		close(c.done)
		c.mu.Unlock()
		c.cancel()
		_ = c.socket.Close()
	})
	return nil
}

// String never exposes runtime authentication material.
func (c *InferenceClient) String() string { return "AI Gateway inference client (credentials hidden)" }
