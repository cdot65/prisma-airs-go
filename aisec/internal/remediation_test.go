package internal

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdot65/prisma-airs-go/aisec"
)

// newOAuthFixture returns a healthy token server (counting fetches) and an
// OAuthServiceConfig pointing at apiURL.
func newOAuthFixture(t *testing.T, apiURL string, retries int) (*OAuthServiceConfig, *int32) {
	t.Helper()
	var tokenHits int32
	tok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&tokenHits, 1)
		_, _ = w.Write([]byte(`{"access_token":"t","expires_in":3600,"token_type":"Bearer"}`))
	}))
	t.Cleanup(tok.Close)
	oc := NewOAuthClient(OAuthClientOpts{ClientID: "a", ClientSecret: "b", TsgID: "1", TokenEndpoint: tok.URL})
	return &OAuthServiceConfig{BaseURL: apiURL, OAuth: oc, NumRetries: retries, TsgID: "1"}, &tokenHits
}

// A persistent 401/403 used to hot-loop forever because the token-refresh
// retry never consumed retry budget. It must now stop after one refresh.
func TestDoMgmtRequest_Persistent403IsBounded(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		var apiHits int32
		api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			atomic.AddInt32(&apiHits, 1)
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"message":"denied"}`))
		}))
		cfg, tokenHits := newOAuthFixture(t, api.URL, 5)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := DoMgmtRequest[map[string]any](ctx, cfg, MgmtRequestOptions{Method: http.MethodGet, Path: "/x"})
		cancel()
		api.Close()

		if err == nil {
			t.Fatalf("status %d: expected an error", status)
		}
		if got := atomic.LoadInt32(&apiHits); got != 2 {
			t.Errorf("status %d: API hits = %d, want 2 (original + one post-refresh retry)", status, got)
		}
		if got := atomic.LoadInt32(tokenHits); got != 2 {
			t.Errorf("status %d: token fetches = %d, want 2", status, got)
		}
		var sdkErr *aisec.AISecSDKError
		if !errors.As(err, &sdkErr) || sdkErr.StatusCode != status {
			t.Errorf("status %d: error = %#v, want SDK error carrying the status", status, err)
		}
	}
}

// One stale-token 401 must still recover transparently.
func TestDoMgmtRequest_RecoversFromStaleToken(t *testing.T) {
	var apiHits int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&apiHits, 1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer api.Close()
	cfg, tokenHits := newOAuthFixture(t, api.URL, 0) // zero retry budget: refresh must still be free

	resp, err := DoMgmtRequest[map[string]any](context.Background(), cfg, MgmtRequestOptions{Method: http.MethodGet, Path: "/x"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Data["ok"] != true {
		t.Errorf("data = %v", resp.Data)
	}
	if atomic.LoadInt32(tokenHits) != 2 {
		t.Errorf("token fetches = %d, want 2 (initial + refresh)", atomic.LoadInt32(tokenHits))
	}
}

// Two separate requests each get their own free refresh (state is per request).
func TestAuthRefreshHandler_IsPerRequest(t *testing.T) {
	oc := NewOAuthClient(OAuthClientOpts{ClientID: "a", ClientSecret: "b", TsgID: "1"})
	newResp := func(code int) *http.Response {
		return &http.Response{StatusCode: code, Body: http.NoBody}
	}
	h1 := NewAuthRefreshHandler(oc)
	if ok, _ := h1(newResp(403), 0); !ok {
		t.Error("first 403 should request a refresh retry")
	}
	if ok, _ := h1(newResp(403), 0); ok {
		t.Error("second 403 on the same request must not retry")
	}
	if ok, _ := NewAuthRefreshHandler(oc)(newResp(401), 0); !ok {
		t.Error("a fresh handler should grant its own refresh")
	}
	if ok, _ := NewAuthRefreshHandler(oc)(newResp(500), 0); ok {
		t.Error("non-auth statuses are not the handler's business")
	}
}

func TestExecuteWithRetry_429HonorsRetryAfter(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	start := time.Now()
	resp, err := ExecuteWithRetry(RetryOptions{
		MaxRetries: 2,
		Execute:    func(int) (*http.Response, error) { return http.Get(srv.URL) },
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if hits != 2 {
		t.Errorf("hits = %d, want 2", hits)
	}
	if time.Since(start) > 900*time.Millisecond {
		t.Errorf("Retry-After: 0 should skip jittered backoff, took %v", time.Since(start))
	}
}

func TestExecuteWithRetry_429ExhaustedMapsToRateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"message":"slow down"}`))
	}))
	defer srv.Close()

	_, err := ExecuteWithRetry(RetryOptions{
		MaxRetries: 1,
		Execute:    func(int) (*http.Response, error) { return http.Get(srv.URL) },
	})
	if !errors.Is(err, aisec.ErrRateLimited) {
		t.Errorf("err = %v, want ErrRateLimited", err)
	}
}

func TestExecuteWithRetry_ErrorsCarryStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"no such thing"}`)) // note: no "404"/"not found" text
	}))
	defer srv.Close()

	_, err := ExecuteWithRetry(RetryOptions{
		MaxRetries: 0,
		Execute:    func(int) (*http.Response, error) { return http.Get(srv.URL) },
	})
	if !aisec.IsNotFound(err) {
		t.Fatalf("IsNotFound(%v) = false", err)
	}
	var sdkErr *aisec.AISecSDKError
	if !errors.As(err, &sdkErr) || sdkErr.StatusCode != 404 || sdkErr.ErrorType != aisec.ClientSideError {
		t.Errorf("err = %#v", err)
	}
	if aisec.IsNotFound(aisec.NewAISecSDKError("x", aisec.ClientSideError)) {
		t.Error("an error without a status must not match ErrNotFound")
	}
}

func TestExecuteWithRetry_ContextCancelStopsBackoff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := ExecuteWithRetry(RetryOptions{
		Ctx:        ctx,
		MaxRetries: 5,
		Execute:    func(int) (*http.Response, error) { return http.Get(srv.URL) },
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want it to wrap context.DeadlineExceeded", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("cancellation took %v; the 30s Retry-After sleep was not interrupted", time.Since(start))
	}
}

func TestRetryAfterDelay(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		header string
		want   time.Duration
		ok     bool
	}{
		{"seconds", "7", 7 * time.Second, true},
		{"zero", "0", 0, true},
		{"capped", "86400", 30 * time.Second, true},
		{"http-date", now.Add(5 * time.Second).UTC().Format(http.TimeFormat), 5 * time.Second, true},
		{"past date", now.Add(-time.Hour).UTC().Format(http.TimeFormat), 0, true},
		{"negative", "-3", 0, false},
		{"garbage", "soon", 0, false},
		{"absent", "", 0, false},
	}
	for _, c := range cases {
		h := http.Header{}
		if c.header != "" {
			h.Set("Retry-After", c.header)
		}
		got, ok := RetryAfterDelay(h, now)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: got (%v,%v), want (%v,%v)", c.name, got, ok, c.want, c.ok)
		}
	}
}

// A hung token endpoint must be cancellable through the caller's context.
func TestGetTokenContext_CancelsHungTokenEndpoint(t *testing.T) {
	release := make(chan struct{})
	tok := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body) // the server only notices a client disconnect once the body is read
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer tok.Close()
	defer close(release)

	oc := NewOAuthClient(OAuthClientOpts{ClientID: "a", ClientSecret: "b", TsgID: "1", TokenEndpoint: tok.URL})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := oc.GetTokenContext(ctx)
	if err == nil {
		t.Fatal("expected error")
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("token fetch ignored the context for %v", time.Since(start))
	}
}

// Waiters must receive the leader's real error, not a generic message.
func TestGetTokenContext_WaitersShareLeaderError(t *testing.T) {
	started := make(chan struct{})
	proceed := make(chan struct{})
	var once sync.Once
	tok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		once.Do(func() { close(started) })
		<-proceed
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error_description":"bad client credentials"}`))
	}))
	defer tok.Close()

	oc := NewOAuthClient(OAuthClientOpts{ClientID: "a", ClientSecret: "b", TsgID: "1", TokenEndpoint: tok.URL})

	leaderErr := make(chan error, 1)
	go func() { _, err := oc.GetToken(); leaderErr <- err }()
	<-started

	waiterErr := make(chan error, 1)
	go func() { _, err := oc.GetToken(); waiterErr <- err }()
	waitForWaiters(t, oc, 1)
	close(proceed)

	for name, ch := range map[string]chan error{"leader": leaderErr, "waiter": waiterErr} {
		err := <-ch
		if err == nil || !strings.Contains(err.Error(), "bad client credentials") {
			t.Errorf("%s error = %v, want the token endpoint's description", name, err)
		}
	}
}

// If the leader gives up because *its* context ended, a waiter whose context is
// still live must fetch for itself instead of inheriting the cancellation.
func TestGetTokenContext_WaiterRetriesWhenLeaderCancelled(t *testing.T) {
	started := make(chan struct{})
	var calls int32
	tok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if atomic.AddInt32(&calls, 1) == 1 {
			close(started)
			<-r.Context().Done() // leader's request hangs until its ctx is cancelled
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"second","expires_in":3600}`))
	}))
	defer tok.Close()

	oc := NewOAuthClient(OAuthClientOpts{ClientID: "a", ClientSecret: "b", TsgID: "1", TokenEndpoint: tok.URL})

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	go func() { _, _ = oc.GetTokenContext(leaderCtx) }()
	<-started

	type result struct {
		tok string
		err error
	}
	res := make(chan result, 1)
	go func() {
		tk, err := oc.GetTokenContext(context.Background())
		res <- result{tk, err}
	}()
	waitForWaiters(t, oc, 1)
	cancelLeader()

	select {
	case r := <-res:
		if r.err != nil || r.tok != "second" {
			t.Errorf("waiter got (%q, %v), want a token from its own fetch", r.tok, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter never completed")
	}
}

type countingTransport struct {
	hits int32
	next http.RoundTripper
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	atomic.AddInt32(&c.hits, 1)
	return c.next.RoundTrip(r)
}

// A caller-supplied *http.Client must carry both API and token traffic.
func TestInjectedHTTPClientIsUsedForAPIAndTokens(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) }))
	defer api.Close()
	tok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"t","expires_in":3600}`))
	}))
	defer tok.Close()

	ct := &countingTransport{next: http.DefaultTransport}
	cfg, err := ResolveOAuthConfig(ResolveOAuthConfigOpts{
		ClientID: "a", ClientSecret: "b", TsgID: "1",
		BaseURL: api.URL, TokenEndpoint: tok.URL, NumRetries: 0,
		PrimaryEnvPrefix: "PANW_TEST_NONE",
		HTTPClient:       &http.Client{Transport: ct},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DoMgmtRequest[map[string]any](context.Background(), cfg, MgmtRequestOptions{Method: http.MethodGet, Path: "/x"}); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&ct.hits); got != 2 {
		t.Errorf("custom transport saw %d requests, want 2 (token + API)", got)
	}
}

func TestDoMgmtRaw_ReturnsBodyAndHonorsContentType(t *testing.T) {
	var gotCT string
	var gotBody []byte
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte("a,b\n1,2\n"))
	}))
	defer api.Close()
	cfg, _ := newOAuthFixture(t, api.URL, 0)

	raw, err := DoMgmtRaw(context.Background(), cfg, RawMgmtRequestOptions{
		Method: http.MethodPost, Path: "/up", Body: []byte("payload"), ContentType: "multipart/form-data; boundary=x",
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotCT != "multipart/form-data; boundary=x" || string(gotBody) != "payload" {
		t.Errorf("server saw content-type %q body %q", gotCT, gotBody)
	}
	if string(raw.Body) != "a,b\n1,2\n" || raw.Status != 200 {
		t.Errorf("raw = %+v", raw)
	}
}

func TestResolveEndpoint(t *testing.T) {
	t.Setenv("PANW_TEST_EP", "https://env.example/")
	if got := ResolveEndpoint("https://opt.example//", "PANW_TEST_EP", "https://def.example"); got != "https://opt.example" {
		t.Errorf("explicit = %q", got)
	}
	if got := ResolveEndpoint("", "PANW_TEST_EP", "https://def.example"); got != "https://env.example" {
		t.Errorf("env = %q", got)
	}
	if got := ResolveEndpoint("", "PANW_TEST_UNSET", "https://def.example/"); got != "https://def.example" {
		t.Errorf("default = %q", got)
	}
}

// waitForWaiters blocks until n callers are parked on an in-flight token fetch,
// so tests do not depend on scheduler timing.
func waitForWaiters(t *testing.T, oc *OAuthClient, n int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for atomic.LoadInt32(&oc.waiters) < n {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d parked waiter(s)", n)
		}
		time.Sleep(time.Millisecond)
	}
}

func tokenServerWith(t *testing.T, handler http.HandlerFunc) (*OAuthClient, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		atomic.AddInt32(&hits, 1)
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return NewOAuthClient(OAuthClientOpts{ClientID: "a", ClientSecret: "b", TsgID: "1", TokenEndpoint: srv.URL}), &hits
}

// Bad credentials are not transient: one request, and the error carries 401.
func TestTokenFetch_CredentialErrorsAreNotRetriedAndCarryStatus(t *testing.T) {
	oc, hits := tokenServerWith(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	})
	_, err := oc.GetToken()
	if !errors.Is(err, aisec.ErrUnauthorized) {
		t.Errorf("err = %v, want ErrUnauthorized", err)
	}
	var sdkErr *aisec.AISecSDKError
	if !errors.As(err, &sdkErr) || sdkErr.ErrorType != aisec.OAuthError {
		t.Errorf("err = %#v, want an OAuthError", err)
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Errorf("token endpoint hit %d times, want 1", atomic.LoadInt32(hits))
	}
}

func TestTokenFetch_RetriesTransient503ThenSucceeds(t *testing.T) {
	var n int32
	oc, hits := tokenServerWith(t, func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"ok","expires_in":3600}`))
	})
	tok, err := oc.GetToken()
	if err != nil || tok != "ok" {
		t.Fatalf("got (%q, %v)", tok, err)
	}
	if atomic.LoadInt32(hits) != 2 {
		t.Errorf("hits = %d, want 2", atomic.LoadInt32(hits))
	}
}

func TestTokenFetch_PersistentRateLimitIsBoundedAndTyped(t *testing.T) {
	oc, hits := tokenServerWith(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTooManyRequests) })
	_, err := oc.GetToken()
	if !errors.Is(err, aisec.ErrRateLimited) {
		t.Errorf("err = %v, want ErrRateLimited", err)
	}
	if got := atomic.LoadInt32(hits); got != tokenFetchAttempts {
		t.Errorf("hits = %d, want %d", got, tokenFetchAttempts)
	}
}

type panicOnceTransport struct{ n int32 }

func (p *panicOnceTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if atomic.AddInt32(&p.n, 1) == 1 {
		panic("transport exploded")
	}
	return http.DefaultTransport.RoundTrip(r)
}

// A panic while fetching must not leave later callers parked forever.
func TestGetToken_PanicDuringFetchDoesNotWedgeClient(t *testing.T) {
	tok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"after","expires_in":3600}`))
	}))
	defer tok.Close()
	oc := NewOAuthClient(OAuthClientOpts{ClientID: "a", ClientSecret: "b", TsgID: "1", TokenEndpoint: tok.URL,
		HTTPClient: &http.Client{Transport: &panicOnceTransport{}}})

	func() {
		defer func() { _ = recover() }()
		_, _ = oc.GetToken()
	}()

	done := make(chan string, 1)
	go func() { tk, _ := oc.GetToken(); done <- tk }()
	select {
	case tk := <-done:
		if tk != "after" {
			t.Errorf("token = %q", tk)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client wedged after a panicking fetch")
	}
}

func TestPathSeg(t *testing.T) {
	cases := map[string]string{
		"plain": "plain", "a/b": "a%2Fb", "x?y#z": "x%3Fy%23z", "has space": "has%20space",
		".": "%2E", "..": "%2E%2E", "a..b": "a..b",
	}
	for in, want := range cases {
		if got := PathSeg(in); got != want {
			t.Errorf("PathSeg(%q) = %q, want %q", in, got, want)
		}
	}
}

// A server that accepts the connection but never answers must not hang a
// request forever: the default transport gives up after the header timeout.
func TestDefaultTransport_GivesUpOnServerThatNeverResponds(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	old := DefaultResponseHeaderTimeout
	DefaultResponseHeaderTimeout = 150 * time.Millisecond
	defer func() { DefaultResponseHeaderTimeout = old }()
	client := &http.Client{Transport: newDefaultTransport()}

	start := time.Now()
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil) // deliberately no context deadline
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("expected a timeout error")
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("took %v; the response-header timeout did not apply", time.Since(start))
	}
	if tr := DefaultHTTPClient().Transport.(*http.Transport); tr.MaxIdleConnsPerHost != aisec.MaxConnectionPoolSize {
		t.Errorf("MaxIdleConnsPerHost = %d", tr.MaxIdleConnsPerHost)
	}
}

// Malformed token responses are a server/config problem, not a transient one.
func TestTokenFetch_MalformedBodyIsNotRetried(t *testing.T) {
	oc, hits := tokenServerWith(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`not json`)) })
	if _, err := oc.GetToken(); err == nil {
		t.Fatal("expected error")
	}
	if got := atomic.LoadInt32(hits); got != 1 {
		t.Errorf("hits = %d, want 1", got)
	}
}

// The fetch's own timeout must not look like the leader's context ending.
func TestTokenFetch_OwnTimeoutDoesNotWrapContextError(t *testing.T) {
	oc, _ := tokenServerWith(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	old := tokenFetchTimeoutOverride
	tokenFetchTimeoutOverride = 100 * time.Millisecond
	defer func() { tokenFetchTimeoutOverride = old }()

	_, err := oc.GetToken()
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Errorf("err = %v must not wrap a context error", err)
	}
}
