package redteam

import (
	"context"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cdot65/prisma-airs-go/aisec"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("disk on fire") }

func TestClient_EndpointsFromEnvironment(t *testing.T) {
	var dataHits, mgmtHits int32
	tok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"t","expires_in":3600}`))
	}))
	data := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&dataHits, 1)
		_, _ = w.Write([]byte(`{}`))
	}))
	mgmt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&mgmtHits, 1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer tok.Close()
	defer data.Close()
	defer mgmt.Close()
	t.Setenv("PANW_RED_TEAM_DATA_ENDPOINT", data.URL)
	t.Setenv("PANW_RED_TEAM_MGMT_ENDPOINT", mgmt.URL+"/")

	client, err := NewClient(Opts{ClientID: "a", ClientSecret: "b", TsgID: "1", TokenEndpoint: tok.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = client.Scans.List(context.Background(), ScanListOpts{})     // data plane
	_, _ = client.Targets.List(context.Background(), TargetListOpts{}) // mgmt plane
	if atomic.LoadInt32(&dataHits) != 1 || atomic.LoadInt32(&mgmtHits) != 1 {
		t.Errorf("data hits = %d, mgmt hits = %d; want 1 and 1", dataHits, mgmtHits)
	}
}

func TestUploadPromptsCsv_SendsMultipartFileAndQuery(t *testing.T) {
	var gotQuery, gotName, gotContent string
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("prompt_set_uuid")
		mt, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mt != "multipart/form-data" {
			t.Errorf("content-type = %q (%v)", r.Header.Get("Content-Type"), err)
			return
		}
		part, err := multipart.NewReader(r.Body, params["boundary"]).NextPart()
		if err != nil {
			t.Error(err)
			return
		}
		b, _ := io.ReadAll(part)
		gotName, gotContent = part.FileName(), string(b)
		_, _ = w.Write([]byte(`{"message":"uploaded"}`))
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()
	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)

	resp, err := client.CustomAttacks.UploadPromptsCsv(context.Background(), "ps-1", strings.NewReader("prompt\nhello\n"), "p.csv")
	if err != nil {
		t.Fatal(err)
	}
	if gotQuery != "ps-1" || gotName != "p.csv" || gotContent != "prompt\nhello\n" || resp.Message != "uploaded" {
		t.Errorf("query=%q file=%q content=%q resp=%+v", gotQuery, gotName, gotContent, resp)
	}
}

func TestUploadPromptsCsv_ReaderFailureIsAnSDKError(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, _ *http.Request) { t.Error("no request should be sent") })
	defer tokenSrv.Close()
	defer apiSrv.Close()
	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)

	_, err := client.CustomAttacks.UploadPromptsCsv(context.Background(), "ps", failingReader{}, "f.csv")
	var sdkErr *aisec.AISecSDKError
	if !errors.As(err, &sdkErr) || sdkErr.ErrorType != aisec.UserRequestPayloadError {
		t.Errorf("err = %#v, want *AISecSDKError of type UserRequestPayloadError", err)
	}
}

// The three raw endpoints each carried their own copy of the unbounded
// 401/403 retry loop; all of them now share the bounded one.
func TestRawEndpoints_Persistent403Terminates(t *testing.T) {
	calls := map[string]func(c *Client) error{
		"DownloadReport": func(c *Client) error {
			_, err := c.Reports.DownloadReport(context.Background(), "j", FileFormatJSON)
			return err
		},
		"DownloadTemplate": func(c *Client) error {
			_, err := c.CustomAttacks.DownloadTemplate(context.Background(), "ps")
			return err
		},
		"UploadPromptsCsv": func(c *Client) error {
			_, err := c.CustomAttacks.UploadPromptsCsv(context.Background(), "ps", strings.NewReader("x"), "f.csv")
			return err
		},
	}
	for name, call := range calls {
		var hits int32
		tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, _ *http.Request) {
			atomic.AddInt32(&hits, 1)
			w.WriteHeader(http.StatusForbidden)
		})
		client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)

		err := call(client)
		tokenSrv.Close()
		apiSrv.Close()

		if !errors.Is(err, aisec.ErrForbidden) {
			t.Errorf("%s: err = %v, want ErrForbidden", name, err)
		}
		if got := atomic.LoadInt32(&hits); got != 2 {
			t.Errorf("%s: API hits = %d, want 2", name, got)
		}
	}
}

func TestDownloadReport_ReturnsRawBytes(t *testing.T) {
	want := []byte{0x00, 0x01, 'P', 'K', 0xff}
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("file_format") != "CSV" {
			t.Errorf("file_format = %q", r.URL.Query().Get("file_format"))
		}
		_, _ = w.Write(want)
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()
	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)

	got, err := client.Reports.DownloadReport(context.Background(), "j", FileFormatCSV)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("bytes = %v, want %v", got, want)
	}
}

func TestGeneratePartialReport_PostsAndParses(t *testing.T) {
	tokenSrv, apiSrv := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/report/job-9/generate-partial-report" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"message":"queued"}`))
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()
	client := newTestClient(t, tokenSrv.URL, apiSrv.URL, apiSrv.URL)

	resp, err := client.Reports.GeneratePartialReport(context.Background(), "job-9")
	if err != nil || resp.Message != "queued" {
		t.Errorf("resp=%+v err=%v", resp, err)
	}
}
