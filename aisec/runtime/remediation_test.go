package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/cdot65/prisma-airs-go/aisec"
)

// profilePager serves `total` profiles named p<i> (id id<i>) honoring limit/offset.
func profilePager(total int, pages *int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(pages, 1)
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		if limit == 0 {
			limit = 100
		}
		end := offset + limit
		if end > total {
			end = total
		}
		var items []SecurityProfile
		for i := offset; i < end; i++ {
			items = append(items, SecurityProfile{ProfileID: fmt.Sprintf("id%d", i), ProfileName: fmt.Sprintf("p%d", i), Revision: 1})
		}
		resp := SecurityProfileListResponse{Items: items}
		if end < total {
			resp.NextOffset = end
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// Lookups used to look at the first 1000 profiles only, so item 1500 was
// reported as "not found" even though it existed.
func TestProfiles_GetByID_FindsItemsBeyondFirstPage(t *testing.T) {
	var pages int32
	tokenSrv, apiSrv := newTestMgmtServer(t, profilePager(2500, &pages))
	defer tokenSrv.Close()
	defer apiSrv.Close()
	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)

	p, err := client.Profiles.GetByID(context.Background(), "id1999")
	if err != nil {
		t.Fatal(err)
	}
	if p.ProfileName != "p1999" {
		t.Errorf("profile = %+v", p)
	}
	if got := atomic.LoadInt32(&pages); got != 2 {
		t.Errorf("fetched %d pages, want 2 (should stop once found)", got)
	}
}

func TestProfiles_GetByName_ScansAllPagesForHighestRevision(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		var resp SecurityProfileListResponse
		if offset == 0 {
			resp = SecurityProfileListResponse{
				Items:      []SecurityProfile{{ProfileID: "a", ProfileName: "dup", Revision: 1}},
				NextOffset: 1,
			}
		} else {
			resp = SecurityProfileListResponse{Items: []SecurityProfile{{ProfileID: "b", ProfileName: "dup", Revision: 7}}}
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()
	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)

	p, err := client.Profiles.GetByName(context.Background(), "dup")
	if err != nil {
		t.Fatal(err)
	}
	if p.ProfileID != "b" || p.Revision != 7 {
		t.Errorf("got %+v, want revision 7 from page 2", p)
	}
}

// A server that never ends its pagination must not hang the lookup.
func TestPaginate_StopsAtPageCap(t *testing.T) {
	calls := 0
	err := paginate(func(o ListOpts) ([]int, int, error) {
		calls++
		return []int{1}, o.Offset + 1, nil // always claims there is more
	}, func(int) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	if calls != maxLookupPages {
		t.Errorf("calls = %d, want cap %d", calls, maxLookupPages)
	}
}

func TestPaginate_FullPagesWithoutNextOffsetAdvanceByCount(t *testing.T) {
	var offsets []int
	err := paginate(func(o ListOpts) ([]int, int, error) {
		offsets = append(offsets, o.Offset)
		if o.Offset >= 2*lookupPageSize {
			return make([]int, 3), 0, nil // short final page
		}
		return make([]int, lookupPageSize), 0, nil
	}, func(int) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	want := []int{0, lookupPageSize, 2 * lookupPageSize}
	if fmt.Sprint(offsets) != fmt.Sprint(want) {
		t.Errorf("offsets = %v, want %v", offsets, want)
	}
}

func TestPaginate_PropagatesFetchError(t *testing.T) {
	boom := errors.New("boom")
	err := paginate(func(ListOpts) ([]int, int, error) { return nil, 0, boom }, func(int) bool { return false })
	if !errors.Is(err, boom) {
		t.Errorf("err = %v", err)
	}
}

// Client-side "not found" must be indistinguishable from a server 404 for
// callers that use errors.Is, while keeping the original message.
func TestLookups_NotFoundMatchesErrNotFound(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ai_profiles": []any{}, "dlp_profiles": []any{}})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()
	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	ctx := context.Background()

	_, err1 := client.Profiles.GetByID(ctx, "nope")
	_, err2 := client.Profiles.GetByName(ctx, "nope")
	_, err3 := client.DlpProfiles.Get(ctx, "nope")
	for i, err := range []error{err1, err2, err3} {
		if !aisec.IsNotFound(err) {
			t.Errorf("lookup %d: IsNotFound(%v) = false", i, err)
		}
	}
	if got := err1.Error(); got != "AISEC_CLIENT_SIDE_ERROR:profile not found: nope" {
		t.Errorf("message changed: %q", got)
	}
}

func TestServer404MatchesErrNotFound(t *testing.T) {
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Profile does not exist"}`)) // no "404"/"not found" wording
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()
	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)

	_, err := client.Profiles.Delete(context.Background(), "x")
	if !aisec.IsNotFound(err) {
		t.Fatalf("IsNotFound(%v) = false", err)
	}
}

func TestPathSegmentsAreEscaped(t *testing.T) {
	var path string
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.EscapedPath()
		_, _ = w.Write([]byte(`{}`))
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()
	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)

	_, _ = client.ApiKeys.Delete(context.Background(), "my key/../x", "me")
	if want := "/v1/mgmt/apikey/delete/my%20key%2F..%2Fx"; path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	_, _ = client.Topics.ForceDelete(context.Background(), "a/b", "me")
	if want := "/v1/mgmt/topic/force/a%2Fb"; path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
}

func TestNewClient_EndpointFromEnvironment(t *testing.T) {
	var hit int32
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hit, 1)
		_, _ = w.Write([]byte(`{"ai_profiles":[]}`))
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()
	t.Setenv("PANW_MGMT_ENDPOINT", apiSrv.URL+"/")

	client, err := NewClient(Opts{ClientID: "a", ClientSecret: "b", TsgID: "1", TokenEndpoint: tokenSrv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Profiles.List(context.Background(), ListOpts{}); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&hit) != 1 {
		t.Error("PANW_MGMT_ENDPOINT was ignored")
	}
}

func TestNewClient_ExplicitEndpointBeatsEnvironment(t *testing.T) {
	var hit int32
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hit, 1)
		_, _ = w.Write([]byte(`{"ai_profiles":[]}`))
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()
	t.Setenv("PANW_MGMT_ENDPOINT", "http://127.0.0.1:1") // would fail if used

	client, err := NewClient(Opts{ClientID: "a", ClientSecret: "b", TsgID: "1", APIEndpoint: apiSrv.URL, TokenEndpoint: tokenSrv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Profiles.List(context.Background(), ListOpts{}); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&hit) != 1 {
		t.Error("explicit APIEndpoint should win over the environment")
	}
}

func TestNewClient_InjectedHTTPClientCarriesTraffic(t *testing.T) {
	var transportHits int32
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"ai_profiles":[]}`)) })
	defer tokenSrv.Close()
	defer apiSrv.Close()

	client, err := NewClient(Opts{
		ClientID: "a", ClientSecret: "b", TsgID: "1", APIEndpoint: apiSrv.URL, TokenEndpoint: tokenSrv.URL,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			atomic.AddInt32(&transportHits, 1)
			return http.DefaultTransport.RoundTrip(r)
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Profiles.List(context.Background(), ListOpts{}); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&transportHits); got != 2 {
		t.Errorf("injected transport saw %d requests, want 2 (token + API)", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// End-to-end: a persistent 403 through a real sub-client terminates quickly.
func TestClient_Persistent403Terminates(t *testing.T) {
	var hits int32
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"no entitlement"}`))
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()
	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)

	_, err := client.Profiles.List(context.Background(), ListOpts{})
	if !errors.Is(err, aisec.ErrForbidden) {
		t.Errorf("err = %v, want ErrForbidden", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("API hits = %d, want 2", got)
	}
}

// The DLP list endpoint takes no pagination parameters, so Get must not re-request.
func TestDlpProfiles_GetUsesOneRequest(t *testing.T) {
	var calls int32
	tokenSrv, apiSrv := newTestMgmtServer(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		items := make([]DlpProfile, 1200)
		for i := range items {
			items[i] = DlpProfile{ID: fmt.Sprintf("d%d", i)}
		}
		_ = json.NewEncoder(w).Encode(DlpProfileListResponse{Items: items})
	})
	defer tokenSrv.Close()
	defer apiSrv.Close()
	client := newTestClient(t, tokenSrv.URL, apiSrv.URL)

	if _, err := client.DlpProfiles.Get(context.Background(), "d1100"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DlpProfiles.Get(context.Background(), "missing"); !aisec.IsNotFound(err) {
		t.Errorf("err = %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("list calls = %d, want 2 (one per Get)", got)
	}
}
