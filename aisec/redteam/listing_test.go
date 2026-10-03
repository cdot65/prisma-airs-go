package redteam

import (
	"context"
	"encoding/json"
	"github.com/cdot65/prisma-airs-go/aisec"
	"net/http"
	"strconv"
	"testing"
)

func TestScanListAllCurrentTotalAndFilters(t *testing.T) {
	var skips []int
	token, server := newTestServers(t, func(w http.ResponseWriter, r *http.Request) {
		skip, _ := strconv.Atoi(r.URL.Query().Get("skip"))
		skips = append(skips, skip)
		if r.URL.Query().Get("limit") != "2" || r.URL.Query().Get("status") != "COMPLETED" {
			t.Errorf("filters=%s", r.URL)
		}
		data := []map[string]any{{"uuid": "scan1"}, {"uuid": "scan2"}}
		if skip == 2 {
			data = []map[string]any{{"uuid": "scan3"}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "pagination": map[string]int{"total_items": 3}})
	})
	defer token.Close()
	defer server.Close()
	c, err := NewClient(Opts{ClientID: "id", ClientSecret: "secret", TsgID: "123", DataEndpoint: server.URL, MgmtEndpoint: server.URL, TokenEndpoint: token.URL})
	if err != nil {
		t.Fatal(err)
	}
	items, err := c.Scans.ListAll(context.Background(), ScanListOpts{Status: "COMPLETED"}, aisec.CollectOptions{Limit: 2})
	if err != nil || len(items) != 3 || len(skips) != 2 || skips[1] != 2 {
		t.Fatalf("items=%v skips=%v err=%v", items, skips, err)
	}
}
