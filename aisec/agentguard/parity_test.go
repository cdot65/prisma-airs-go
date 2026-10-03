package agentguard

import "testing"

func TestTypeScriptBackgroundRefreshPreservesFalse(t *testing.T) {
	flag := false
	q := scanListQuery(ScanListOpts{IsBackgroundRefresh: &flag})
	if q.Get("isBackgroundRefresh") != "false" {
		t.Fatal(q)
	}
	if _, ok := scanListQuery(ScanListOpts{})["isBackgroundRefresh"]; ok {
		t.Fatal("omitted refresh flag sent")
	}
}
