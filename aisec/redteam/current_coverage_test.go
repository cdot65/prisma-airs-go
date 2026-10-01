package redteam

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Every pinned operation must execute through the public HTTP contract harness.
func TestAllCurrentRedTeamOperationsCovered(t *testing.T) {
	cases := append(currentRPCContractCases(t), currentDetailsContractCases(t)...)
	cases = append(cases, extensionContractCases(t)...)
	seen := map[string]bool{}
	for _, tc := range cases {
		method := tc.method
		if tc.template == "/v1/metering/quota" && method == "GET" {
			method = "POST"
		}
		seen[tc.plane+" "+method+" "+extensionTemplate(tc)] = true
	}
	for _, plane := range []string{"data", "mgmt", "broker"} {
		b, err := os.ReadFile("../../specs/contracts/redteam-" + plane + ".json")
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Paths map[string]map[string]json.RawMessage `json:"paths"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		count := 0
		for path, item := range doc.Paths {
			for method := range item {
				switch method {
				case "get", "post", "put", "delete", "patch":
					count++
					if !seen[plane+" "+strings.ToUpper(method)+" "+path] {
						t.Errorf("uncovered %s %s %s", plane, method, path)
					}
				}
			}
		}
		t.Logf("%s: %d operations", plane, count)
	}
}
