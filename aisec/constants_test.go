package aisec

import "testing"

func TestConstants_Endpoints(t *testing.T) {
	if DefaultEndpoint != "https://service.api.aisecurity.paloaltonetworks.com" {
		t.Errorf("DefaultEndpoint = %q", DefaultEndpoint)
	}
	if DefaultMgmtEndpoint != "https://api.sase.paloaltonetworks.com/aisec" {
		t.Errorf("DefaultMgmtEndpoint = %q", DefaultMgmtEndpoint)
	}
	if DefaultTokenEndpoint != "https://auth.apps.paloaltonetworks.com/oauth2/access_token" {
		t.Errorf("DefaultTokenEndpoint = %q", DefaultTokenEndpoint)
	}
	if DefaultModelSecDataEndpoint != "https://api.sase.paloaltonetworks.com/aims/data" {
		t.Errorf("DefaultModelSecDataEndpoint = %q", DefaultModelSecDataEndpoint)
	}
	if DefaultModelSecMgmtEndpoint != "https://api.sase.paloaltonetworks.com/aims/mgmt" {
		t.Errorf("DefaultModelSecMgmtEndpoint = %q", DefaultModelSecMgmtEndpoint)
	}
	if DefaultRedTeamDataEndpoint != "https://api.sase.paloaltonetworks.com/ai-red-teaming/data-plane" {
		t.Errorf("DefaultRedTeamDataEndpoint = %q", DefaultRedTeamDataEndpoint)
	}
	if DefaultRedTeamMgmtEndpoint != "https://api.sase.paloaltonetworks.com/ai-red-teaming/mgmt-plane" {
		t.Errorf("DefaultRedTeamMgmtEndpoint = %q", DefaultRedTeamMgmtEndpoint)
	}
}

func TestConstants_RegionalEndpoints(t *testing.T) {
	if AIRSEndpoints.US != "https://service.api.aisecurity.paloaltonetworks.com" {
		t.Errorf("US = %q", AIRSEndpoints.US)
	}
	if AIRSEndpoints.EU != "https://service-de.api.aisecurity.paloaltonetworks.com" {
		t.Errorf("EU = %q", AIRSEndpoints.EU)
	}
	if AIRSEndpoints.India != "https://service-in.api.aisecurity.paloaltonetworks.com" {
		t.Errorf("India = %q", AIRSEndpoints.India)
	}
	if AIRSEndpoints.Singapore != "https://service-sg.api.aisecurity.paloaltonetworks.com" {
		t.Errorf("Singapore = %q", AIRSEndpoints.Singapore)
	}
}

func TestConstants_ContentLimits(t *testing.T) {
	if MaxContentPromptLength != 2*1024*1024 {
		t.Errorf("MaxContentPromptLength = %d", MaxContentPromptLength)
	}
	if MaxContentResponseLength != 2*1024*1024 {
		t.Errorf("MaxContentResponseLength = %d", MaxContentResponseLength)
	}
	if MaxContentContextLength != 100*1024*1024 {
		t.Errorf("MaxContentContextLength = %d", MaxContentContextLength)
	}
}

func TestConstants_BatchLimits(t *testing.T) {
	if MaxNumberOfScanIDs != 5 {
		t.Errorf("MaxNumberOfScanIDs = %d", MaxNumberOfScanIDs)
	}
	if MaxNumberOfReportIDs != 5 {
		t.Errorf("MaxNumberOfReportIDs = %d", MaxNumberOfReportIDs)
	}
	if MaxNumberOfBatchScanObjects != 5 {
		t.Errorf("MaxNumberOfBatchScanObjects = %d", MaxNumberOfBatchScanObjects)
	}
}

func TestConstants_Retry(t *testing.T) {
	if MaxNumberOfRetries != 5 {
		t.Errorf("MaxNumberOfRetries = %d", MaxNumberOfRetries)
	}
	expected := []int{500, 502, 503, 504}
	if len(HTTPForceRetryStatusCodes) != len(expected) {
		t.Fatalf("HTTPForceRetryStatusCodes len = %d", len(HTTPForceRetryStatusCodes))
	}
	for i, code := range expected {
		if HTTPForceRetryStatusCodes[i] != code {
			t.Errorf("HTTPForceRetryStatusCodes[%d] = %d, want %d", i, HTTPForceRetryStatusCodes[i], code)
		}
	}
}

func TestConstants_Headers(t *testing.T) {
	if HeaderAPIKey != "x-pan-token" {
		t.Errorf("HeaderAPIKey = %q", HeaderAPIKey)
	}
	if HeaderAuthToken != "Authorization" {
		t.Errorf("HeaderAuthToken = %q", HeaderAuthToken)
	}
	if PayloadHash != "x-payload-hash" {
		t.Errorf("PayloadHash = %q", PayloadHash)
	}
}

func TestConstants_ScanPaths(t *testing.T) {
	if SyncScanPath != "/v1/scan/sync/request" {
		t.Errorf("SyncScanPath = %q", SyncScanPath)
	}
	if AsyncScanPath != "/v1/scan/async/request" {
		t.Errorf("AsyncScanPath = %q", AsyncScanPath)
	}
	if ScanResultsPath != "/v1/scan/results" {
		t.Errorf("ScanResultsPath = %q", ScanResultsPath)
	}
	if ScanReportsPath != "/v1/scan/reports" {
		t.Errorf("ScanReportsPath = %q", ScanReportsPath)
	}
}

func TestConstants_Version(t *testing.T) {
	if Version == "" {
		t.Error("Version is empty")
	}
	if UserAgent == "" {
		t.Error("UserAgent is empty")
	}
}
