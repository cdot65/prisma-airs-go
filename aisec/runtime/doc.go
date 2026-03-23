// Package runtime provides both data-plane and management-plane clients for
// the AI Runtime Security service.
//
// Data plane (API Key auth):
//
//	scanner := runtime.NewScanner(cfg)   // SyncScan, AsyncScan, QueryByScanIDs, QueryByReportIDs
//
// Management plane (OAuth2 auth):
//
//	client := runtime.NewClient(opts)    // Profiles, Topics, ApiKeys, CustomerApps, DlpProfiles, DeploymentProfiles, ScanLogs, OAuth
package runtime
