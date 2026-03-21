# Release Notes

## v0.1.0 — Initial Release

- Project scaffolding and Go module setup
- GitHub Actions CI/CD (lint, test matrix, docs deploy, release validation)
- MkDocs Material documentation site
- Core package: constants, configuration, errors, utils
- HTTP client with exponential backoff retry and full jitter
- **Scan API**: Scanner with SyncScan, AsyncScan, QueryByScanIDs, QueryByReportIDs
- **OAuth2 Client**: token caching, proactive refresh, 401/403 auto-retry, concurrent deduplication
- **Management API**: 8 sub-clients (profiles, topics, API keys, customer apps, DLP profiles, deployment profiles, scan logs, OAuth management)
- **Model Security API**: 3 sub-clients (scans, security groups, security rules) + PyPI auth
- **Red Team API**: 5 sub-clients (scans, reports, custom attack reports, targets, custom attacks) + 7 convenience methods
- Full feature parity with TypeScript SDK v0.6.7
