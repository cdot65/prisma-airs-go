// Package aisec provides a Go SDK for Palo Alto Networks Prisma AI Runtime Security (AIRS).
//
// The SDK covers four service domains:
//
//   - Scan API (API key auth): real-time content scanning
//   - Management API (OAuth2): security profile and topic CRUD
//   - Model Security API (OAuth2): ML model scanning and security rules
//   - Red Team API (OAuth2): automated attack testing and reporting
//
// # Quick Start
//
// Scan API with API key:
//
//	import (
//	    "github.com/cdot65/prisma-airs-go/aisec"
//	    "github.com/cdot65/prisma-airs-go/aisec/scan"
//	)
//
//	cfg := aisec.NewConfig(aisec.WithAPIKey("your-api-key"))
//	scanner := scan.NewScanner(cfg)
//	resp, err := scanner.SyncScan(ctx, profile, content)
//
// Management API with OAuth2:
//
//	import "github.com/cdot65/prisma-airs-go/aisec/management"
//
//	client, err := management.NewClient(management.Opts{
//	    ClientID:     "id",
//	    ClientSecret: "secret",
//	    TsgID:        "tsg-id",
//	})
package aisec
