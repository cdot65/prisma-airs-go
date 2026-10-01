// Package gateway provides Prisma AIRS AI Gateway management CRUD operations
// for existing workspaces, with SCM OAuth and explicit data/admin routing.
//
// It exposes configs, workspace/org guardrails, providers, integrations, MCP
// integrations/servers, API keys, usage/rate policies, secret references and
// deployments. Lifecycle helpers are explicit: no polling, reconciliation,
// automatic secret rotation, signed-URL following or workspace provisioning.
// Creation receipts and read models have separate types in the schema package.
package gateway
