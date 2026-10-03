// Package agentguard provides the Prisma AIRS AgentGuard public preview API.
// Scans and Statistics use the data plane; Instances, Rules, RuleInstances, and
// SkillOverrides use the management plane. Both share SCM OAuth credentials.
// Explicit endpoints are required because the supplied preview has no servers.
// UploadURL returns a signed URL; callers upload their archive separately before
// invoking UploadComplete. The SDK does not follow signed URLs automatically.
package agentguard
