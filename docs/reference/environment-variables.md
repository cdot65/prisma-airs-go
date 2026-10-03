# Environment Variables

Complete reference for all environment variables used by the SDK.

## Scan API

| Variable | Required | Description |
|----------|----------|-------------|
| `PANW_AI_SEC_API_KEY` | Yes* | API key for HMAC-SHA256 signed requests |
| `PANW_AI_SEC_API_TOKEN` | Yes* | Bearer token (alternative to API key) |
| `PANW_AI_SEC_API_ENDPOINT` | No | Override default endpoint (`https://service.api.aisecurity.paloaltonetworks.com`) |

*One of `PANW_AI_SEC_API_KEY` or `PANW_AI_SEC_API_TOKEN` is required.

## Management API

| Variable | Required | Description |
|----------|----------|-------------|
| `PANW_MGMT_CLIENT_ID` | Yes | OAuth2 client ID |
| `PANW_MGMT_CLIENT_SECRET` | Yes | OAuth2 client secret |
| `PANW_MGMT_TSG_ID` | Yes | Tenant service group ID |
| `PANW_MGMT_ENDPOINT` | No | Override management API endpoint |
| `PANW_MGMT_TOKEN_ENDPOINT` | No | Override OAuth2 token endpoint |
| `PANW_MGMT_DLP_ENDPOINT` | No | Unreleased DLP base; default `https://api.dlp.paloaltonetworks.com` |
| `PANW_MGMT_DASHBOARD_ENDPOINT` | No | Unreleased dashboard base; defaults to the resolved management endpoint |

## Model Security API

All variables fall back to their `PANW_MGMT_*` equivalents.

| Variable | Fallback | Description |
|----------|----------|-------------|
| `PANW_MODEL_SEC_CLIENT_ID` | `PANW_MGMT_CLIENT_ID` | OAuth2 client ID |
| `PANW_MODEL_SEC_CLIENT_SECRET` | `PANW_MGMT_CLIENT_SECRET` | OAuth2 client secret |
| `PANW_MODEL_SEC_TSG_ID` | `PANW_MGMT_TSG_ID` | Tenant service group ID |
| `PANW_MODEL_SEC_DATA_ENDPOINT` | — | Data plane endpoint |
| `PANW_MODEL_SEC_MGMT_ENDPOINT` | — | Management plane endpoint |
| `PANW_MODEL_SEC_TOKEN_ENDPOINT` | `PANW_MGMT_TOKEN_ENDPOINT` | Token endpoint |

## Red Team API

All variables fall back to their `PANW_MGMT_*` equivalents.

| Variable | Fallback | Description |
|----------|----------|-------------|
| `PANW_RED_TEAM_CLIENT_ID` | `PANW_MGMT_CLIENT_ID` | OAuth2 client ID |
| `PANW_RED_TEAM_CLIENT_SECRET` | `PANW_MGMT_CLIENT_SECRET` | OAuth2 client secret |
| `PANW_RED_TEAM_TSG_ID` | `PANW_MGMT_TSG_ID` | Tenant service group ID |
| `PANW_RED_TEAM_DATA_ENDPOINT` | — | Data plane endpoint |
| `PANW_RED_TEAM_MGMT_ENDPOINT` | — | Management plane endpoint |
| `PANW_RED_TEAM_TOKEN_ENDPOINT` | `PANW_MGMT_TOKEN_ENDPOINT` | Token endpoint |

## AI Gateway (SCM OAuth)

Credentials and token endpoint fall back to `PANW_MGMT_*` equivalents. API
endpoint overrides use only their service-specific variables.

| Variable | Fallback | Description |
|---|---|---|
| `PANW_AI_GW_CLIENT_ID` | `PANW_MGMT_CLIENT_ID` | SCM OAuth client ID |
| `PANW_AI_GW_CLIENT_SECRET` | `PANW_MGMT_CLIENT_SECRET` | SCM OAuth client secret |
| `PANW_AI_GW_TSG_ID` | `PANW_MGMT_TSG_ID` | Tenant ID; also sent as `x-tsg-id` on API requests |
| `PANW_AI_GW_TOKEN_ENDPOINT` | `PANW_MGMT_TOKEN_ENDPOINT` | OAuth token endpoint |
| `PANW_AI_GW_DATA_ENDPOINT` | — | CRUD data plane; default `https://api.apps.paloaltonetworks.com/ai_gw/v2` |
| `PANW_AI_GW_ADMIN_ENDPOINT` | — | CRUD admin plane; default `https://api.apps.paloaltonetworks.com/ai_gw/admin/v2` |

The following additions are **unreleased** and have no SCM credential fallback
for inference. HTTPS is required except for local test endpoints.

| Variable | Description |
| --- | --- |
| `PANW_IAM_ENDPOINT` | Workspace IAM base; default `https://api.apps.paloaltonetworks.com/iam/v1` |
| `PANW_AI_GW_INFERENCE_ENDPOINT` | Explicit inference base URL; required without an option |
| `PANW_AI_GW_INFERENCE_API_KEY` | Runtime API key; required without an option |

The standalone pricing client requires `ModelPricingOpts.Endpoint` and sends no
credentials. See [parity configuration](../developer/typescript-parity.md).

Red Team also accepts `PANW_RED_TEAM_BROKER_ENDPOINT` for the independent
Network Broker API base.

## Skill scanning (AgentGuard public preview) (SCM OAuth)

Credentials and the token endpoint fall back to `PANW_MGMT_*`. Both API base
URLs are required unless supplied through constructor options; the preview
schemas omit server URLs.

| Variable | Fallback | Description |
| --- | --- | --- |
| `PANW_AGENT_GUARD_CLIENT_ID` | `PANW_MGMT_CLIENT_ID` | SCM OAuth client ID |
| `PANW_AGENT_GUARD_CLIENT_SECRET` | `PANW_MGMT_CLIENT_SECRET` | SCM OAuth client secret |
| `PANW_AGENT_GUARD_TSG_ID` | `PANW_MGMT_TSG_ID` | Tenant service group ID; sent as `x-tsg-id` on API requests |
| `PANW_AGENT_GUARD_TOKEN_ENDPOINT` | `PANW_MGMT_TOKEN_ENDPOINT` | OAuth token endpoint |
| `PANW_AGENT_GUARD_DATA_ENDPOINT` | — | Required data-plane base URL |
| `PANW_AGENT_GUARD_MGMT_ENDPOINT` | — | Required management-plane base URL |

See [AgentGuard](../services/agentguard-api.md) for operations and preview limits.

## Examples

| Variable | Description |
|----------|-------------|
| `PANW_AI_SEC_PROFILE_NAME` | Default profile name for example scripts |
