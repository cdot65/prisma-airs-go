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

## Examples

| Variable | Description |
|----------|-------------|
| `PANW_AI_SEC_PROFILE_NAME` | Default profile name for example scripts |
