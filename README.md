# Agent Identity Gateway

A security platform for managing authentication, authorization, and lifecycle governance of enterprise AI agents.

## Problem Statement

AI agents increasingly interact with enterprise systems, databases, and business tools. Shared API keys and long-lived credentials introduce risks such as excessive permissions, impersonation, unauthorized access, and poor auditability.

Agent Identity Gateway addresses these challenges through independent agent identities, delegated authorization, short-lived credentials, and centralized policy enforcement.

## Core Objectives

- Independent identities for AI agents.
- Human authentication using Keycloak.
- OAuth 2.0 and OpenID Connect integration.
- Delegated token exchange.
- Short-lived, audience-restricted credentials.
- Protected MCP tool servers.
- Least-privilege authorization using OPA.
- Structured security audit logging.
- Non-human identity lifecycle automation.
- Formal authorization verification using Z3.
- Adversarial security testing.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python 3.12 | Backend |
| FastAPI | API gateway |
| Keycloak | Identity provider |
| OAuth 2.0 / OIDC | Authentication |
| MCP | Tool integration |
| OPA / Rego | Authorization |
| Z3 | Formal verification |
| Docker Compose | Infrastructure |
| pytest | Testing |
| GitHub Actions | CI/CD |

## Architecture

See [Architecture Documentation](docs/ARCHITECTURE.md).

## Development Progress

See [PROJECT_PROGRESS.md](PROJECT_PROGRESS.md).

## Security Scope

Initially developed as a local security demonstration environment. Production deployment requires additional security hardening and independent review.

## Development Status

Under development. Features will be marked complete only after implementation and verification.


## Phase 1 local setup

Run from the repository root in PowerShell. For a fresh checkout, copy `.env.example` to `.env`. If `.env` already exists, add the missing gateway settings and keep the existing bootstrap values. Set a local Keycloak admin password for a fresh instance and fill in the confidential client secret from the Keycloak admin console. Keep `.env` private.

| Variable | Local value or purpose |
|---|---|
| `KEYCLOAK_ISSUER` | `http://localhost:8080/realms/agent-gateway` |
| `KEYCLOAK_CLIENT_ID` | `agent-gateway-api` |
| `KEYCLOAK_CLIENT_SECRET` | Secret from the client Credentials tab |
| `KEYCLOAK_REDIRECT_URI` | `http://localhost:8000/auth/callback` |
| `KEYCLOAK_API_AUDIENCE` | `agent-gateway-api`, also mapped into access tokens |
| `KC_BOOTSTRAP_ADMIN_USERNAME`, `KC_BOOTSTRAP_ADMIN_PASSWORD` | Keycloak bootstrap admin credentials for Docker Compose |

```powershell
py -3.12 -m venv .venv  # If the environment does not exist yet
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
docker compose up -d keycloak
.venv\Scripts\python.exe -m uvicorn app.gateway.main:app --host 127.0.0.1 --port 8000 --no-access-log
```

Open the Keycloak admin console at `http://localhost:8080/admin/` and verify the following settings.

1. In realm `agent-gateway`, configure the OpenID Connect client `agent-gateway-api` with client authentication and Standard Flow enabled. Keep Direct Access Grants, Authorization and Standard Token Exchange disabled. Set the exact valid redirect URI above and set the PKCE challenge method to `S256`. Use RS256 signing and standard JWT access tokens.
2. In the client's dedicated client scope, add an **Audience** protocol mapper with **Included Client Audience** set to `agent-gateway-api` and **Add to access token** enabled. Leave **Add to ID token** off. Keep the realm role mapper that populates `realm_access.roles` and the profile claim mapping for `preferred_username`. If client scope mappings restrict roles, include both application realm roles.
3. Assign the realm role `hr_manager` to `priya` and `employee` to `rahul` and `ananya`. Set local sign-in credentials in Keycloak as needed.

[Keycloak server administration guide](https://www.keycloak.org/docs/latest/server_admin/)

### Endpoints

| Endpoint | Behavior |
|---|---|
| `GET /auth/login` | Starts browser login and redirects to Keycloak |
| `GET /auth/callback` | Validates the login transaction, exchanges the code, then redirects to `/auth/me` |
| `GET /auth/me` | Returns verified subject, username and realm roles |
| `GET /hr/team` | Requires the `hr_manager` realm role |
| `GET /employee/me` | Requires the `employee` realm role |

The two role-protected routes return the verified caller identity for this phase. Protected routes accept the browser session or an independently obtained API bearer token. Missing or invalid authentication returns 401. A valid caller with insufficient roles receives 403.

### Verification

```powershell
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m pip check
```

Python 3.12.10 verification recorded 22 passing tests and one Starlette TestClient/httpx deprecation warning. Dependency checking reported no broken requirements. The automated suite uses generated signing keys and mocked Keycloak endpoints. A live pre-login smoke check returned 200 for realm discovery and JWKS, 303 for the gateway login redirect, and 200 for the Keycloak login form.

To finish Phase 1 verification, first confirm the protected routes return 401 in a fresh browser profile. Then open `http://localhost:8000/auth/login` and sign in separately as each user, using a fresh private session for each account to avoid reusing Keycloak SSO. Use `localhost` consistently for the gateway URLs. Confirm the callback redirects to `/auth/me`, the user and roles match, and the browser receives an opaque session cookie without a token or client secret in the response.

| User | `/auth/me` | `/hr/team` | `/employee/me` |
|---|---|---|---|
| priya | 200 | 200 | 403 |
| rahul | 200 | 403 | 200 |
| ananya | 200 | 403 | 200 |

Credentialed browser checks are pending. See the architecture document for session, token and deployment constraints.

## Phase 2 workload authentication

The HR assistant uses the Keycloak client credentials grant. Configure these settings in the ignored local `.env`.

| Variable | Local value or purpose |
|---|---|
| `KEYCLOAK_ISSUER` | `http://localhost:8080/realms/agent-gateway` |
| `KEYCLOAK_HR_AGENT_CLIENT_ID` | `agent-hr-assistant` |
| `KEYCLOAK_HR_AGENT_CLIENT_SECRET` | Confidential client secret from Keycloak |
| `KEYCLOAK_API_AUDIENCE` | `agent-gateway-api` |

Set both HR agent credentials to enable workload authentication. Omit both to run only the human login flow. In Keycloak, the agent client needs client authentication and service accounts enabled, the `hr_agent` realm role assigned and in scope, and the API audience mapped into its access token. Keep the `preferred_username` claim for the service account. [Keycloak service account setup](https://www.keycloak.org/docs/26.8.0/server_admin/#_service_accounts)

`GET /agent/me` requires a valid bearer token for the configured HR service account. The gateway verifies the signature, issuer, expiry and API audience using the same JWKS verifier as the human routes. It then checks the signed client ID (`azp`), service account username and realm role. The gateway acquires or reuses its own verified service token and confirms both tokens identify the same subject. The response contains the subject, username and realm roles. Missing or invalid bearer credentials return 401. A verified token for a different identity returns 403. Provider unavailability returns 503, and a rejected workload exchange or invalid provider token response returns 502.

The gateway keeps one verified workload token per process. The cache uses the earlier of `expires_in` from the start of the exchange and the signed JWT expiration, with a one-hour upper bound. Requests refresh under a lock when 10% of the usable lifetime remains, up to 30 seconds early. If refresh fails, the error is returned. The next request can retry. Restarts clear the cache, each worker manages its own cache, and the gateway does not perform immediate revocation checks or automatic secret rotation.

The live Keycloak 26.8.2 setup had already been verified manually with a 300-second token lifetime. The backend smoke check then acquired and reused a real service token, returned 200 from `/agent/me`, and returned 403 from both human role routes. The full unit suite reported 46 passed with one existing TestClient/httpx deprecation warning. Run `.venv\Scripts\python.exe -m pytest -q` to repeat the mocked tests. See [the progress tracker](PROJECT_PROGRESS.md) for the implementation record.
