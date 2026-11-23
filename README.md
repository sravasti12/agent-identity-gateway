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

## Phase 3 Stage 1 recovery verification

On the isolated Keycloak 26.8.2 recovery instance at `http://localhost:8081`, both built-in delegation scopes passed readback in the `agent-gateway` realm.

| Scope | Generated scope ID | Verified protocol mapper providers |
|---|---|---|
| `delegation:user` | `ea200624-3bcc-4129-9901-bcd8e43e5298` | `oidc-parameterized-scope-user-property-mapper` |
| `delegation:client` | `4d50e0f0-557f-4dee-aef9-44bd76e45442` | `oidc-parameterized-scope-client-sub-mapper`, `oidc-parameterized-scope-mapper`, `oidc-parameterized-scope-audience-mapper` |

Windows PowerShell 5.1 wrapped the JSON array emitted by the original helper in a second array, so the check counted one outer element. Assigning `ConvertFrom-Json -InputObject $response.Content` directly before counting verified one user mapper and three client mappers. Both scope representations and all four mapper configurations matched the 26.8.2 baseline before and after registration. [Keycloak 26.8.2 built-in scope definitions](https://github.com/keycloak/keycloak/blob/26.8.2/services/src/main/java/org/keycloak/protocol/oidc/OIDCLoginProtocolFactory.java#L627-L667)

Authenticated PowerShell Admin REST calls under `/admin/realms/agent-gateway` returned 204 for both `PUT /default-optional-client-scopes/{id}` operations. `GET /default-optional-client-scopes`, `GET /client-scopes/{id}`, `GET /client-scopes/{id}/protocol-mappers/models`, and the final `GET /client-scopes` returned 200 and passed verification. Before-and-after reads confirmed both existing clients kept their default and optional scope assignments. Consent settings and FGAP V2 permissions were untouched.

Stage 1 is complete on the recovery instance. See the [progress tracker](PROJECT_PROGRESS.md) for the final inventory and the Stage 2A verification status.

## Phase 3 delegation and protected MCP tool

Delegation is off by default. The opt-in switch is `DELEGATION_ENABLED`. The existing `KEYCLOAK_ISSUER`, `KEYCLOAK_API_AUDIENCE`, and human and HR agent client credentials are used. There are no new secrets. For approved recovery integration, use `http://localhost:8081/realms/agent-gateway` as the issuer and keep the credentials in the ignored local `.env`.

1. The human starts at `GET /auth/login?delegate=true`. The existing OIDC PKCE flow asks for `hr_team_read` and `delegation:client:<agent-client-id>`. The callback checks signed subject claims, the actor client and service-account subject in `may_act`, and the granted scopes. After consent, a same-origin browser `POST /auth/delegation` returns an opaque handoff valid for at most two minutes.
2. The workload calls `read_hr_team` over stateless MCP Streamable HTTP at `/mcp`. It supplies the handoff as the tool argument and its own service-account access token as the HTTP bearer. The gateway verifies that bearer and checks the signed subject-to-actor relationship and the human's HR role before atomically consuming the handoff.
3. The gateway authenticates to Keycloak as the agent client and sends both signed tokens to the 26.8.2 delegation exchange. The request specifies the API audience and only `hr_team_read`. The gateway verifies the returned JWT, checks that `sub` and `act` match the validated subject and actor, and requires the single API audience. It rejects extra privileges, missing scopes, a refresh token, and expiry beyond either input token or five minutes.
4. The in-process policy requires `hr_manager`, `hr_agent`, and `hr_team_read` before permitting the tool. The tool returns verified identity metadata for this demonstration. No HR data source is connected. Subject and delegated JWTs stay server-side. The gateway does not retain exchanged JWTs after the operation. [Keycloak 26.8.2 delegation](https://github.com/keycloak/keycloak/blob/26.8.2/docs/guides/securing-apps/token-exchange.adoc) · [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)

Browser sessions and pending handoffs are process-local. Handoffs are single-use in one process, including when the provider fails after consumption. Restarting the process discards pending handoffs and sessions. Multi-worker deployments are unsupported because sign-in callbacks and tool calls can reach a worker without the corresponding state. A new sign-in invalidates the previous browser session's handoff for subsequent lookups. Immediate browser-session revocation is unavailable, and a request already in flight can race with session replacement. The agent access token is a bearer credential and needs secure transport and storage. The MCP endpoint checks Host and Origin against the configured browser callback origin. The current policy is local Python. OPA and production tool integrations remain future work.

### Phase 3 security remediation

- Direct human routes and browser sign-in require the configured human client in the signed `azp` claim and a nonempty signed `sid`. They reject `act` and the Keycloak service-account markers `client_id`, `clientHost`, and `clientAddress`. Role checks remain in effect. Keep service accounts disabled on the human client and preserve the workload mappers. The gateway relies on the issuer to keep the token classes distinct. [Keycloak 26.8.2 token construction](https://github.com/keycloak/keycloak/blob/26.8.2/services/src/main/java/org/keycloak/protocol/oidc/TokenManager.java#L1020-L1042) · [Keycloak service-account markers](https://www.keycloak.org/docs/26.1.5/upgrading/)
- The MCP gateway filters SDK log sources that can include decoded requests or malformed input. Its own security events use fixed outcomes and reason codes without request arguments or authorization headers. Keep credential and request-body capture disabled in reverse proxies and observability tools.
- The exchange rejects added realm roles and client-role pairs, extra tool scopes, and invalid lifetime claims. Sanitized diagnostics distinguish expired input, expired output, output extending beyond either input, the five-minute cap, and invalid reported lifetime. No lifetime rule was relaxed.
- The Z3 model includes three signature-validity inputs and models the actor's single tool permission as a consequence of `hr_agent`. It requires `hr_manager` on both the original and delegated subject. The model abstracts verified claims and permission sets. It does not prove issuer consent, claim provenance, runtime enforcement, logging, or distributed replay.

### Phase 3 acceptance

The post-remediation automated suite reported 114 passed and one pre-existing Starlette TestClient/httpx deprecation warning. It adds human token-class rejection, exact lifetime boundaries, actor signature and subject binding, client-role narrowing, and credential-free MCP debug logging checks. Ruff on changed Python files, Mypy, compilation, dependency checks, and `git diff --check` passed.

Phase 3 remains open. The complete Stage 2A after-state was unavailable. Recovery-only acceptance still requires authenticated client and FGAP readback, confirmation of `may_act` mapper and policy provenance, and confirmation that both clients can request `hr_team_read`. Live tests require separate approval. Verify normal browser JWT claims, ordinary workload authentication, consented access and denial without consent or permission, both token identities, exact API audience, scope and role narrowing, exchanged expiry when either input expires first, and successful and denied MCP calls.
