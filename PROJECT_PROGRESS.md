# Agent Identity Gateway — Project Progress

## Project Goal

Build a security gateway that provides independent identities, delegated access, policy-based authorization, and lifecycle governance for enterprise AI agents.

## Development Rules

1. Complete and verify each phase before proceeding.
2. Record actual implementation, not intended implementation.
3. Record changed files and verification results.
4. Update README.md and this file at every phase completion.
5. Never claim an unverified security capability.
6. Use consolidated Codex prompts to conserve usage.
7. Record architectural decisions and known limitations.

## Phase Tracker

| Phase | Description | Status |
|---|---|---|
| 0 | Foundation and architecture | completed|
| 1 | Human identity and Keycloak | Implemented and unit-tested. Credentialed integration pending. |
| 2 | Non-human agent identity | Python backend implemented and verified |
| 3 | Secure token exchange | Backend implemented and mock-tested. Stage 2A full readback and live exchange pending. |
| 4 | Protected MCP tool server | Not started |
| 5 | OPA authorization | Not started |
| 6 | Audit and lifecycle automation | Not started |
| 7 | Security testing and Z3 | Not started |
| 8 | Finalization and demonstration | Not started |

## Phase 0 — Foundation

### Completed
- [x] Python, Git and Docker CLI installed.
- [x] Python 3.12 selected.
- [x] Local Git repository initialized.
- [x] Docker Linux engine verified.
- [x] Project directory structure created.
- [x] Virtual environment created and activated.
- [x] .gitignore populated.
- [x] README.md populated.

### Pending
- [ ] Architecture documentation populated.
- [ ] Environment and Git configuration verified.
- [ ] Initial Git commit created.
- [ ] GitHub repository connected.

## Implementation Log

Phase 1 implements OIDC code flow with S256 PKCE, an opaque browser session, RS256 JWT validation using Keycloak JWKS, and FastAPI realm-role checks.

Phase 2 adds a client credentials service for `agent-hr-assistant`, a lock-protected per-process token cache, and bearer-only `GET /agent/me`. The gateway verifies both the caller token and the acquired service token against the existing JWKS, issuer and API audience. The diagnostic checks the configured client, service account username, `hr_agent` realm role and matching subject.

Created `app/identity/agent_tokens.py`, `app/identity/agent_routes.py` and `tests/unit/test_agent_authentication.py`. Updated `config/settings.py`, `app/identity/tokens.py`, `app/gateway/main.py`, `README.md` and this tracker. The existing `.env.example` already documented the two agent credential variables. Phase 2 uses the existing dependencies.

## Verification Log

| Check | Result |
|---|---|
| Python 3.12 environment | Activated |
| Docker engine | Running |
| Git repository | Initialized |
| README.md | 1918 bytes |
| Python 3.12.10 unit suite | 22 passed. One Starlette TestClient/httpx deprecation warning. |
| Dependency consistency | pip check reported no broken requirements. |
| Live Keycloak pre-login smoke check | Discovery and RS256 JWKS 200. Gateway login 303. Keycloak login form 200. |
| Credentialed Keycloak integration | Pending browser sign-in, real code exchange, access-token audience and realm-role verification. |
| Prior manual Phase 2 Keycloak 26.8.2 check | Client credentials grant worked. The observed lifetime was 300 seconds. FastAPI validated the token and both human role routes returned 403. |
| Phase 2 live backend smoke check | The Python service acquired and reused the Keycloak token. `/agent/me` returned 200. Both human role routes returned 403. |
| Phase 2 full suite | `.venv\Scripts\python.exe -m pytest -q` reported 46 passed with the existing Starlette TestClient/httpx deprecation warning. |
| Phase 2 dependency and syntax checks | `pip check` reported no broken requirements. `compileall -q app config tests` succeeded. The repository has no configured lint or type check. |

## Phase 3 Stage 1 recovery record

Keycloak 26.8.2 on recovery port 8081, realm `agent-gateway`.

| Scope | Generated scope ID | Mapper providers verified | Realm-optional |
|---|---|---|---|
| `delegation:user` | `ea200624-3bcc-4129-9901-bcd8e43e5298` | `oidc-parameterized-scope-user-property-mapper` | PUT 204, GET 200 confirmed |
| `delegation:client` | `4d50e0f0-557f-4dee-aef9-44bd76e45442` | `oidc-parameterized-scope-client-sub-mapper`, `oidc-parameterized-scope-mapper`, `oidc-parameterized-scope-audience-mapper` | PUT 204, GET 200 confirmed |

The original Windows PowerShell 5.1 `@(Read-Json ...)` check counted one outer element containing the three mappers. The corrected verification assigned `ConvertFrom-Json -InputObject $response.Content` directly, preserving the array count. The existing scope IDs were reused.

- `GET /admin/serverinfo` returned 200 and reported 26.8.2.
- `GET /admin/realms/agent-gateway/client-scopes/{id}` and the corresponding `/protocol-mappers/models` GET returned 200 before and after registration. Both scope representations and all four mapper names, providers, protocols, and configurations matched the baseline.
- `PUT /admin/realms/agent-gateway/default-optional-client-scopes/{id}` returned 204 for both scopes. The collection GET returned 200 and contained both exact name and ID pairs.
- GET requests for each existing application's default and optional client scopes returned 200. The before-and-after assignments matched. Consent and FGAP V2 permissions were untouched. No token exchange was performed.

Final `GET /admin/realms/agent-gateway/client-scopes` returned 200 and listed 18 scopes. OpenID Connect scopes were `acr`, `address`, `basic`, `delegation:client`, `delegation:user`, `email`, `kc-admin-api`, `microprofile-jwt`, `offline_access`, `organization`, `phone`, `profile`, `roles`, `service_account`, and `web-origins`. SAML scopes were `AuthnContextClassRef`, `role_list`, and `saml_organization`.

Final realm-optional scopes were `address`, `delegation:client`, `delegation:user`, `microprofile-jwt`, `offline_access`, `organization`, and `phone`. Stage 1 is verified. Client-level configuration and live exchange acceptance tests remain pending separate approval.

## Phase 3 implementation and verification

The backend implements consented OIDC delegation, a two-minute single-use browser handoff, server-side Keycloak 26.8.2 actor and subject token exchange, and a protected MCP `read_hr_team` policy probe. It validates signed identities, audience, expiration, scope and role limits during tool execution. The delegated token is never returned to the caller. The local policy requires both roles and the explicit `hr_team_read` grant. The feature defaults off.

Added `app/identity/delegation.py`, `app/authorization/delegated.py`, `app/tools/mcp_server.py`, `verification/delegation_invariants.py`, `tests/unit/test_delegation.py` and `tests/unit/test_delegation_invariants.py`. Updated `.env.example`, `config/settings.py`, `app/gateway/main.py`, `app/identity/routes.py`, `app/identity/sessions.py`, `app/identity/tokens.py`, `app/authorization/dependencies.py`, both requirements files and both project documents. The MCP SDK is a runtime dependency. Z3, Ruff and Mypy are development dependencies.

### Stage 2A evidence

Only the sanitized before representation and summarized after-state were available. The reports support the following intentional changes. There is no complete after object to compare recursively, and no field has been classified as harmless normalization.

| Field in available report | Before | After |
|---|---|---|
| `/agent-gateway-api/consentRequired` | `false` | `true` |
| `/agent-gateway-api/optionalScopes` | Five existing optional scopes | Same five plus `delegation:client` |
| `/agent-hr-assistant/standardTokenExchange` | `"false"` | `"true"` |
| `/fgapV2Enabled` | `false` | `true` |

`standardTokenExchange` summarizes `/attributes/standard.token.exchange.enabled` on the actor client. The earlier readback also recorded a Priya-only `Users:delegate` permission linked to a client policy for `agent-hr-assistant`. The exact field behind the unrelated-representation assertion and independent FGAP verification remain blocked on authenticated after-state. The current implementation run made no changes to either Keycloak instance.

### Verification results

| Command | Result |
|---|---|
| `.venv\Scripts\python.exe -m pytest -q` | 89 passed, one pre-existing TestClient/httpx deprecation warning |
| `.venv\Scripts\python.exe -m ruff check --select E4,E7,E9,F app config tests verification` | Passed |
| `.venv\Scripts\python.exe -m ruff check app config tests verification` | Three existing Phase 2 import-order findings in `agent_routes.py`, `agent_tokens.py`, and `test_agent_authentication.py` |
| `.venv\Scripts\python.exe -m mypy --explicit-package-bases app config verification` | Passed across 12 source files |
| `.venv\Scripts\python.exe -m compileall -q app config tests verification` | Passed |
| `.venv\Scripts\python.exe -m pip check` | No broken requirements |
| `git diff --check` and `git check-ignore .env` | Whitespace check passed. Local `.env` is ignored and untracked. |

Live acceptance requires a recovery-only authenticated configuration readback, an approved `hr_team_read` scope configuration if missing, and separate approval for live token exchange. Exercise positive and negative consent, subject and actor binding, audience and scope narrowing, expiration, ordinary login and workload authentication, and MCP authorization. Keep Phase 3 open until these pass. Handoff state is process-local, the MCP tool returns identity metadata, and external HR data and OPA integration are pending.

### Phase 3 audit remediation

- A dedicated human verifier requires the configured human `azp` and a signed, nonempty `sid`. It rejects delegated and service-account claims. The browser callback, delegation subject check, and direct human roles use this boundary. A workload token now gets 401 on human routes even if it has a human role.
- MCP SDK log sources that can emit raw requests or validation details are filtered, including the SDK session code that uses the root logger. The gateway emits credential-free authorization outcomes and lifetime categories. Debug tests cover an invalid MCP request and authorization denial with synthetic credentials.
- Exchange lifetime enforcement remains fail-closed. It distinguishes the subject and actor bounds, expired output, maximum lifetime, and invalid reported lifetime. Additional client-role pairs are rejected. The Z3 model now includes actor signature validity and the static HR role-to-tool mapping, with separate negative cases for each signature, same subject and actor, and missing roles.
- Handoffs and browser sessions remain process-local. Restart discards them. Multi-worker deployments are unsupported, and immediate browser-session revocation is unavailable. External proxy and telemetry capture still need deployment verification.

Changed `app/authorization/dependencies.py`, `app/identity/delegation.py`, `app/identity/routes.py`, `app/identity/tokens.py`, `app/tools/mcp_server.py`, `verification/delegation_invariants.py`, `tests/unit/test_authentication.py`, `tests/unit/test_agent_authentication.py`, `tests/unit/test_delegation.py`, `tests/unit/test_delegation_invariants.py`, `README.md`, and this tracker. There were no dependency or Keycloak changes.

| Post-remediation check | Result |
|---|---|
| `.venv\Scripts\python.exe -m pytest -q` | 114 passed, one existing TestClient/httpx deprecation warning |
| `.venv\Scripts\python.exe -m ruff check` on changed Python files | Passed |
| `.venv\Scripts\python.exe -m mypy --explicit-package-bases app config verification` | Passed across 12 files |
| `.venv\Scripts\python.exe -m compileall -q app config tests verification` | Passed |
| `.venv\Scripts\python.exe -m pip check` and `git diff --check` | Passed |

Phase 3 stays open. Verify the recovery client's actual browser and workload claims, FGAP V2 and `may_act` provenance, `hr_team_read` assignments, provider lifetime behavior with either input expiring first, and positive and negative tool calls. Live exchange needs separate approval.

## Engineering Decision Log

| ID | Decision | Reason |
|---|---|---|
| D001 | Python 3.12 | Dependency compatibility |
| D002 | Docker Compose | Reproducible infrastructure |
| D003 | Separate identity and authorization modules | Clear security boundaries |
| D004 | Phase-based development | Verifiable implementation |
| D005 | Maintain README and progress tracker together | Documentation consistency |

## Blockers

The remaining Phase 1 checks require a local client secret and interactive sign-in as the configured Keycloak users.

## Next Steps

1. Configure the local confidential client secret and confirm the client audience and role mappers.
2. Run the browser verification matrix in README.md and record the actual results before completing Phase 1.
3. For broader workload deployment, plan secret rotation and revocation. Each gateway worker currently maintains its own cache and uses short-lived signed tokens that expire without a revocation lookup.

## Phase 0 Completion Record

Status: Complete

- Repository initialized and connected to GitHub.
- Python 3.12 virtual environment verified.
- Docker engine verified.
- Project directory structure established.
- README and architecture documentation created.
- Git initial commit: b599b90
- Remote: origin/main
- Working tree verified clean.

Application functionality was outside the scope of Phase 0.
