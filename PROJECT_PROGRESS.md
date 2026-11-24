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
| 4 | Centralized authorization with OPA and Rego | Implemented and tested with real OPA and mocked Keycloak. Live acceptance pending. |
| 5 | Audit logging and non-human identity lifecycle | Implemented and locally verified. Operational acceptance pending. |
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

## Phase 4 OPA authorization

The protected MCP path now uses an explicit Rego decision after JWT and delegation verification. It sends verified subject and actor fields plus fixed tool and resource context using a separate HTTPX client. OPA independently checks both roles, actor client, subject separation, audience, expiry, and scope for `read_hr_team` on `hr_team/demo-team`. A valid boolean allow is required. Unavailable or malformed responses and decisions that arrive after credential expiry deny execution. OPA receives no credentials or MCP arguments.

Added `compose.opa.yml`, `policies/authorization.rego`, `policies/api_authorization.rego`, `policies/authorization_test.rego`, and `tests/unit/test_opa.py`. Updated `.env.example`, `config/settings.py`, `app/authorization/delegated.py`, `app/gateway/main.py`, `app/tools/mcp_server.py`, `tests/unit/test_delegation.py`, `tests/unit/test_delegation_invariants.py`, `verification/delegation_invariants.py`, `README.md`, and this tracker. Existing HTTPX was sufficient. The existing Keycloak Compose file was preserved.

| Check | Actual result |
|---|---|
| `pytest -q` with `OPA_TEST_BINARY` set to the checksum-verified OPA 1.12.2 CLI | 143 passed, one existing TestClient/httpx warning. Includes actual OPA allow and deny over HTTP and management endpoint denial, with mocked Keycloak. |
| `opa check --strict policies/` and `opa test policies/ -v` | Strict compilation passed, 15 of 15 policy cases passed. |
| Ruff on changed Python files | Passed. Default full-tree Ruff reported two pre-existing import-order findings in `agent_routes.py` and `agent_tokens.py`. |
| Mypy, compile checks, `pip check`, and `git diff --check` | Passed. |
| `docker compose -f compose.opa.yml config --quiet` | Validated with local Docker configuration access warnings. |
| OPA-only Compose smoke test | Pinned container started, health returned 200, empty input returned deny, and management returned 401. The disposable container and network were removed. |

The symbolic model now requires the exact tool and resource, a valid decision response, and explicit policy allow. These are abstract inputs. Real Rego execution is covered separately and live Keycloak behavior remains outside both checks.

Phase 4 acceptance has evidence for policy rules, fail-closed handling, MCP integration with real OPA, and the OPA-only Compose service. Deployment acceptance still requires an approved recovery-only sign-in, exchange, and MCP allow/deny run. The tool still covers one logical resource. Loopback OPA protects the management API with a path policy and relies on the host trust boundary for local decision-query access.

## Phase 5 registry, lifecycle and audit

SQLite persists the agent registry, review decisions, credential version metadata, and a chained audit. Onboarding defaults to empty grants and `PENDING`. A verified human with `gateway_admin` can activate, suspend, reactivate, deprovision, request credential rotation, and approve or reject changes to local permissions. Deprovisioning is terminal, clears assigned grants, revokes credential metadata locally, and leaves external revocation pending. The provider interface covers rotation, disablement, and permission observations. This phase used mocks and leaves the live adapter unconfigured.

Registry generation checks block revoked handoffs and a second check protects the decision-to-tool boundary. Rego requires an active, approved agent and preserves earlier identity and scope rules. The Z3 abstraction checks active status, generation matching, permission subsets and the human administrator boundary. It does not prove live issuer behavior or persistence integrity.

New files are `app/audit/store.py`, `app/audit/verify.py`, `app/identity/lifecycle.py`, `app/identity/lifecycle_models.py`, `app/identity/lifecycle_routes.py`, and `tests/unit/test_lifecycle.py`. Updated the gateway, existing identity and authorization routes, delegation session and tool integration, OPA policies, Z3 model, related tests, settings, environment example, ignore rules, and these project documents. No dependency or Keycloak configuration changes were made.

| Check | Actual result |
|---|---|
| `.venv\Scripts\python.exe -m pytest -q` with `OPA_TEST_BINARY` set to OPA 1.12.2 | 172 passed, one existing TestClient/httpx deprecation warning. Real OPA ran with mocked Keycloak. |
| `opa check --strict policies/` and `opa test policies/ -v` | Passed, including 22 of 22 Rego cases. |
| Ruff on changed Python files | Passed. Full-tree Ruff found the existing import-order issue in `app/identity/agent_tokens.py`. |
| Mypy across app, config and verification | Passed across 17 source files. |
| Compile checks, `pip check`, and `git diff --check` | Passed. |

Local acceptance covers registry durability, verified human administration, lifecycle revocation before MCP execution, mock provider workflows, review decisions, audit pagination, and detection of modified, deleted or reordered records. The offline verifier opens an existing database read-only. Operational acceptance remains open for controlled administrator-role configuration, deployment storage and audit retention, and any separately approved live provider operations and recovery acceptance. No production rotation or revocation was attempted.

## GitHub Actions CI

Added `.github/workflows/ci.yml` with one Ubuntu job for pushes to `main`, pull requests targeting `main`, and manual dispatch. The job uses read-only repository permissions, a 15-minute timeout, and Python 3.12. It installs `requirements-dev.txt` and caches pip downloads using both requirements files.

CI verifies the published SHA-256 and exact version of the official OPA 1.12.2 Linux release binary, makes it available through `OPA_TEST_BINARY`, and runs the complete test suite. Keycloak is mocked. SQLite tests use memory or fresh temporary files. The only application source change organizes imports in `app/identity/agent_tokens.py`, clearing the existing Ruff finding without changing behavior.

| Local check | Actual result |
|---|---|
| `actionlint` 1.7.12 on the workflow | Passed |
| `opa check --strict policies/` and `opa test policies/ -v` | Strict validation passed, 22 of 22 Rego cases passed using OPA 1.12.2 |
| `python -m pytest -q` with `OPA_TEST_BINARY` set | 172 passed, zero skipped, one existing TestClient/httpx deprecation warning |
| Ruff with the CI selectors and with default selectors | Both passed |
| Mypy, Python compilation, `pip check`, and `git diff --check` | Passed |

Checks ran in the existing local Windows Python 3.12 environment. The GitHub-hosted Ubuntu job and its pip cache remain unverified until the workflow is pushed and runs on GitHub. CI does not change the pending live acceptance criteria for earlier phases.

## Engineering Decision Log

### Phase 6 defensive regression coverage

Added three cases in `tests/unit/test_delegation.py` for human bearer denial at `/agent/me` and MCP, confirmed mock rotation, and failed mock rotation. They reuse the existing role, handoff, token, and lifecycle fixtures and the mock credential provider. Rejected MCP calls stop before exchange and tool execution, create denial records, and keep synthetic bearer, handoff, and provider diagnostics out of the checked outputs. Pending rotation preserves existing credential validity. Applying either rotation outcome invalidates old handoffs. Only provider confirmation changes the bearer cutoff. Existing audit and Z3 tests passed. The unchanged Z3 model covers abstract authorization decisions.

Latest local verification recorded 187 pytest cases with zero skips and one existing Starlette TestClient warning, 22 Rego tests, and passing strict OPA, CI Ruff, Mypy, compilation, dependency, and whitespace checks. CI discovers the tests through the existing workflow. This increment has not run on GitHub Actions. Phase 6 remains open for independent browser session and multi-agent isolation acceptance. The runtime uses bearer session handles and a single configured MCP workload client. Verification here uses mocks and does not establish provider-side revocation.

Added four cases in `tests/unit/test_delegation.py` for missing and unknown browser sessions, exact handoff expiry, and suspension after OPA allow. The existing cases already check agent tokens on human routes, agent tokens with admin roles, wrong agent client and subject, handoff replay, delegation denial for inactive agents, and rejection of old handoffs after a lifecycle generation changes. Existing mock-provider lifecycle tests cover pending, confirmed, and failed rotation. MCP end-to-end rotation and isolation across multiple configured agent clients remain open. Local verification passed 184 pytest cases with one existing Starlette TestClient warning, 22 Rego cases, strict OPA checks, CI Ruff rules, Mypy, compilation, dependency checks, and `git diff --check`. GitHub Actions has yet to run this increment.

Added MCP runtime regression cases for OPA connection failure and read timeout in `tests/unit/test_delegation.py`. They verify tool non-execution, correlated denial records, and redaction across the response, captured logs, and those records. CI discovers both cases through the existing pytest job. No dependency or runtime changes were needed.

Added six cases in `tests/unit/test_lifecycle.py` for indexed decision drift, broken hash links, changed head sequence, changed head hash, missing head, and duplicate records. The verifier rejected each inconsistent fixture and reported the expected sequence. Existing pytest discovery includes the cases in CI. The existing Z3 model already covers actor validity, lifecycle status, tool eligibility, delegation binding, and explicit OPA allow, so it was kept as-is. The audit chain still depends on a separately trusted checkpoint for detecting a rewrite of both records and the stored head.

Local verification with OPA 1.12.2 passed 180 pytest cases with one existing Starlette TestClient deprecation warning and 22 Rego tests. Strict Rego validation, CI-selected Ruff rules, Mypy, compilation, `pip check`, and `git diff --check` passed. Phase 6 remains open. GitHub Actions has not run this change.

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
