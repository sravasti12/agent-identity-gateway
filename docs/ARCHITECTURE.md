# Agent Identity Gateway — System Architecture

## 1. Overview

Agent Identity Gateway is designed to secure enterprise AI agents by separating human identity, agent identity, authentication, authorization, and tool execution.

The central security principle is that an AI agent must have an independently verifiable identity and must not automatically inherit unrestricted user permissions.

## 2. System Components

### 2.1 Keycloak — Identity Provider

Keycloak manages human authentication and registered agent clients.

Responsibilities:
- Authenticate human users.
- Manage users, roles, and clients.
- Issue signed access tokens.
- Provide OpenID Connect discovery and signing keys.
- Support configured token exchange capabilities.

### 2.2 Agent Identity

Every registered AI agent receives an independent identity.

Responsibilities:
- Identify individual agents.
- Authenticate agent workloads.
- Associate agents with permitted capabilities.
- Support credential rotation and deprovisioning.

Agent identity remains separate from human user identity.

### 2.3 OAuth Token Exchange

The gateway uses OAuth 2.0 Token Exchange patterns to obtain delegated credentials.

The intended delegated token context includes:
- Authenticated agent identity.
- Human user on whose behalf the agent acts.
- Intended resource server.
- Permitted scopes.
- Token expiration.

The actor relationship will use appropriate token claims, including the standard actor claim where supported by the configured identity provider.

Actual token-exchange support and claim mapping must be tested against the selected Keycloak version.

### 2.4 FastAPI Gateway

The gateway coordinates identity-related operations.

Responsibilities:
- Handle API requests.
- Coordinate token exchange.
- Validate request parameters.
- Communicate with identity and authorization services.
- Record security-relevant events.

### 2.5 MCP Tool Server

The MCP server exposes enterprise capabilities as tools.

Example tools:
- get_team_leave_balance
- get_employee_leave_balance
- get_employee_profile

Before executing a protected tool, the server validates:
- Token signature and trusted issuer.
- Token expiration.
- Intended audience.
- Required scopes.
- Relevant identity claims.

Invalid credentials must be rejected before tool execution.

### 2.6 Open Policy Agent

OPA evaluates authorization policies written in Rego.

Policy inputs can include:
- Human user identity.
- Agent identity.
- User department.
- Agent permissions.
- Requested tool.
- Requested resource.
- Requested action.

OPA returns an authorization decision and explanation.

The application must deny access when authorization cannot be established.

### 2.7 Audit Logging

Security events are recorded with relevant context.

Example fields:
- Timestamp.
- User identity.
- Agent identity.
- Requested tool.
- Resource identifier.
- Authorization decision.
- Policy identifier.
- Request correlation ID.

Sensitive credentials and complete access tokens must never be written to logs.

### 2.8 Z3 Formal Verification

Z3 models authorization rules as logical constraints.

The initial security invariant is:

An agent acting for a user must not obtain permissions beyond the permissions delegated to that agent by the user and the system policy.

The solver will search for counterexamples to this invariant.

Formal verification covers the encoded model and assumptions, not every aspect of the deployed infrastructure.

## 3. Request Flow

1. A human user authenticates through Keycloak.
2. The user requests an operation from an AI agent.
3. The agent authenticates using its own workload identity.
4. The gateway requests a delegated token through the configured token-exchange flow.
5. The issued token is restricted to the intended resource and permissions.
6. The agent sends a request to the MCP tool server.
7. The MCP server validates the token.
8. The MCP server sends trusted authorization context to OPA.
9. OPA evaluates the applicable Rego policy.
10. The tool executes only if authorization succeeds.
11. The decision and execution outcome are recorded in the audit log.

## 4. Trust Boundaries

### Boundary A — Human to Identity Provider

Human authentication is handled by the trusted identity provider.

### Boundary B — Agent to Gateway

Agent authentication must be independent of human authentication.

### Boundary C — Gateway to Token Service

Delegated credentials must be issued only through approved token-exchange rules.

### Boundary D — Agent to MCP Server

The resource server must validate credentials rather than trusting the agent's claims about itself.

### Boundary E — MCP Server to OPA

Authorization inputs must be constructed from validated identity and trusted server-side context.

### Boundary F — Tool Server to Enterprise Resources

Only authorized operations should reach protected resources.

## 5. Threat Scenarios

The implementation will test:

- Token replay.
- Incorrect token audience.
- Expired tokens.
- Excessive agent permissions.
- Unauthorized cross-department access.
- Agent impersonation.
- Compromised agent credentials.
- Deprovisioned agent access.
- Prompt injection attempting unauthorized tool execution.

Prompt injection is treated as an untrusted-input and authorization-bypass threat. The authorization boundary must remain effective even when an agent receives malicious instructions.

## 6. Security Principles

1. Least privilege.
2. Independent workload identity.
3. Short-lived credentials.
4. Audience restriction.
5. Explicit authorization.
6. Fail-closed access decisions.
7. Security auditability.
8. Credential lifecycle governance.
9. Separation of duties.
10. Automated security testing.

## 7. Architecture Status

This document describes the intended architecture.

Actual protocol support, token claims, Keycloak configuration, MCP authentication behavior, OPA policies, and Z3 invariants must be implemented and independently tested before they are considered complete.

## 8. Phase 1 human authentication

The browser starts at `/auth/login`. FastAPI generates a random state, nonce and PKCE verifier. It stores the verifier and nonce in a five-minute server-side transaction and sets an HttpOnly, SameSite=Lax cookie restricted to the callback path. Keycloak receives the state, nonce and S256 challenge and handles user sign-in.

On callback, FastAPI matches the returned state to the browser cookie and atomically consumes the transaction. It sends the code, original verifier, redirect URI and confidential client credentials to Keycloak's token endpoint. It verifies the ID token's signature, issuer, expiry, client audience and nonce. It checks the access-token hash when present and requires both tokens to identify the same subject. A successful login creates a fresh opaque session cookie and redirects to `/auth/me`. The gateway keeps the access token in memory and discards the ID and refresh tokens after the exchange.

The token verifier reads the `kid` header to select an RSA public signing key from the configured realm's JWKS endpoint. It accepts RS256 and verifies the signature, exact issuer, expiration, API audience and Keycloak access-token type. It extracts identity and realm roles from verified claims. Keys are cached for five minutes, with a refresh attempt on an unknown key subject to a ten-second request cooldown. A provider outage produces 503 when the gateway needs keys and has no usable cached key.

FastAPI revalidates the access token on each protected request. Browser sessions are usable for up to 15 minutes and end earlier when the access token expires. Explicit bearer credentials take precedence over the browser cookie. The role dependencies require exact membership in the named realm role and return 403 when the caller lacks it.

Login transactions and sessions are bounded in-memory stores for a single gateway process. Restarting the gateway clears both, and multiple workers require shared storage. Instant logout, revocation and role changes are outside this phase. Use HTTPS for deployment so cookies carry the Secure flag. HTTP is supported for loopback development. Run without Uvicorn access logging and keep callback query strings out of proxy logs because they contain authorization codes. Authentication responses use no-store and no-referrer headers.

[OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) · [Keycloak server administration guide](https://www.keycloak.org/docs/latest/server_admin/)
