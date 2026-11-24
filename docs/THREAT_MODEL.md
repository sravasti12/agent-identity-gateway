# Agent Identity Gateway threat model

## Assets and trust boundaries

- The browser holds an opaque session cookie. The gateway holds human tokens, login state, and one-use delegation handoffs in process memory.
- Keycloak controls signing keys, roles, service accounts, audience and delegation mappers, consent, and exchange permissions. The gateway verifies signed claims and binds the exchange result to the human subject and configured workload actor.
- The gateway sends verified identity, registry grants, and the fixed HR tool and resource to OPA. OPA is trusted to return an authentic policy decision. MCP returns identity metadata for the demo resource after a final lifecycle and expiry check.
- SQLite stores lifecycle records, permissions, and audit evidence. The host filesystem, database writer, audit head, and administrator identities are trusted.

Threat actors include an unauthenticated caller, a compromised browser session or workload, a human without administrative or HR authority, and a privileged operator or compromised host. Browser and MCP ingress, the OIDC callback and token endpoints, OPA transport, administrative routes, and SQLite files are the main attack surfaces.

## Controls and evidence

| Scenario | Control and evidence |
|---|---|
| Token confusion or invalid claims | Authentication and delegation tests exercise issuer, audience, signatures, token expiry, authorized party, human versus workload roles, and subject/actor binding. Admin routes require a verified human administrator. |
| Reuse of delegated access | Tests exercise one-use consumption, exact handoff expiry, output scope and lifetime constraints, lifecycle generation changes, and confirmed versus failed mock rotation. |
| Excessive privilege or dependency failure | Real OPA tests exercise allow and deny for the fixed demo tool and resource. Mock transport tests cover an unavailable, slow, or malformed policy service. Registry tests exercise stale and inactive agents and grant checks. |
| Audit corruption or storage failure | SQLite tests detect record changes, deletions, bad ordering, inconsistent metadata, and missing head. The invocation failure test confirms that a failed audit write rolls back access metadata and prevents tool execution. Other tests check correlation and exclusion of synthetic credentials. |

Z3 checks satisfiability of a finite authorization model. Its predicates assume successful verification of identity and policy responses. It models roles, actors, subject, audience, grant inclusion, tool and resource, expiry, lifecycle state and explicit policy allow. It does not establish that JWT parsing, Rego, SQLite transactions, or the live configuration implement those predicates in every case. Runtime and Rego tests provide separate evidence.

## Residual risks and deployment assumptions

- **Medium · Audit anchoring.** Someone able to replace both the records and head can recompute the chain. Restrict database access and protect backups. Independent integrity evidence requires a checkpoint held outside that write boundary.
- **Medium · Bearer possession.** A valid copied browser cookie carries the original session authority until expiry or invalidation. Session and handoff state are process-local. Use TLS, restrict access to process memory and logs, and deploy a single gateway worker with the current stores.
- **Medium · Trusted policy and identity configuration.** An attacker with control of OPA policy or the issuer configuration can change delegated decisions. Restrict their administration and network exposure. Use loopback for local OPA or authenticated, protected production transport. Live Keycloak mapper, policy, role, lifetime, and exchange behavior remain acceptance items.
- **Low · Availability and external effects.** SQLite write failures block the demonstrated tool and can leave earlier events, including policy allow, without a terminal execution event. Monitor write failures and disk availability. The demo returns metadata. Future external side effects require their own authorization and execution consistency design.
