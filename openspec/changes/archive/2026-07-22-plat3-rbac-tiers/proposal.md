## Why

Operator access is all-or-nothing. There are two cert-OU roles — `agent` and `operator` — and every
operator surface (the read queue, the acknowledge/mutate actions, the full investigation view) sits
behind a single `operator` role. A SOC needs least-privilege tiers: a read-only analyst who can triage
the queue but not mutate or see full investigations, a responder who can acknowledge, and an admin.
ADR-4: add per-route RBAC tiers on the existing `requireRole` seam now (org multi-tenancy deferred),
unblocking the PLAT-1 UI, which needs its authz model fixed before design.

## What Changes

- Three operator tiers as cert-OU roles with a hierarchy: `analyst` (1) < `responder` (2) < `admin`
  (3). A higher tier satisfies a lower one.
- The legacy `operator` role maps to `admin`, so **existing operator certificates keep full access**
  (backward compatible).
- `requireTier(minRole, h)` gates a route on `rank(certRole) >= rank(minRole)`; `requireRole` stays for
  the exact-match `agent` case.
- Per-route gating: the read surface (`/alerts`, `/search`, `/events`, `/overdue`, `/incidents`,
  `/subject`) requires **analyst**; the mutating acks (`/alerts/ack`, `/incidents/ack`) require
  **responder**; the full investigation `/view` requires **admin**.
- Provisioning issues `analyst`/`responder`/`admin` certs (in addition to `agent`/`operator`).
- OIDC-group-backed tiers (mapping a verified OIDC group to a tier at the gateway) are **noted as an
  optional follow-up** — this change does the cert-OU tiers, the core ADR-4 decision.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `operator-identity`: a verified certificate is authorized per route by a tiered role
  (analyst<responder<admin, legacy operator=admin); a higher tier satisfies a lower requirement, and
  reads/acks/investigation are gated at distinct tiers.
- `provisioning`: the tool issues the new analyst/responder/admin role certificates.

## Impact

- **Code:** `internal/controlplane/views.go` (role constants, `certRole`, `requireTier` + `roleRank`),
  `internal/controlplane/enroll_http.go` + `operator_read.go` (per-route tier gating),
  `internal/provision/provision.go` (accept the new roles), and tests.
- **No proto/core change.** Backward compatible: existing `operator` certs act as `admin`; existing
  route behavior is preserved for them.
- **Org multi-tenancy deferred** (XL, ADR-4). OIDC-group tier backing deferred (optional follow-up).
