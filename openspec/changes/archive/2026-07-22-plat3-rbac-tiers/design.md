## Context

`requireRole(role, h)` does an EXACT match of the verified client cert's OU against a single role
(`agent` or `operator`); `certRole` recognizes only those two. Every operator surface — the read
queue, the `/…/ack` mutations, and the full investigation `/view` — is gated by one `operator` role,
so there is no least-privilege split. ADR-4 adds tiers on this same seam.

## Goals / Non-Goals

**Goals:**
- analyst<responder<admin tiers as cert-OU roles; a higher tier satisfies a lower requirement.
- Distinct gates: read surface = analyst, acks = responder, investigation view = admin.
- Backward compatible: existing `operator` certs keep full (admin) access.

**Non-Goals:**
- Org multi-tenancy (XL, deferred per ADR-4).
- OIDC-group→tier mapping (optional follow-up; the gateway's OIDC verifier already resolves a role, a
  future change can map its group claim to a tier).
- Removing `agent`/`operator` — they stay (agent for `/enroll`, operator as an admin alias).

## Decisions

### D-a · A role rank ladder; higher satisfies lower
`roleRank(role)`: `analyst`=1, `responder`=2, `admin`=3, legacy `operator`=3 (admin alias). `agent`
and any unknown/absent role = 0 (authorized for no operator route — deny by default). `requireTier(min,
h)` serves `h` iff there is a verified cert and `roleRank(certRole) >= roleRank(min)`; 401 without a
cert, 403 when the tier is too low — the 401/403 distinction (D58) is preserved. `requireRole` stays
for `/enroll` (exact `agent`).

*Alternative considered:* a set of allowed roles per route. **Rejected** — a linear rank is exactly
the analyst⊂responder⊂admin containment ADR-4 describes, and reads cleaner than enumerating sets.

### D-b · `certRole` recognizes the tier OUs; legacy operator stays valid
`certRole` returns the first recognized OU among `agent`, `operator`, `analyst`, `responder`, `admin`.
An `operator` cert therefore still resolves and, via `roleRank`, ranks as admin — no existing cert
breaks.

### D-c · Per-route gating, composed
`/enroll` → `requireRole(agent)`. `/view` → `requireTier(admin)` (full investigation evidence is the
most sensitive read, and it records the viewer). The operator read handler is wrapped
`requireTier(analyst)` as the baseline; inside it, `/alerts/ack` and `/incidents/ack` are additionally
wrapped `requireTier(responder)`. Composition works because the outer analyst gate admits
analyst/responder/admin and the inner responder gate then rejects a bare analyst on the ack routes —
so analyst reads, responder acks, admin does everything, and legacy operator (=admin) is unchanged.

### D-d · Provisioning accepts the new roles
`IssueCert` accepts `analyst`/`responder`/`admin` in addition to `agent`/`operator`, so the tool can
mint a tiered operator cert. The OU-as-role marker and the D58 distinctness are unchanged.

## Risks / Trade-offs

- **`/view` moves from operator to admin** → for legacy `operator` certs this is a no-op (operator=
  admin); only a NEW bare analyst/responder is denied `/view`, which is the intended least-privilege.
- **A cert with multiple recognized OUs** → `certRole` takes the first; provisioning issues one role
  per cert, so this is not a real ambiguity, and `roleRank` of the resolved role is deterministic.
- **OIDC-group tiers not yet wired** → the cert path is the authoritative operator gate today; the
  OIDC path is a documented follow-up, not a regression.

## Migration Plan

Backward compatible: deploy the code; existing `agent`/`operator` certs behave exactly as before
(operator = admin). New deployments issue analyst/responder/admin certs for least privilege. Rollback
reverts the code; no data or schema change.

## Open Questions

None for the cert-tier scope. OIDC-group backing is a deliberate follow-up.
