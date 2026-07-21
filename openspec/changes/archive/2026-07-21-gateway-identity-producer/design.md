## Context

D85 gave `core.Context` typed `Identity`/`Role`/`DevicePosture` and proved a policy
can decide on them through the unchanged dispatcher. Nothing fills them yet — the
gateway subject is still `sha256(src-IP)` (D77/D84), which is not an identity. The
provisioning CA (D60) already issues agent/operator certs, verified by role at the
D58 gate. This adds a client role and the producer that turns a verified client cert
into a ZT subject.

## Goals / Non-Goals

**Goals:** issue and verify a client cert; resolve a pseudonymous identity + group
into `core.Context`; keep the raw identity out of the pipeline.

**Non-Goals:** OIDC/bearer; the access-proxy mode; the posture producer; the service
catalog; the risk loop.

## Decisions

**A client cert is a DISTINCT role, not a reuse of agent/operator.** `IssueClientCert`
is a separate path; `IssueCert` stays agent/operator-only, unchanged. The client cert
carries `OU=[RoleClient]` (the marker) and `O=[group]` (the authorization class). So
`FromClientCert` can reject an agent or operator cert outright — an agent identity is
not a client identity (the D58 discipline: the role is on the cert, verified, never
inferred). This keeps the three roles cleanly separable and prevents an operator cert
from being replayed as a client login.

**The identity is pseudonymised at the boundary; the group is not.** The CN is the
real user identity (e.g. `alice@corp`) — personally identifying, so it is hashed
one-way into `Subject = "sub_"+hash(CN)` (D23), exactly as the endpoint pseudonymises
its subject and the gateway pseudonymised the src IP. The raw identity never enters
`core.Context`, the Event, or telemetry; the reverse mapping (pseudonym → real
identity) is a deployer concern behind an audited lookup (D23/D47). The GROUP
(`finance`) is an authorization class, not personally identifying, so it is carried as
`Role` in the clear — a policy needs it to authorize.

**Posture is a separate producer, so cert-auth alone does not grant trust.**
`Identity.Context()` sets `Identity`/`Role` but leaves `DevicePosture.HasPosture=false`.
Under D85 a ZT access policy denies when posture is absent — so a client that
authenticates with a valid cert but whose device is unattested is still denied until
the posture producer (a later increment) runs. Authentication ≠ authorization ≠ device
trust; each is a distinct input, resolved by a distinct producer.

## Risks / Trade-offs

- **A producer with no live consumer yet.** The access-proxy mode (§5.1) that calls
  `FromClientCert` per connection is the next increment; this ships the tested producer
  logic first (contract → producer → connector), the project's build order (D69→D73).
- **Client-cert distribution is a real operational cost** (every user needs a cert).
  OIDC (A.2b) is the lower-friction path for human users; client certs suit
  service/workload identities. Both feed the same `Identity` — noted, not blocking.
