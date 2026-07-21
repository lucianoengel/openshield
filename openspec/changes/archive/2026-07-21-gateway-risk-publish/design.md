## Context

D89 gave the gateway a RiskStore + continuous verification, but it is inert — no
publisher fills the store. Peer-UEBA (D54) computes per-subject risk server-side. This
connects them: the server publishes risk, the gateway subscribes.

## Goals / Non-Goals

**Goals:** the server publishes per-subject risk; the gateway populates its RiskStore
from it; continuous verification fires on real risk.

**Non-Goals:** per-message risk signing; subject-space unification; posture; OIDC.

## Decisions

**Server publishes DATA on a subject; the gateway reads it — the T2 model (D14/D54).**
`Server.PublishRisk` publishes a `RiskUpdate` on `natsx.SubjectRisk`; the gateway
subscribes and `RiskStore.Set`s it. The server never sends a "deny X" command — only a
risk value the gateway's LOCAL policy interprets (D89). A compromised server can publish
a wrong value (a lie the bounded policy still evaluates), but cannot command the gate.

**Transport security authenticates the publisher for now; per-message signing is a
follow-up.** A spoofed high risk could deny a legitimate user (a DoS), so the channel's
integrity matters. mTLS on NATS (D55) authenticates the publisher at the connection
level — the same channel the fleet telemetry uses. Per-message signing (as telemetry
does, D50) is a stated hardening follow-up, not required for the mechanism.

**Best-effort publish, latest-wins store.** `observePeer` publishes risk after recording
the peer alert, best-effort (a publish failure is logged, never breaks ingest). The
RiskStore holds the latest received value per subject (D89) — never a stale cache with no
refresh.

## Risks / Trade-offs

- **Subject-space unification** (noted in D89): peer-UEBA scores the endpoint subject;
  the gateway's is the client-identity pseudonym. They must resolve to the same subject
  for risk to gate the right person — a deployment identity-mapping concern.
- **No per-message signing yet** (above) — a hardening follow-up.
