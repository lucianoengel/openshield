## Context

`Proxy.handleConnect` (D74/D75) either intercepts a host (terminates TLS, runs the
pipeline, records a Decision) or tunnels it blind (relays ciphertext, records
nothing). The intercepted path is auditable; the tunneled path is silent. The
ledger is the tamper-evident record of what the gateway saw, and a flow it saw but
did not inspect is not the same as a flow that never happened.

## Goals / Non-Goals

**Goals:**
- Record a metadata-only ledger entry for every tunneled flow, so uninspected
  egress is visible.
- Distinguish it from an inspected flow's Decision entry.
- Never let recording break the tunnel.

**Non-Goals:**
- Projecting tunnel records to the control plane (decision-less telemetry — a
  follow-up); per-request records; inner-ClientHello SNI capture.

## Decisions

**A tunnel is an OUTCOME, not a Decision.** No classification happened, so there is
no verdict to record — representing it as an ALLOW Decision would falsely claim the
flow was inspected and allowed. The ledger's Outcome fields exist for exactly this:
a terminal event that produced no Decision (timeouts, failures). A tunnel entry sets
`OutcomeKind="tunneled"` and `OutcomeStage` = "<host> (<reason>)", with a nil
Decision. An investigator reading the chain sees "tunneled to host X, reason Y" and
knows it was NOT inspected — the honest representation.

**Metadata only, inherently.** A CONNECT carries a host:port authority and no path
and no body. So a tunnel entry naturally holds only the destination host and the
reason — no content, no URL path, no user body (D10/D29). The host is destination
metadata, the same field telemetry retains (D77). Nothing sensitive to redact.

**Best-effort recording, never breaks the tunnel.** The flow is happening
regardless; a ledger append failure must not sever connectivity or the audit gap we
are closing becomes an availability bug. `RecordTunnel` logs an append error and
returns; `handleConnect` proceeds to relay. The forward-secure ledger is still the
record when it works; when it fails, the failure is logged (not silent).

**One entry per CONNECT.** A CONNECT establishes one TLS tunnel that may carry many
requests (keep-alive); the gateway sees the connection, not the inner requests
(that is what interception is for). So one entry per tunneled CONNECT is the correct
granularity — it records the fact of an uninspected connection to a destination.

## Risks / Trade-offs

- **Volume.** High-HTTPS environments produce many CONNECTs, hence many tunnel
  entries. Per-connection (not per-request) keeps it bounded; a busy gateway still
  writes a lot. Acceptable for an audit trail whose job is completeness; a sampling
  or aggregation mode is a possible future knob, noted.
- **The reason is coarse.** "interception-disabled" vs "do-not-intercept" is enough
  to explain WHY a flow was not inspected; finer taxonomy (which list rule matched)
  is a possible refinement, not needed now.
