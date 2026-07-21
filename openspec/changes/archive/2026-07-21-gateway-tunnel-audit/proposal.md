## Why

The gateway tunnels HTTPS blind (D74, when no interception CA is configured) and
tunnels do-not-intercept hosts (D75) WITHOUT recording anything — an investigator
cannot tell "a flow to evil.com transited uninspected" from "no flow happened."
That is the silence the audit trail exists to prevent (D1/D17 spirit: a coverage
gap must be VISIBLE, not invisible). This records a metadata-only entry for every
tunneled flow.

## What Changes

- `Gateway.RecordTunnel(ctx, host, reason)` — appends a metadata-only `core.Entry`
  to the local forward-secure ledger: `OutcomeKind="tunneled"`, `OutcomeStage`
  carrying the destination host and the reason it was not inspected
  ("interception-disabled" or "do-not-intercept"). NO body, NO URL path, NO
  Decision — just the destination host and reason, inherently boundary-safe
  (D10/D29). An append error is logged; the tunnel still proceeds (a recording
  failure must not break connectivity).
- `Proxy.handleConnect` records exactly one tunnel entry per tunneled CONNECT (the
  branch covering both no-CA and do-not-intercept), before relaying bytes.
- The D74/D75 tests that asserted ZERO ledger entries for tunneled flows now assert
  exactly ONE metadata-only "tunneled" entry naming the host — the visibility
  improvement.

## Capabilities

### Modified Capabilities
- `network-gateway`: uninspected tunneled flows (blind tunnel and do-not-intercept)
  are recorded as a metadata-only ledger entry — destination host + reason — so
  uninspected egress is visible in the audit trail rather than silent.

## Impact

- `internal/gateway` (RecordTunnel + handleConnect call); two existing tunnel tests
  updated to assert the new metadata entry; `docs/decisions.md` D78. No proto,
  pipeline, or transport change.
- Proven: blind tunnel → one "tunneled" entry (reason interception-disabled, host
  named, no Decision, no body); do-not-intercept → "tunneled" entry (reason
  do-not-intercept); an intercepted flow records its Decision, NOT a tunnel entry
  (the two paths are distinct); the tunnel still works if the append fails.
- NOT in scope (stated): projecting tunnel records to the control plane (a
  decision-less telemetry path — a follow-up); per-request tunnel records; recording
  the inner-ClientHello SNI. Respects D10/D29, D30, D1/D17, D74/D75.
