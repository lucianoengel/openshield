## Why

The notification idempotency key is non-functional. `emit` stamped `newNotifyID()` — a fresh
`crypto/rand` value per call — and nothing checked it server-side. The exact scenario the key exists
for (an agent re-sends telemetry → the server re-detects → re-emits) minted a NEW id each time, so a
receiver could not dedupe and the double-page persisted. The async hand-off (SIEM-8/-11) is real; the
idempotency it advertised was not.

## What Changes

- The notification id is derived **deterministically** from the alert's identity — `kind | subject |
  agentID | window-bucket(At)` — so a logical alert re-emitted within the window carries the SAME id,
  and a genuinely new occurrence in a later window carries a new one.
- The control plane keeps a **bounded, FIFO-evicting seen-set** and suppresses a duplicate id in
  `emit`, so a re-detected alert is delivered exactly once. A suppression is counted
  (`NotifyDeduped`, exposed as `openshield_notify_deduped_total`) — never silent.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `control-plane`: the notification idempotency key is deterministic (content + time-window), and the
  control plane suppresses a re-emitted duplicate server-side so a re-detected alert pages once.

## Impact

- **Code:** `internal/controlplane/notify.go` (`notifyID`, `dedupeSet`, `emit`),
  `internal/controlplane/controlplane.go` (`NotifyDeduped` counter + `notifyDedupe` field),
  `internal/controlplane/metrics.go` (expose the counter).
- **No proto/core change**; delivery semantics (best-effort, off-ingest, retry/permanence) unchanged.
- A receiver that already deduped on the id now actually benefits; the change only removes duplicate
  pages, never suppresses a distinct alert.
