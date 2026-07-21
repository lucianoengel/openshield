## Why

Audit finding #4 (part 1), verified: `SignedPublisher` holds `seq atomic.Uint64`
IN MEMORY with no persistence, so every agent restart (crash, redeploy, the
`systemctl restart` D45 prescribes for every upgrade) resets it to 0. The control
plane's `VerifySigned` treats `seq <= last_sequence` as `ErrReplay` and REJECTS
it — so the next several legitimate messages after a restart are
indistinguishable-from-tampering rejections until the counter organically climbs
back past the server's recorded value. Routine restarts silently drop telemetry
and look like an attack.

## What Changes

- A file-backed, RESERVATION-based sequence store: it persists a high-water mark
  in blocks (reserve N ahead, ~one atomic write per N publishes, temp+rename like
  the D46 signer state). On startup the publisher LOADS the last reserved
  high-water and resumes from there — never reusing a sequence.
- Resuming AHEAD is safe by construction: `VerifySigned` treats `seq > last+1` as
  a GAP (accepted and counted, D50); only `seq <= last` is a replay. A persisted
  monotonic counter is therefore always forward, never a replay.
- Wired into `cmd/openshield-fleet-agent` via `OPENSHIELD_SEQ_FILE`. The
  in-memory publisher is kept for callers that do not need persistence
  (backward-compatible constructor).
- Corrected honesty: `internal/transport/nats/nats.go`'s comment claims it runs
  "over NATS JetStream" but the code uses only core NATS (fire-and-forget). It is
  reworded to say plainly it is core NATS (at-most-once; durability across a
  control-plane outage is the offline queue's job, wired separately), so the doc
  matches the code.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `event-transport`: the signed publisher's sequence survives a restart via a
  persisted reservation, so a restarted agent's telemetry is forward-monotonic,
  never a false replay; the transport doc no longer overclaims JetStream.
- `control-plane`: a restarted agent's telemetry is accepted (a gap at worst),
  not rejected as a replay.

## Impact

- New: a seq store (file-backed, reservation) in `internal/transport/nats`; a
  persistence-aware constructor; `OPENSHIELD_SEQ_FILE` in the fleet agent; tests;
  the corrected transport doc; docs (D66).
- Behaviour: a restart no longer manufactures replay-rejections. A skipped block
  (reserved-but-unused seqs) becomes a GAP, which D50 records and accepts — the
  honest cost of crash-safety without a per-message fsync.
- Respects D46 (signer write-resume discipline) and D50 (gap/replay semantics).
