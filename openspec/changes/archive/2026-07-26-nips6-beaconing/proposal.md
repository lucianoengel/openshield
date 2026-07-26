## Why

Every network detection OpenShield has needs to already know something: an IOC feed lists the domain, a
signature matches the payload, a policy names the destination. An implant on a fresh domain, with an
encrypted payload and trivial volume, passes all of them.

What it cannot easily give up is the **check-in rhythm**. An implant that checks in has to check in, and
the regularity of that is hard to hide without giving up responsiveness. Beaconing detection is the one
network signal that needs no prior knowledge of the destination.

## What Changes

- `internal/analytics/beacon`: a pure detector finding destinations contacted at regular intervals,
  reporting **interval, contact count, regularity and jitter** as evidence.
- Regularity is built on the **median absolute deviation**, not the standard deviation — one long gap (a
  sleeping laptop, a dropped link) inflates a standard deviation enough to hide a beacon, and hiding by
  dropping a single check-in should not be that easy.
- `DetectBeaconing` sweeps the fleet aggregate, reading **only VERIFIED** network-flow events the platform
  already collects — no new capture.
- Contacts are grouped **per subject**, because a rhythm belongs to one endpoint talking to one
  destination.

## Capabilities

### Modified Capabilities
- `network-threat-intel`: adds destination-agnostic beaconing detection over collected flow metadata.

## Impact

- **New**: `internal/analytics/beacon`, `controlplane.DetectBeaconing`. **No migration, no proto change,
  no new dependency.**
- **Honest scope, and it is the important part**: legitimate software beacons constantly — NTP, update
  checks, telemetry, monitoring agents, mail polling. On a real network they outnumber malicious beacons
  by orders of magnitude. So this raises a **medium** alert carrying its evidence, never enforces, and
  takes an **allowlist as configuration** rather than an afterthought: a detector whose output is mostly
  known-good gets muted, and a muted detector is worse than none. It does not detect low-and-slow beacons
  below the contact threshold, does not attribute a beacon to a process, and does not distinguish a
  malicious beacon from a legitimate one — that judgement is the analyst's, which is why the evidence
  travels with the finding.
