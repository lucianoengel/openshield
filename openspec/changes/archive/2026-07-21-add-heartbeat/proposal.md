# Add the heartbeat / dead-man's-switch (T-018)

## Why

The README's honest claim — detection, not prevention (D16) — is currently unbacked. Anyone with
root can stop the agent, mask its unit, or pull the machine off the network, and nothing notices.
"Tamper-detection" is only true if the ABSENCE of an agent is itself detectable. That is what a
heartbeat and a dead-man's-switch provide: the control plane knows when an agent last checked in,
and raises an alert when a host that should be reporting goes silent. Without this, replacing
"tamper-proof" with "tamper-evident" is a wording change with no mechanism behind it.

## What changes

**The agent emits a periodic heartbeat, and the control plane tracks "last seen" per host.** A
heartbeat is a small signed-in-spirit telemetry message (agent id, sequence, timestamp) on its
own subject; the control plane records the latest per agent. This makes "when did we last hear
from host X" a queryable fact.

**A dead-man's-switch: silence past a threshold is an alert.** The control plane's detector, given
the last-seen times and a threshold, reports which agents are OVERDUE — silent longer than they
should be. Silence is the signal: a healthy agent heartbeats on an interval, so absence beyond a
few intervals means stopped, masked, disconnected, or dead. The detector is pure logic over
timestamps, tested directly.

**Stopping the agent is itself an audited event.** The systemd unit gets an `ExecStopPost` hook
that records the stop — so a graceful `systemctl stop openshield-agent` leaves a trail, and the
distinction between "stopped cleanly (recorded)" and "vanished (silence, no record)" is
observable. A clean stop is benign and accounted for; a silence with no stop record is the
suspicious case the dead-man's-switch exists to surface.

## What this does NOT claim or cover

- **It does not prevent tampering, and it is defeatable** (D16). Root can stop the agent AND
  suppress the heartbeat AND block the control plane. The honest guarantee is narrow: a host that
  goes silent is *noticed*, turning "the agent quietly died" into "the agent is overdue — someone
  should look". A determined adversary who also compromises the control plane defeats it; that is
  the same limit every host agent has.
- **Silence is ambiguous by nature.** A laptop legitimately sleeps, travels, and goes offline. The
  dead-man's-switch reports *overdue*, not *tampered* — it is a signal for a human to investigate,
  not an accusation. The offline queue (T-024) means a briefly-offline agent's telemetry still
  arrives on reconnect; sustained silence is what matters.
- **The heartbeat is not the evidentiary record.** Last-seen lives in the fleet aggregate (D41),
  which is not tamper-evident. A compromised control plane could forge a heartbeat to hide a dead
  agent. The narrow value is detecting the common, non-adversarial-control-plane case; stated, not
  overclaimed.
- **No automated response.** Overdue raises a signal; it does not quarantine, page, or act. Alert
  routing is a deployment concern.

## Decisions

Depends on **D16** (tamper-detection via heartbeat / dead-man's-switch / "agent last seen"),
**D41/T-023** (the control plane that receives and tracks it), **D24** (the transport), and
**D17** (a stop is a loud, recorded event).

Establishes a new decision: **the dead-man's-switch reports a silent host as OVERDUE, not
tampered — a signal for a human, not an accusation — and a clean agent stop is itself recorded so
silence-with-no-stop is the case that stands out; the mechanism is defeatable by root and by a
compromised control plane, and claims only to notice the common case.**
