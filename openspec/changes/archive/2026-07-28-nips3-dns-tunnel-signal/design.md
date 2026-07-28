# Design

## Where the score goes, and why not `behavioral`

The brief suggested reusing `input.event.behavioral.score`, which the default policy already
alerts on at `>= 0.5`. That would have been one line and it is the wrong choice, for two reasons
that are about meaning rather than tidiness.

**Its siblings do not apply.** `behavioral` is `{score, lolbin, suspicious_lineage,
encoded_command}` — a process verdict. A DNS query has no LOLBin and no parent process, so
reusing the key means emitting `lolbin: false` on a DNS event: *false*, not *absent*. A policy
author reasonably reads that as "this was checked and it wasn't a LOLBin", when nothing was
checked at all. Absence is information; a fabricated `false` destroys it.

**It would silently change what existing policies mean.** `default.rego` documents that "file and
network events have no `input.event.behavioral`, so this is undefined for them and never fires".
Any operator policy written against `behavioral.score` today means *process behaviour*. Making
DNS queries populate it would start firing those rules on DNS traffic without anyone editing a
policy — a change in behaviour delivered by a change in vocabulary, which is the hardest kind to
notice.

So DNS gets its own key. The precedent is already in the mapping layer: `cloud` (CASB) is a
derived, content-free typed input under its own name, present only when a catalogued host
matched, absent otherwise. `dns` is built the same way and is absent for every event that is not
a DNS query.

```
input.event.dns.tunnel_score   # float in [0,1]
```

Only the score. The intermediate signals (longest-label length, entropy) are diagnostics rather
than policy inputs, and exposing them would invite policies that reimplement the heuristic badly
in Rego.

## Where the score is computed

In `internal/policy/mapping.go`, next to `casb.Classify` and `behavioral.Analyze` — the layer
whose job is deriving typed policy inputs from an event. Not in `dns.ToEvent`.

That is deliberate. `ToEvent` runs in the connector, and putting a score there would mean the
score travels on the wire in the event, which is a proto change, and would also mean the
CONNECTOR decides how suspicious something is. The engine's mapping layer is where every other
derivation lives, it is pure and content-free, and it keeps the detector one refactor away from
being replaced without touching the event contract.

The name is METADATA, not content — the same status as an exec path or an SNI host — so this
needs no sandboxed worker. D29 is about parsing attacker-controlled bytes; scoring the length and
entropy of a name the parser already produced is arithmetic.

## Alert, never block

The default rule ALERTS. A tunnel score is a heuristic over one query with no session context,
and a rule that blocked would deny name resolution — a failure that presents to users as "the
internet is down" and to an operator as nothing in particular. D1 is observe-only by default and
the NIPS-2 threat-match rule already made exactly this call for exactly this reason.

An operator raises it to BLOCK deliberately. That is what the closed action set is for (T1).

## The threshold, and the D303 trap

`OPENSHIELD_DNS_TUNNEL_THRESHOLD`, validated as `KindUnitInterval` — the same kind added for the
peer-UEBA threshold after that setting accepted `1.2`, ran the detector, scored every subject and
could never alert, while logging that it was enabled.

The trap here is sharper, because `TunnelScore` multiplies two clamped signals: reaching 1.0
requires a 63-character label at maximum entropy, so thresholds near 1.0 are *technically* in
range and *practically* unreachable. Validation refuses out-of-range values; it cannot refuse an
unwise one. So the startup line reports the threshold and the engine states when the detector is
enabled, and the requirement below is written in terms of the SETTING being refused when
out of range, not in terms of guessing operator intent.

Default: **0.5**, matching the behavioral rule's threshold, so the two suspicion signals in the
default policy agree on what "suspicious enough to alert" means.

## What the test has to prove, and how it can lie

The scenario drives a real UDP query at a live listener and asserts on the AUDIT ROW, not on a
log line — a startup line has been wrong four times in this project.

**Both halves are required.** An ordinary name must produce NO alert and a tunnelling name must
produce one. "The tunnelling name alerted" is satisfied by a detector that alerts on everything,
which is worse than one that alerts on nothing: it is an alert channel that has to be ignored.

**The ledger must be content-free.** The whole point of a DNS tunnel is that the exfiltrated data
IS the name, so an audit trail that records the query name records the exfiltrated payload. A
detector whose evidence is the disclosure is the failure D10/D29 exist to prevent, and it is more
acute here than anywhere else in the product.

## Deferred, honestly

- **DoH/DoT.** A `:53` query connector cannot see them, and they are the real evasion. Anything
  that matters gets tunnelled over HTTPS eventually; this raises the cost of the lazy path only.
- **NXDOMAIN rate and query volume.** This signal is per-query and stateless. Volumetric
  detection is a different mechanism with different state, not a bigger threshold.
- **Response-side analysis.** TXT-record payloads are the other half of a tunnel and are not seen
  by a query connector.
