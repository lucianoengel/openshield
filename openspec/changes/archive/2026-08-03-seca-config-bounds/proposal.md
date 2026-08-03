# SEC-A · No configuration field declared a bound

## Why

`grep "Validate:" internal/config/*.go` outside tests returned **zero**. `Field.Validate` existed, was
invoked by both the boot-time validator and the write path — and no field had ever declared one. The
entire per-field bound was the `Kind`'s parseability.

At single-admin tier, over `POST /config`, with no four-eyes, no TTL and no sequence, every one of these
is a valid value:

| setting | consequence |
|---|---|
| `OPENSHIELD_CORRELATE_INTERVAL=0s` | **no incidents are raised at all** |
| `OPENSHIELD_OVERDUE_THRESHOLD=8760h` | a killed agent is never reported missing |
| `OPENSHIELD_BEACON_ALLOWLIST=<c2 domain>` | the command-and-control destination is never reported |
| `OPENSHIELD_FLEET_RETENTION=1h` + `RETENTION_INTERVAL=1m` | evidence purged through a **sanctioned delete path the hash chain does not cover** |

`KindUnitInterval` is the one existing range check and it is a *parseability* bound, not a
*reachability* one — its own doc says validation "cannot refuse an unwise one", and a threshold of
`0.999999` is in range and unreachable.

## What changes

1. **Real operational ranges** as `Validate` on the fields gating a detector or a retention window, each
   refusal saying what breaks rather than which limit was exceeded. An operator told a rule routes around
   it; one told the consequence does not.

2. **A `Sensitivity` direction on every such field**, so "this change moves toward less detection" is
   computable. This is the half a bound cannot cover: most of these changes use values that are
   perfectly reasonable in isolation, and no range refuses a 24-hour retention.

3. **A disabling value orders as the weakest setting**, not by magnitude. `CORRELATE_INTERVAL=0s`
   disables scheduled correlation; ordered numerically it is the smallest interval and therefore the most
   aggressive, so the one change that raises no incidents at all would have scored as a hardening.

4. **A weakening change raises an alert and is recorded on the revision diff.** A log line will not do —
   the threat is an operator credential used to blind the product before the thing it would have caught,
   and nobody reads a configuration history at the moment that matters.

5. **A guard test names every classified field**, so a new detector's threshold cannot be added
   unclassified. `NotSensitive` is the zero value, so silence reads as "irrelevant to detection".

## Impact

- **No behaviour change for a deployment inside the ranges.** Values outside them are now refused at the
  moment they are set rather than accepted and silently disabling.
- **One migration**, an additive column on the change diff.
- **Deliberately not in scope:** four-eyes on configuration writes (that is `SEC-D`'s primitive and a
  separate decision about which keys warrant it); a TTL on a dynamic change; bounds on fields that do not
  gate detection or retention, where a wrong value is an outage the operator sees immediately rather
  than a silence they do not.
