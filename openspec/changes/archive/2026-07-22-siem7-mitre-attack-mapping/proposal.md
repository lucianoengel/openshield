## Why

OpenShield's detections say *what* was found — a credential, a known-bad domain, a LOLBin, data heading
to cloud sync — but not *what the adversary is doing* in a shared vocabulary. MITRE ATT&CK is that
vocabulary: every SOC speaks in techniques (T1567 exfiltration, T1552 unsecured credentials, T1218
system-binary-proxy). Tagging detections with ATT&CK techniques makes alerts legible to analysts and
tools, and — critically — gives the XDR correlation lane its *sequence vocabulary* (an identity-anomaly →
exec → C2 sequence is expressed in technique ids). This is SIEM-7, and it is reused, not re-ticketed, by
XDR-4.

## What Changes

- An `internal/attack` mapping: from the detection signals OpenShield already computes — detector types
  (credentials, EDM/IDM, passport…), threat-intel categories (IOC domain/IP, URI signature), the exfil
  channel (cloud-sync, removable), and the behavioral flags (LOLBin, encoded command, suspicious
  lineage) — to the ATT&CK technique ids they evidence.
- The policy input exposes `input.attack.techniques` (ids) computed from the state, content-free and
  derived like `input.event.behavioral` — so a policy can route by technique and SIEM/XDR can group by it.

## Capabilities

### New Capabilities
- `attack-mapping`: map OpenShield's detection signals to MITRE ATT&CK technique ids, so detections carry
  a shared adversary vocabulary — the tagging SIEM reporting and XDR correlation both consume.

### Modified Capabilities
<!-- none -->

## Impact

- **Code:** a new `internal/attack` package (a static signal→technique table + a `Techniques(signals)`
  function returning deduplicated, sorted techniques) and `input.attack.techniques` in the policy
  mapping. No proto/core change — the techniques are a pure derivation of existing signals. Proven: a
  cloud-sync exfil + a credential detection yield the exfiltration + unsecured-credentials techniques; a
  LOLBin behavioral yields the system-binary-proxy technique; an IOC domain yields a C2 technique; no
  signals yield none.
- **Scope note (honest):** the mapping is a curated STARTER set covering the signals OpenShield produces
  today — it is not the full ATT&CK matrix, and it maps signal→technique, not the full sub-technique
  taxonomy (sub-techniques and tactic grouping are refinements). Persisting the techniques onto the
  unified alert row is XDR-2's schema work; this increment computes and exposes them so a policy sees
  them now and the correlation lane reuses the vocabulary.
