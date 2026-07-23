## Context

FIM (D223) hashes a baseline and detects per-file drift; the real-time watch (D228) triggers a re-scan
on a fanotify change. Ransomware canary reuses both but adds the ransomware-specific signal: a
**correlated mass change** of decoys. The novel logic is the sliding-window correlation detector and the
entropy check; the plant + watch + scan are compositions of existing pieces.

## Goals / Non-Goals

**Goals:** plant decoys; fire a high-severity ransomware detection when a threshold of distinct canaries
change within a window; entropy raises confidence; feed the pipeline for a policy alert.

**Non-Goals (deferred):** automated containment (SOAR-7 intent); adaptive thresholds; canary re-planting;
per-process attribution.

## Decisions

1. **The signal is CORRELATED mass change, not any change.** A `Detector{Threshold, Window}` records each
   canary change with its timestamp and reports a detection when the number of DISTINCT canaries changed
   within the trailing `Window` reaches `Threshold`. This is what separates ransomware (many files fast)
   from a lone canary edit (one anomaly). Distinct-path counting prevents one canary flapping from
   tripping it. Old changes prune out of the window, so the fleet's slow background churn never
   accumulates to a false detection.

2. **Canaries are a FIM baseline; drift is confirmed by hash.** `Plant` writes decoy files and records
   their SHA-256 baseline (a `fim.Manifest`). On a fanotify change, the producer runs `fim.Scan` over the
   canaries and feeds each drifted (modified/deleted) canary path to the detector — so the detector counts
   *confirmed* content changes, not raw fanotify events (a metadata touch that does not change content is
   not a canary trip).

3. **Entropy raises confidence.** For a *modified* (still-present) canary, the producer computes the
   Shannon entropy of its new content; near-maximal entropy (≈ 8 bits/byte) is the encryption signature.
   Increment 1 uses entropy as a confidence input on the emitted event (high-entropy → higher
   confidence), not as a gate — a deleted canary or a low-entropy corruption still counts toward the
   threshold (ransomware that deletes rather than encrypts must still be caught).

4. **A distinct high-severity event kind.** `EVENT_KIND_RANSOMWARE_SUSPECTED = 11` (additive) so the
   policy can route it specifically (alert now; contain later via SOAR-7). It carries the affected
   directory as a `FilesystemSubject` and is classified **metadata-only** (the files may be
   encrypted/deleted — do not open them), like `FILE_DELETED`.

5. **Plant is idempotent and unobtrusive.** Canary files use plausible-but-recognizable names/content so
   ransomware treats them as ordinary targets (and encrypts them), while an operator/agent can recognize
   them. Re-running Plant does not overwrite existing canaries (their baseline is stable).

## Risks / Trade-offs

- **Threshold tuning.** Too low → a legitimate bulk operation touching a canary dir false-fires; too high
  → slow ransomware evades. Increment 1 exposes `Threshold`/`Window` as operator config; adaptive
  thresholds are deferred. Canaries in directories users don't normally touch minimize false positives.
- **Detection, not prevention (increment 1).** The event drives an ALERT; automated containment (killing
  the encrypting process) is the SOAR-7 intent seam, deferred. Early alert still shrinks the blast radius.
- **Entropy as confidence, not gate.** A ransomware that deletes or overwrites with low-entropy junk is
  still caught by the mass-change threshold; entropy only sharpens confidence for the encrypt case.
- **Canary evasion.** Sophisticated ransomware could skip files it recognizes as canaries; plausible
  naming mitigates but does not eliminate this — canaries are one layer, complementing FIM and behavioral.
