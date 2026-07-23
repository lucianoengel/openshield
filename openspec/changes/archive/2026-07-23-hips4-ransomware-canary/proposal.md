## Why

Ransomware's defining behavior is **mass file modification** — it walks a tree and encrypts everything.
FIM (D223/D228) detects tampering of *specific* critical files, but ransomware's signal is different and
louder: **many** files changing at once. A ransomware canary exploits this: plant innocuous decoy files
that no legitimate process should touch, and when *several* of them change (are encrypted or deleted)
within a short window, that correlated mass-change is a high-confidence ransomware signal — caught early,
while the encryption is still spreading, not after the fact. This is a classic, expected endpoint control
OpenShield lacks.

## What Changes

- **New `internal/canary` package** — the detection core:
  - **Plant** decoy files (recognizable content) into operator-designated directories, and record their
    known-good baseline (reusing the FIM manifest). Idempotent — existing canaries are not re-planted.
  - **A correlation detector** — a sliding-window counter of *distinct* canaries changed; when the count
    reaches a threshold within the window, it fires a ransomware detection. A single canary edit does not
    fire (that is a lone anomaly); the *mass* signature does.
  - **An entropy check** — Shannon entropy over a changed canary's content; a high-entropy rewrite is the
    encryption signature, raising confidence over a plain edit.
- **A producer** — watches the canary directories (reusing the real-time fanotify watch, D228), and on a
  change re-checks the canaries against their baseline (reusing `fim.Scan`); each drifted canary feeds
  the detector, and crossing the threshold emits a high-severity **ransomware event** into the pipeline
  → policy → alert.
- **Proto (additive):** `EVENT_KIND_RANSOMWARE_SUSPECTED = 11`; the engine classifies it as metadata-only
  (the affected files may be encrypted/deleted) and the policy alerts on it.

## Capabilities

### New Capabilities
- `ransomware-canary`: detect a ransomware attack by planting decoy files and firing a high-severity
  detection when a threshold of them is modified/deleted within a window (with entropy raising
  confidence), so encryption is caught while it spreads.

### Modified Capabilities
<!-- none — the engine metadata-only classify of the new kind is carried by the new capability. -->

## Impact

- **Code:** new `internal/canary` (plant + correlation detector + entropy); a producer + wiring in
  `cmd/openshield-engine` (behind `OPENSHIELD_CANARY_DIRS`); one additive proto enum value; the engine
  `classifyStage` treats the ransomware kind as metadata-only (like `FILE_DELETED`). Reuses `fim` and the
  fanotify watch. No migration, no new dependency.
- **Testing:** the detector (threshold within window fires; spread-out changes do not; distinct-canary
  counting), the entropy check (high-entropy vs plain content), and planting are unit-tested; an
  end-to-end test mass-modifies planted canaries and asserts a ransomware event reaches a policy alert.
- **Deferred:** automated CONTAINMENT (kill the encrypting process / isolate — the SOAR intent seam,
  SOAR-7); adaptive thresholds; canary self-healing/re-planting after a trip; per-process attribution of
  which process is encrypting (needs the exec/fanotify-PID correlation).
