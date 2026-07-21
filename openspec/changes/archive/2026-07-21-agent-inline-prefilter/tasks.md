# Tasks — two-tier inline prefilter (D94)

## 1. Prefilter

- [x] 1.1 `prefilter.PreFilter` implements `watchdog.Evaluator`; seams `PartialDecider` + `AsyncSubmitter`; inline BLOCK only on action BLOCK && confidence ≥ floor; always submit async; fail-open on decide error; New refuses ≤0 floor. Never parses (D13).

## 2. Proof (guards mutation-tested)

- [x] 2.1 **Test**: high-confidence partial deny → VerdictBlock (and drives the REAL watchdog to a kernel Deny); low-confidence deny → VerdictAllow; clean → VerdictAllow; decide error → VerdictAllow + surfaced error; async submitted on EVERY path.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D94; empirically re-confirmed the permission-mode blocker (privileged rootless podman → EPERM).
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| confidence floor ignored (block on any BLOCK) | low-confidence-hit test — a 0.5 deny would wrongly block inline |
| async submit dropped | every test asserts exactly one async submission |
| decide error treated as clean allow (no error returned) | fail-open test — the watchdog must SEE the error to audit it |
| Block verdict downgraded to Allow | inline-block + watchdog-Deny tests |
