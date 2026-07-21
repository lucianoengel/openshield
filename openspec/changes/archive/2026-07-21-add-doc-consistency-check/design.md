## Context

`README.md` § "What it does and does not claim" states the honest limits using the very words a
naive denylist forbids ("cannot prevent", "tamper-*proof* ... impossible"). The 2026-07-20 grep
false-positived on four such uses. The decision register `docs/decisions.md` holds D1–D36, each
`| **Dnn** | ... |`. Research reports under `docs/research-*` are append-only and discuss
everything.

## Goals / Non-Goals

**Goals:**
- Catch an unqualified overclaim on a claim surface; pass honest negated discussion.
- Catch a duplicate D-number in the register.
- Prove both with fixtures (a passing and a failing surface).

**Non-Goals:**
- Parsing English; checking all docs; validating a reference's meaning; tone linting.

## Decisions

### Claim-surface check: forbidden term, minus qualification
`doccheck.ScanClaimSurface(text) []Violation`. For each line, for each forbidden pattern, record a
violation UNLESS the line is qualified. Forbidden patterns (case-insensitive, markdown emphasis
`*`/`_` stripped before matching so `tamper-*proof*` matches `tamperproof`):
`tamper-?proof`, `unhackable`, `fully secure`, `100% secure`, `impenetrable`, `prevents
exfiltration`, `prevents data loss`, `guarantees? (?:security|safety|protection|your data)`.

Qualified means any of:
- a negation cue on the line: `\b(cannot|can't|not|never|no|isn't|impossible|does ?n't|without)\b`;
- an inline escape `<!-- allow: <term> -->` on the line or the line immediately above;
- (for the emphasis-contrast idiom) the term written with markdown emphasis AND paired with
  "evident" nearby — e.g. `tamper-*evident*, not tamper-*proof*` — is covered by the negation cue
  "not" already, so no special case is needed.

The forbidden list is chosen for a clear overclaim rationale, not vibe: each term maps to a
specific false promise the threat model forbids (prevention, tamper-proofing, absolutes).

### Claim surfaces are an explicit allowlist
`doccheck.ClaimSurfaces = []string{"README.md"}`. Explicit, because scanning `docs/` would
recreate the false-positive failure — those files exist to discuss the words. New user-facing
copy is added here deliberately.

### Register check: unique D-numbers
`doccheck.CheckDecisionRegister(text) error` extracts every `\*\*D(\d+)\*\*` and fails on a
duplicate. This catches the concrete drift risk (two decisions colliding on a number, or a
copy-paste that reused one) robustly. The ticket's alternative — flag paragraphs >3 lines next to
a D-reference — is the same heuristic that made the naive grep fail (it punishes discussion), so it
is deliberately not built; this substitution is recorded in the proposal and the decision note.

### Wiring
A test `internal/doccheck/doccheck_test.go` runs the check over the real `README.md` and
`docs/decisions.md` (so the tree must stay clean) and over `testdata/` fixtures (so the check is
proven to catch a planted overclaim and a duplicate D-number). A CI step runs the package.

## Risks / Trade-offs

- **Heuristic negation.** A convoluted sentence could pass a claim, or the allow-escape be abused.
  Accepted: the check makes an ACCIDENTAL overclaim fail CI, which is the realistic failure mode;
  a deliberate one is a reviewer's catch. Stated, not hidden.
- **Forbidden list is not exhaustive.** New overclaim phrasings won't be caught until added. The
  list is a denylist with the same limits as any denylist; it covers the specific promises the
  threat model names.
- **Fixtures could rot.** Guarded by asserting the bad fixture FAILS and the good one PASSES, so a
  change that neutered the check breaks these tests.
