## 1. Refactor Stage into an N-member composite

- [x] 1.1 Change `policy.Stage` to hold an ordered list of members `{name string; query rego.PreparedEvalQuery}`
      plus the composed `id`/`version` and the injected `newID`/`now`. Keep the `core.Stage` interface.
- [x] 1.2 Refactor `Run` to build the input ONCE, eval every member, extract each candidate via the
      existing decision-extraction logic (action/reason/confidence, and the "no rule matched → explicit
      ALLOW" default per member), then combine (task 2). A 1-member Stage MUST return that member's
      Decision unchanged (behavior-identical to today).
- [x] 1.3 Keep `New(ctx, id, version, module)` building a 1-member Stage with that id/version — every
      existing caller and test stays green.

## 2. The most-restrictive-wins combine

- [x] 2.1 Add a `dataRank` for the data-plane verbs: ALLOW<ALERT<REDIRECT<ENCRYPT_LOCAL<
      QUARANTINE_LOCAL<BLOCK. Add a `combine(candidates)` that returns the highest-ranked data candidate
      (its reason + confidence), first-wins on ties (deterministic by member order).
- [x] 2.2 Process-verb handling: `DENY_EXEC`/`KILL_PROCESS` are off-lattice. If a candidate is a process
      verb AND its member is a compliance PACK → return an error (a pack cannot escalate to a process
      verb). A process verb from the default/custom member takes precedence over data candidates (a
      process event's KILL is not overridden by a pack's ALLOW). Data event never yields a process verb.
- [x] 2.3 Stamp the composed bundle identity on the Decision: for a multi-member Stage,
      `PolicyId="openshield.composite"`, `PolicyVersion` = the member names joined in order
      (e.g. `default+pci+hipaa`). A 1-member Stage keeps its explicit id/version.

## 3. NewComposite + wiring

- [x] 3.1 Add `policy.NewComposite(ctx, packNames []string, customModule string) (*Stage, error)`:
      prepend the default, append each named pack (unknown name → error, reuse the `compliancePacks`
      registry), append the custom module (if non-empty) as member `custom`. Prepare each as its own
      query. Reject at construction if a PACK module can yield a process verb where detectable, else the
      combine guard (2.2) catches it at eval.
- [x] 3.2 Rewire `cmd/openshield-engine/main.go` and `cmd/openshield-gateway/main.go`: build packNames
      from `OPENSHIELD_POLICY_PACK` (singular, back-compat) + `OPENSHIELD_POLICY_PACKS` (comma list);
      read `OPENSHIELD_POLICY_CUSTOM` (optional rego file); if any set → `NewComposite`, else
      `NewDefault`. Update the comments to say COMPOSE, not replace.

## 4. Verify (real path, no false premise) + mutation guards

- [x] 4.1 Test: with the PCI pack composed onto the default, a behavioral process hit STILL ALERTs, a
      raw CPF STILL ALERTs, and a PCI card STILL ALERTs — driving the real composed `Stage.Run`, not a
      hand-built expectation. Parameterize over every pack (pci/hipaa/gdpr) to prove default protections
      survive EVERY pack.
- [x] 4.2 Test: the lattice picks the most-restrictive across modules (construct two members whose verbs
      differ — e.g. a BLOCK-emitting test module beside an ALLOW default — and assert BLOCK wins;
      QUARANTINE over ENCRYPT; ALERT over ALLOW).
- [x] 4.3 Test: a compliance pack whose decision yields `KILL_PROCESS` is REJECTED by composition (build
      a tiny in-test pack module or inject one) — asserts the pack-cannot-kill guard.
- [x] 4.4 Test: a 1-member composite equals the single policy's decision unchanged (identity).
- [x] 4.5 Mutation guards (apply, confirm FAIL, revert): (A) revert to single-pack-REPLACES-default →
      the behavioral-survives-PCI test FAILs; (B) break the lattice (pick min / first instead of max) →
      the most-restrictive test FAILs; (C) drop the process-verb pack guard → the pack-cannot-kill test
      FAILs. Record each in this file.
      - Confirmed 2026-07-22: (A) drop the default member → TestDefaultProtectionsSurviveEveryPack FAILs ("behavioral alerting was disabled by the pack"); (B) `r>br`→`r<br` → TestSelectWinnerMostRestrictive FAILs (ALLOW not BLOCK); (C) `if false && c.isPack` → TestSelectWinnerProcessVerbGuardAndPrecedence FAILs (pack KILL accepted). All reverted.

## 5. Gate + record

- [x] 5.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green on Linux; `GOOS=windows go build ./...` and
      `GOOS=darwin go build ./...` clean.
- [x] 5.2 Add decisions.md entry (next D-number): the silent-disable root cause, compose-not-replace via
      independent evals + Go lattice, process-verb pack guard, composed bundle stamping, the mutation
      guards; note it implements ADR-5 and closes DLP-5b.
- [x] 5.3 Update the roadmap next-order (mark DLP-5b done) and the phase-1-progress memory file.
