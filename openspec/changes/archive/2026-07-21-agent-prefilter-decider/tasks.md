# Tasks — prefilter PartialDecider implementation (D95)

## 1. Decider

- [x] 1.1 `prefilter.Decider` (`NewDecider`) implements `PartialDecider`: bounded prefix read (LimitReader + worker MaxBytes), worker content-classify (D72), policy via an audit-less dispatcher, returns Decision. Never parses (D13); never audits (D16).

## 2. Proof (real worker; guards mutation-tested)

- [x] 2.1 **Test** (real worker binary + real OPA BLOCK-on-CPF policy): a bounded prefix with a CPF → BLOCK high-confidence; clean file → ALLOW; wired through PreFilter + REAL watchdog → inline kernel DENY + async job submitted; a CPF PAST the prefix → ALLOW (bound is real); empty path → its own error.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D95.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| empty-path guard removed | empty-path test asserts the distinct 'no path to classify' error |
| (read LimitReader removed) | NOT detection-observable — worker MaxBytes also bounds the parse; kept as an IPC/memory latency guard, noted honestly |
| BLOCK routing / async-submit / floor | covered by the D94 PreFilter mutation set (this decider feeds it) |
