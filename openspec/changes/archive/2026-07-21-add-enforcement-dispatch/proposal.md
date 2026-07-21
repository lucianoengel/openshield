# Add post-decision enforcement dispatch — Phase 2 kickoff (Direction 3)

## Why

The closed action set (D14), the `Enforcer` contract, and a real enforcer (USB, T-020) all exist,
but nothing carries out a Decision — the whole system is observe-only (D1). Phase 2 is enforcement.
The honest first step is NOT inline fanotify blocking: that would require the pipeline to complete
inside the 532µs permission window (T-002/D24), which classification — reading whole files — cannot
do. The tractable, real step is POST-DECISION enforcement: once a Decision is made and recorded, an
enforcer that can carry out its action does so, and the enforcement outcome is itself audited.
That covers the actions that do not need to be inline (quarantine-local, encrypt-local, the USB
posture, alerting) and establishes the enforcement path without reopening the budget problem.

## What changes

**The engine dispatches a Decision to a registered enforcer, after recording it.** The engine gains
an enforcer registry. When a Decision is produced, the engine records it (the existing audit), then
— if an enforcer advertises the Decision's action — invokes `Enforce`. The ORDER is deliberate: the
Decision is audited BEFORE enforcement is attempted, so the trail shows what was decided even if
enforcement fails or the machine dies mid-enforce. **Enforcement failure is itself audited** (D14 —
a failed enforcement is not silence): a high-severity audit entry records that the action could not
be carried out.

**Observe-only remains the default.** With NO enforcers registered — the Phase-1 configuration — the
engine behaves exactly as before: decide, record, do nothing. Registering an enforcer is what turns
enforcement on, per action, so D1's observe-only default is preserved and enforcement is opt-in.

**A real quarantine-local file enforcer.** `QUARANTINE_LOCAL` moves a flagged file to a quarantine
directory (owner-only), so a concrete, non-inline enforcement exists and the path is exercised end
to end: a policy that emits QUARANTINE_LOCAL → the file is moved → the decision AND the enforcement
outcome are in the ledger. It is behind a mover interface, so the dispatch logic is tested without
touching real files, with a real-filesystem test alongside.

## What this does NOT claim or cover

- **It is NOT inline blocking.** It does not deny a file open before it happens; the file was already
  read (that is how it was classified). Post-decision enforcement CONTAINS after detection
  (quarantine, encrypt, revoke), it does not PREVENT the access that triggered it. Inline blocking
  (fanotify DENY within the permission window) remains deferred with its T-002 budget reasoning —
  and even then, only for decisions cheap enough to make in-window, which classification is not.
  This is stated plainly so "enforcement" is not read as "prevention", the exact overclaim the
  threat model forbids (D16).
- **It does not enforce by default.** No enforcers registered = observe-only (D1). Enabling
  enforcement is an explicit operator act, per action.
- **Quarantine is defeatable by root** (D16). A user with root can retrieve a quarantined file. The
  honest value is containing a careless insider's flagged file, audited — not stopping a determined
  adversary.
- **It does not add new actions.** It carries out the existing closed set (D14); it invents nothing.

## Decisions

Depends on **D14** (closed action set; enforcer sees only the Decision; enforcement failure is
auditable), **D1** (observe-only default; enforcement is Phase 2), **D16** (containment not
prevention; defeatable by root), **T-020** (the enforcer contract, proven), and the engine
(Direction 2).

Establishes a new decision: **enforcement is POST-DECISION — the engine records a Decision, then
dispatches it to a registered enforcer that can carry out its action, auditing the enforcement
outcome (including failure); observe-only is the default (no enforcers), inline fanotify blocking
stays deferred (the pipeline cannot complete in the permission window), and post-decision
enforcement CONTAINS after detection, it does not PREVENT.**
