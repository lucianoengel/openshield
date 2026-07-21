# Add privacy-law product features (T-013)

## Why

D20 made privacy-law features Phase-1 architecture, not later additions, because retrofitting
them is expensive and, for a workplace-monitoring tool in the EU, their absence is a legal
blocker (GDPR Art. 5/17; German works-council veto). The schema already carries the columns
(purpose, retention_class, pseudonymous subject_id); nothing yet acts on them. This change makes
retention, exclusion and view-accountability real.

It also confronts a tension the ledger created and this ticket must resolve: **enforced
retention requires deleting old records, and the audit ledger is hash-chained, so deleting a
record breaks verification of every record after it.** Retention and tamper-evidence appear to
contradict. They do not, but only with a deliberate design — this change is largely that design.

## What changes

**Retention purge by tombstoning, not deletion.** A purge erases the personal data in an expired
entry (the pseudonymous subject and the decision payload) while KEEPING the chain skeleton —
sequence, previous-hash, hash, signature. Verification treats a tombstoned entry specially: it
checks the chain link and the signature over the stored hash, and does NOT recompute the hash
from content, because the content is intentionally gone. The chain stays continuous and
authentic across an erasure; what is lost is exactly what retention requires to be lost. A
purge is itself recorded, and verification reports how many entries are tombstoned so an auditor
sees that erasure happened rather than being unable to tell erasure from tampering.

**Retention classes map to durations, enforced by a purge job.** `RetentionShort/Standard/
Investigation` get concrete maximum ages; an entry past its age is tombstoned. Investigation-class
entries are held (a legal hold overrides routine retention) — purging evidence in an open
investigation would be the wrong default.

**Exclusion lists as a first-class policy primitive.** A configured exclusion (a personal
folder, a break-time window) means the event is never produced — excluded input does not reach
classification, so no personal data about it is ever created. Exclusion at the source, not
redaction after the fact: the honest way to not surveil something is to not look at it.

**View accountability.** Reading an investigation through the CLI writes an audit entry recording
that it was viewed. D20 requires the trail cover who VIEWED, not only who acted. **Honest limit,
resolved openly:** there is no authenticated operator identity until T-017, so the recorded
viewer is the local OS user, labelled as unauthenticated. That is a real, attributable signal on
a single-operator deployment (the dogfood target) — different from the "unattributable" case the
CLI change (D32) declined to fake. This refines that decision rather than contradicting it: an OS
user is attributable; an absent identity is not.

**Pseudonymisation and purpose tagging: confirmed and tested, not newly built.** subject_id is
pseudonymous by construction (D23) and purpose rides every event (D20); this change adds the
tests that pin those properties so they cannot regress, rather than reimplementing them.

## What this does NOT claim or cover

- **It does not make erasure defeat a root attacker.** Tombstoning is a legitimate retention
  operation; an attacker with database access could also tombstone a live entry to hide it, and
  without an external anchor (T-019) that is indistinguishable from a lawful purge — the SAME
  limit the ledger already states for truncation. Tamper-evident, not tamper-proof.
- **It does not ship the full L1 legal package.** The four-eyes gate before HR-visible outcomes
  and the employee-notice mechanism concern enforcement and a control plane that do not exist in
  observe-only Phase 1; a DPIA template is shipped in docs as the one L1 item that is purely
  documentary. The rest is scoped to the phase where enforcement exists, and named so it is a
  deferral, not a drop.
- **It does not provide authenticated viewer identity.** The OS user is recorded and labelled
  unauthenticated; real identity is T-017.
- **Exclusion is not a security boundary.** It is a privacy control the operator configures; a
  user cannot invoke it to evade DLP because the operator owns the exclusion list, not the user.

## Decisions

Depends on **D20** (privacy features are architecture: retention/purge, purpose, exclusion lists,
pseudonymisation, view-audit), **D23** (pseudonymous subject), **D12/D30** (the hash-chained,
forward-secure ledger the purge must not break), and **D32** (the CLI's honest trust posture).

Establishes a new decision: **retention purge tombstones rather than deletes — erasing content
while preserving the chain skeleton — so retention and tamper-evidence coexist**, with the
residual (a root attacker's tombstone is indistinguishable from a lawful purge without T-019)
stated plainly.
