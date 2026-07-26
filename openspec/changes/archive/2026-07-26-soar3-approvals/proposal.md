## Why

Four-eyes control exists in this codebase exactly once, welded to one action: closing an investigation case
(D36). The predicate is right — the requester≠approver comparison is enforced inside the UPDATE, so two
operators racing cannot both slip through — but it is spelled into `cases` and reachable from nothing else.

Everything Lane B is about to build needs the same control over different subjects. SOAR-7's high-impact
Response-Intents (`CONTAIN`, `REVOKE_TRUST`) must not be issuable by one person. SOAR-4's playbooks need a
`wait-for-approval` step. SOAR-8's IdP responder disables user accounts and is specified as "four-eyes
always". Re-implementing the predicate per feature is how one of them ends up subtly wrong — and the one
that is wrong is the one that lets a single operator contain a fleet.

## What Changes

- **A typed `approvals` object**: a request names a SUBJECT KIND (`case-close`, `playbook-step`,
  `response-intent`), a subject id, and a requester; an approval names a different operator. Any feature
  that needs a second pair of eyes asks for an approval rather than growing its own columns.
- **The requester≠approver rule stays in the UPDATE predicate**, so it is atomic under a race — the property
  that makes it a control rather than a check.
- **Approvals expire.** A pending approval past its TTL is not approvable: an approval request left open for
  a week is not consent, and stale pending state is how "someone approved it eventually" becomes the norm.
- **Case closure moves onto it**, so there is one implementation and D36 keeps behaving exactly as before.

## Capabilities

### New Capabilities

- `four-eyes-approvals`: a reusable approval object with an atomic requester≠approver rule, expiry, and
  terminal outcomes.

### Modified Capabilities

- `control-plane`: case closure is expressed as an approval rather than case-specific columns.

## Impact

- **Code:** `internal/controlplane` (the approvals store + routes), one migration, `cases.go` rewired.
- **Decisions:** generalizes **D36** (four-eyes on case close) and is the dependency SOAR-4/7/8 need.

### What this change does NOT claim or cover

- **It does not authenticate the approver** beyond the verified operator identity the transport already
  provides: two certificates issued to the same human are two operators as far as this is concerned. That
  is an identity-governance problem (who gets a cert), not one an approval table can solve, and claiming
  otherwise would be the overclaim.
- It does **not** implement approval *policy* — which subjects require approval, and how many approvals, is
  the requesting feature's decision. This ticket provides one approval, from one different operator.
- It does **not** notify anyone that an approval is pending; routing is SOAR-9.
- Nothing yet *uses* it beyond case closure. SOAR-4 and SOAR-7 are the consumers, and until they land this
  is a capability with one caller — stated so it is not mistaken for coverage.
