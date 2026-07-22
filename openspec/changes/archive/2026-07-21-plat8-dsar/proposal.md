# PLAT-8: data-subject access request (DSAR)

## Why

A privacy regime (GDPR Art. 15, LGPD Art. 18) gives a person the right to know what a system
holds about them. OpenShield's privacy features — pseudonymisation (D23), retention purge, legal
holds — built the mechanisms to *limit* what is held, but nothing compiled the *inventory* a
data-subject access request produces: "here is everything we hold about you." An operator asked
to answer a DSAR had to hand-run four separate queries and hope they found every store.

## What Changes

- **`SubjectAccessReport(subjectID)`** compiles, for one pseudonymous subject, a summary from
  every subject-keyed store: the audit entries (count + time span), the peer-UEBA alerts (count,
  peak risk/severity, time span), the investigation cases, and whether the subject is under a
  legal hold that would override erasure. An empty subject id is refused — a DSAR over "everyone"
  is not a data-subject request and would dump the whole store.
- **A `GET /subject?id=<subject>` endpoint**, operator-gated under mutual TLS, that records the
  DSAR access against the operator's verified identity **before** returning the report — like
  viewing an investigation (D56), an access that left no trace of who ran it would be the opposite
  of accountable.

This adds to the `privacy-features` capability. No core change; it composes existing tables.

## Impact

- Affected specs: `privacy-features`
- Affected code: `internal/controlplane/dsar.go` (new), `operator_read.go` + `enroll_http.go`
  (mount `/subject`).
- Not in scope (stated): on-demand per-subject ERASURE (right-to-be-forgotten) — retention purge
  already erases ledger content and legal holds already override it; a subject-triggered erase
  respecting holds is the follow-up; exporting raw record content (a DSAR is the inventory, and
  the ledger's content is pseudonymous and separately erasable); a self-service subject portal.
