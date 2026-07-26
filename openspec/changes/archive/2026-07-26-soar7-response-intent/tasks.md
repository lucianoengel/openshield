## 1. Contract

- [x] 1.1 `ResponseIntent{intent_id, verb, subject, version, issued_at, expires_at, reason}` with a CLOSED
  `IntentVerb` enum (unspecified, elevate-scrutiny, contain, revoke-trust); a new NATS subject.
- [x] 1.2 An enum-completeness test mirroring the Action-set guard: adding a verb requires a deliberate edit.

## 2. Publication, gated

- [x] 2.1 `SetIntentSigner` + `PublishIntent`: signs with the control-plane key, refuses to publish
  unsigned, refuses a verb outside the vocabulary.
- [x] 2.2 High-impact verbs (contain, revoke-trust) require an APPROVED four-eyes approval whose subject is
  the intent id; low-impact (elevate-scrutiny) does not.
- [x] 2.3 A blast-radius ceiling refused before publication.
- [x] 2.4 Tests: unsigned → nothing published; unapproved contain → refused (**mutation:** skip the
  approval check → FAILS); over-ceiling → refused; elevate-scrutiny needs no approval.

## 3. Consumption as verified context

- [x] 3.1 An `IntentStore` + subscriber on the consuming side: verify the signature against the
  control-plane public key, reject and COUNT a forgery, ignore an unknown version, and return nothing for
  an expired intent.
- [x] 3.2 Tests: a valid intent becomes readable context; a FORGED one is rejected and counted
  (**mutation:** skip verification → FAILS); an expired one reads as absent (**mutation:** ignore expiry →
  FAILS); an unknown version is rejected.
- [x] 3.3 Expose the current intent in policy input, so a policy CAN read it — and prove a policy that does
  not read it is unaffected.

## 4. Gate and land

- [x] 4.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` + `make proto-check` green.
- [x] 4.2 Roadmap + decision register: state plainly that nothing enacts intents yet, and that XDR-6 and
  HIPS-3 inc 2b are the consumers this unblocks.
- [x] 4.3 Commit `SOAR-7`, sync spec, archive.
