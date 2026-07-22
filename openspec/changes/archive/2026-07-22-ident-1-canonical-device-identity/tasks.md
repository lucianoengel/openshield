## 1. Shared pseudonym derivation

- [x] 1.1 Create `internal/pseudonym` (package `pseudonym`) with `func Of(identity string) string`
      returning the exact current bytes `"sub_"+hex(sha256("zt-client-subject:"+identity)[:12])`;
      imports only `crypto/sha256` and `encoding/hex`.
- [x] 1.2 Add a golden-value test pinning `pseudonym.Of` for a fixed input, so a future change to the
      domain string or truncation is caught (guards D23 stability of existing user-cert subjects).
- [x] 1.3 Route `internal/gateway/identity.pseudonym` through `pseudonym.Of` (thin call; no byte
      change) and confirm existing `identity`/OIDC/access tests still pass unchanged.

## 2. Canonical posture subject on the producer

- [x] 2.1 In `cmd/openshield-fleet-agent/main.go`, publish device posture under
      `pseudonym.Of(agentID)` (not `env("OPENSHIELD_SUBJECT", agentID)`); leave the agent's own event
      `PseudonymousId` as-is (XDR-1 scope). Update the nearby comment to state the canonical binding.
- [x] 2.2 If `internal/posture.Publish`'s doc implies a raw subject, adjust the comment to name the
      canonical pseudonym contract (no signature change — `Publish` still takes the subject it is given;
      the CANON decision is explicit at the call site per design D-b).

## 3. Roster / verifier keyed by the canonical pseudonym

- [x] 3.1 In `internal/gateway/posture.go` `LoadPostureRoster`, key the resolver map by
      `pseudonym.Of(field0)` (treat field 1 as the agent identity), and update the format doc/comment
      from `<subject>` to `<agent-identity> <base64-pubkey>`.
- [x] 3.2 Confirm SEC-12 still holds: an update with subject `pseudonym.Of(agentID)` verifies against
      the roster key for that agent; a foreign-subject update is still rejected (existing SEC-12 test
      re-keyed to the canonical pseudonym, still green, mutation-reintroduction still FAILs).

## 4. Device certificate CN convention

- [x] 4.1 Document in `internal/provision` (and the deploy/provisioning notes) that a device's
      RoleClient certificate is issued with `CN = the enrolled agent identity`, so the proxy's
      `pseudonym(CN)` equals the producer's `pseudonym.Of(agentID)`. No signature change to
      `NewClientCert` (CN is already the `identity` arg).
- [x] 4.2 Add a provisioning test: issue a client cert with `identity = agentID`, resolve it via
      `identity.FromClientCert`, assert `.Subject == pseudonym.Of(agentID)`.

## 5. End-to-end verification (real path, no seeded literal) + mutation guards

- [x] 5.1 Add an e2e test (gateway/posture level): the REAL `posture.Publish` signs a compliant
      posture for an enrolled agent → gateway `PostureSubscriber.Apply` verifies (roster keyed by
      `pseudonym.Of`) and stores → a request whose device cert has `CN = agentID` resolves posture
      PRESENT and a posture-gated policy ALLOWS it; an agent with no published posture is DENIED.
      The store MUST NOT be pre-seeded with the key the test asserts.
- [x] 5.2 Mutation guard A: revert the publisher to key posture by the raw `agentID` → the e2e's
      compliant-device assertion FAILs (proves the canonical keying is load-bearing).
- [x] 5.3 Mutation guard B: make the proxy derive the lookup subject by an independent scheme (e.g.
      raw CN) → the e2e FAILs (proves the shared derivation is load-bearing on the proxy side).
- [x] 5.4 Repair any existing test that passed only by seeding `Set(pseudonym(CN))` and reading the
      same literal (posture, ZT-3 dual-credential) to drive the real publish→verify→resolve path.

## 6. Gate + record

- [x] 6.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green (build+vet+`-race` test+check) on Linux;
      `GOOS=windows go build ./...` and `GOOS=darwin go build ./...` clean.
- [x] 6.2 Add decisions.md entry (next D-number) describing the inert-posture root cause, the shared
      `internal/pseudonym` derivation, the canonical `pseudonym.Of(agentID)` keying across
      publisher/roster/proxy, the cert-CN convention, and the two mutation guards; note IDENT-1
      unblocks ZT-3 in prod and ZT-1/XDR-1.
- [x] 6.3 Update the roadmap next-order (mark IDENT-1 done) and the phase-1-progress memory file.
