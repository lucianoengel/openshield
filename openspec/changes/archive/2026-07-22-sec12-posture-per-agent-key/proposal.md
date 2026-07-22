# SEC-12: bind posture signatures to the reporting agent's own key

## Why

SEC-1 closed unsigned / past-mTLS posture forgery by requiring a signature — but against ONE shared
posture key the whole fleet holds. So any agent (or one compromised endpoint) can sign a
`PostureUpdate{subject: <another agent>, compliant: true}` with the shared key and it verifies —
forging the victim's compliance and defeating the D85 device-posture tamper-lockout for that victim.
SEC-1 fixed third-party forgery; agent-to-agent forgery remained.

## What Changes

- **Posture is verified against the REPORTING AGENT's own enrolled key**, resolved by the update's
  subject (subject↔key binding): an update for subject S is applied only if it verifies against S's
  own key. An agent holding only its own key therefore cannot sign a compliant posture for a
  different subject.
- **`PostureSubscriber` takes a `PostureKeyResolver`** (subject → enrolled pubkey) instead of a
  single trusted key. `LoadPostureRoster` loads a `<subject> <base64-pubkey>` roster file into a
  resolver; the gateway wires it via `OPENSHIELD_POSTURE_ROSTER` (replacing the single
  `OPENSHIELD_POSTURE_PUBKEY`). Risk stays on the single control-plane key (SEC-1 split unchanged).

## Impact

- Affected specs: `device-posture`
- Affected code: `internal/gateway/posture.go` (resolver + roster loader), `signedupdate.go`
  (split parse from verify), `cmd/openshield-gateway/main.go` (roster wiring).
- Not in scope (stated): automatically syncing the roster from the control-plane enrollment records
  (the roster is a deployment export for now — a control-plane-fed resolver is a follow-up); hardware
  attestation of the posture itself (ZT-1 — a compromised-but-alive agent still signs its own
  posture; per-agent keys stop forging ANOTHER's, not lying about your own).
