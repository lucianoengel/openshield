## 1. Agent identity

- [x] 1.1 `internal/agent/identity`: `Identity{AgentID, priv, pub}`, `Generate(agentID)`,
      `Sign(seq, payload)`, canonical length-prefixed envelope
- [x] 1.2 **Test**: two identities have distinct keys; one's signature does not verify under the
      other. `TestPerAgentKeys`

## 2. Enrollment (control plane)

- [x] 2.1 Migration `006`: `agent_identities(agent_id PK, public_key, enrolled_at, revoked_at,
      last_sequence)` + `enrollment_tokens(token_hash PK, expires_at, used_at)`
- [x] 2.2 `IssueToken(ttl)` → random token to caller, store SHA-256 hash + expiry
- [x] 2.3 `Enroll(token, agentID, pub)`: verify token valid/unexpired/unused, record identity, burn
      token, in one transaction
- [x] 2.4 **Test**: enroll once succeeds; second use fails; expired token fails; store holds a hash.
      `TestEnrollmentSingleUse`

## 3. Signed telemetry + gaps + revocation

- [x] 3.1 `VerifySigned(agentID, seq, payload, sig)`: load identity (reject unknown/revoked), verify
      sig, sequence check (in-order advance; gap → accept+record; replay/reorder → reject)
- [x] 3.2 `Revoke(agentID)`; `RecordGap`/gap counter
- [x] 3.3 **Test**: in-order accepted + advances; wrong sig rejected; gap accepted+recorded; replay
      rejected. `TestVerifySignedAndGaps`
- [x] 3.4 **Test**: a revoked agent is rejected, another still verifies. `TestRevocation`

## 4. Docs

- [x] 4.1 Note in `docs/decisions.md` (new D-number): per-agent identity, single-use token,
      signed+sequenced telemetry with gap detection, revocation; root-on-host defeats it; mTLS is
      complementary transport-layer, not this
- [x] 4.2 Mark T-017 done in `docs/plan-phase1.md`; validate; archive

## Verification performed

| mutation | caught by |
|---|---|
| accept a revoked identity | `TestRevocation` |
| accept a replay (seq <= last) | `TestVerifySignedAndGaps` |
| skip the signature check | `TestVerifySignedAndGaps` (compiling skip) |
| token not burned (reusable) | `TestEnrollmentSingleUse` |

Per-agent keys: one agent's signature does not verify under another's
(`TestPerAgentKeys`). Enrollment is single-use (second use fails), rejects expired
tokens, and stores only a hash. Signed telemetry verifies in-order and advances,
records a gap (2,3,4 suppressed → GapSize=3) while still accepting the authentic
message, and rejects replays/reorders. Revocation is per-agent — a revoked agent
is rejected while another still verifies, and an unknown agent is rejected. All
against real Postgres; guards mutation-tested. Docs: D44.
