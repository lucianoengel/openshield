## 1. Signed envelope

- [x] 1.1 `SignedTelemetry` proto (agent_id, sequence, kind, payload, signature) + regenerate;
      `SubjectSigned` in the nats transport
- [x] 1.2 `SignedPublisher{identity, conn, seq}`: sign canonical(agentID, seq, payload), publish;
      one monotonic counter across kinds

## 2. Verify on ingest

- [x] 2.1 Migration `008`: add `verified BOOLEAN NOT NULL DEFAULT false` to fleet_telemetry
- [x] 2.2 Control plane subscribes to `SubjectSigned`; handler VerifySigned → on success persist
      (verified=true, attributed to the verified agent, unmarshal by kind); on error increment
      `RejectedTelemetry`; on gap increment `Gaps`
- [x] 2.3 Legacy unsigned handler persists with verified=false

## 3. Tests (embedded NATS + real Postgres)

- [x] 3.1 **Test**: an enrolled agent's signed telemetry verifies, is stored verified, attributed.
      `TestSignedTelemetryVerified`
- [x] 3.2 **Test**: bad signature / unknown agent / revoked / replay each rejected + counted, stores
      nothing. `TestUnverifiableRejected`
- [x] 3.3 **Test**: a gap is recorded and the message still stored. `TestSignedGapRecorded`
- [x] 3.4 **Test**: legacy unsigned telemetry stored verified=false. `TestLegacySelfAsserted`

## 4. Docs

- [x] 4.1 Note in `docs/decisions.md` (new D-number): verify-on-ingest; attributable + gaps; legacy
      path labelled self-asserted; root forges; mTLS complementary
- [x] 4.2 Validate; archive

## Verification performed

| mutation | caught by |
|---|---|
| persist on VerifySigned error (don't reject) | `TestUnverifiableRejected` |
| mark legacy unsigned rows verified=true | `TestLegacySelfAsserted` |

An enrolled agent's signed telemetry verifies, is attributed and stored
verified=true (`TestSignedTelemetryVerified`); an unknown agent and a bad
signature are rejected and counted, storing nothing (`TestUnverifiableRejected`);
a jumped sequence records a gap while storing the authentic message
(`TestSignedGapRecorded`); legacy unsigned telemetry is stored verified=false
(`TestLegacySelfAsserted`). All over embedded NATS + real Postgres; guards
mutation-tested. Docs: D50.
