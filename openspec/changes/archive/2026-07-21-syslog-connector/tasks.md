# Tasks — syslog connector (D106)

## 1. Connector

- [x] 1.1 `internal/connectors/syslog`: Parse (priority → facility/severity, RFC 5424 with SD skipping + RFC 3164, bounded, rejects no-priority).

## 2. Proof (real lines; guards mutation-tested)

- [x] 2.1 **Test**: 5424 + 3164 messages decode host/app/msg/facility/severity; SD with spaces skipped; priority splits exactly (0/191/86); malformed (empty/no-pri/no-'<'/unclosed/non-numeric/out-of-range) rejected.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D106.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| priority range check removed | an out-of-range priority is then accepted |
| facility/severity split swapped | the facility/severity decode test then fails |
| SD stripping disabled | the structured-data message then includes the "[sd]" prefix |
| missing-'<' guard removed | a "34>..." line (no opening bracket) is then accepted |
