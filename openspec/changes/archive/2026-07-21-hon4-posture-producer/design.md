## Context

D92 built the posture store; SEC-1 made the subscriber verify signatures. Neither could be
exercised on the happy path because nothing published posture. HON-4 is the producer.

## Goals / Non-Goals

**Goals:** an endpoint producer that reports honest device posture, signed so the gateway
verifies it; the posture happy-path proven.

**Non-Goals:** per-agent key binding at the gateway; TPM attestation; rich detection.

## Decisions

**Honest detection — never assert unverified compliance.** `Detect` reports AgentPresent=true
(the agent is running), DiskEncrypted only if a dm-crypt mount is observed, OSPatchTier=Unknown
(no patch feed), and Compliant only from the disk-encryption evidence. A check it cannot make
reads false/unknown, so a compliance policy denies until real evidence exists — the same
error-vs-absence honesty (D28) as the rest of the system.

**Signed, subject-bound.** The update is signed with the posture key and names the reporting
agent's own pseudonym (D23). The gateway verifies it (SEC-1) before applying — a forger cannot
inject posture. The round-trip test drives the producer's bytes through the real
PostureSubscriber, so the two halves are proven together.

**Opt-in reporting.** The fleet-agent publishes posture only when a signing key is configured
— consistent with the other signed channels (risk, telemetry).

## Risks / Trade-offs

- **Self-report is only as trustworthy as the reporter.** A rooted endpoint could sign
  "compliant". TPM/measured-boot (ZT-1) is the hardening; the absent-posture fail-closed (D85)
  still catches an endpoint that stops reporting.
- **One posture key for the fleet (SEC-1 model).** Per-agent binding at the gateway is the
  hardening; the subject in the update still attributes the report to the reporting agent.
