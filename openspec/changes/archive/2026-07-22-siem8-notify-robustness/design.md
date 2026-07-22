## Context

`internal/notify` already has `Notifier`, `Webhook` (best-effort JSON POST), `Nop`, and
`Retrying` (bounded exponential backoff with a `Permanent`/transient error taxonomy).
Delivery runs off the ingest path via the control plane's `deliverLoop` (SIEM-12). Two
SIEM-8 pieces remain: multiple sinks and an authenticated webhook body.

## Goals / Non-Goals

**Goals:**
- Fan out one notification to N sinks without one broken sink starving the others.
- Let a receiver cryptographically verify a webhook came from this control plane.
- Keep the single-unsigned-webhook path byte-for-byte unchanged (backward compatible).

**Non-Goals:**
- Durable/queued guaranteed delivery (a heavier separate mechanism; delivery stays
  best-effort, D30 — the detection is already recorded in the ledger).
- Per-sink independent addressing of failures back to the caller (the caller only logs
  an aggregate; the retry wrapper is where per-sink resilience lives).
- Rotating webhook secrets / key management (a single static secret; rotation is a
  deployment concern like the other keys).

## Decisions

- **`Multi` is the outer wrapper, retry is inner.** `Multi{Sinks: []Notifier}` delivers
  to each sink and aggregates errors. Composition is `Multi([Retrying(w1), Retrying(w2)])`,
  NOT `Retrying(Multi(...))` — the latter would re-deliver to sinks that already
  succeeded on a retry, double-paging. `Multi.Notify` attempts every sink (no early
  return), joins errors with `errors.Join`, and marks the aggregate `Permanent` only if
  every failing sink was permanent (so an outer retry, if any, doesn't spin on a mix
  that includes a recoverable sink). An empty `Multi` is a no-op success.
- **HMAC-SHA256, GitHub convention.** `Sign(secret, body)` returns `"sha256=" + hex(HMAC)`;
  the webhook sets `X-Openshield-Signature` to it when `Secret` is non-empty.
  `VerifySignature(secret, body, header)` recomputes and compares with
  `hmac.Equal` (constant-time), returning false for a wrong/absent/malformed header.
  Chosen over an asymmetric signature because the control plane and its own webhook
  receiver are a trusted shared-secret pair; HMAC is simpler and has no key-distribution
  step. The exact serialized body is signed (not the struct) so verification is
  unambiguous — the receiver signs the raw bytes it received.
- **cmd wiring.** `OPENSHIELD_ALERT_WEBHOOK` splits on commas → one `Webhook` per URL,
  each wrapped in `Retrying`, combined in a `Multi` when more than one. A single URL
  yields a bare `Retrying(Webhook)` (unchanged shape). `OPENSHIELD_ALERT_WEBHOOK_SECRET`,
  when set, is applied to every `Webhook`.

## Risks / Trade-offs

- **A shared static secret can leak** → HMAC gives integrity + origin-authenticity, not
  confidentiality; the body is already pseudonymous metadata (D23), and the secret is a
  deployment credential like the mTLS keys. Rotation is out of scope, noted.
- **`errors.Join` loses per-sink structure** → acceptable: the caller only logs, and
  per-sink resilience is the inner `Retrying`'s job, not the aggregate's.
- **Signing the marshaled body means marshaling once** → `Webhook.Notify` already
  marshals once and reuses the bytes; signing reuses the same buffer, no double-encode.
