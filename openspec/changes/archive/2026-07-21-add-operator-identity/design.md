## Context

`Server.View(ctx, viewer, eventID)` records a view then returns the investigation
telemetry; `RecordView` writes the `investigation_views` row. The `viewer` is a
string the caller chooses — the honest placeholder is `unauthenticated:<os-user>`.
The enrollment endpoint already runs under a mutual-TLS server config (D55) that
verifies the client certificate against a CA. This change adds a second route
that turns that verified certificate into the recorded viewer identity.

## Goals / Non-Goals

**Goals:**
- The recorded viewer is derived from a VERIFIED client certificate, not asserted
  by the caller.
- No verified certificate → no view (refused), preserving "no unattributable
  view" (D20).
- Authenticated and self-asserted views remain distinguishable in the trail.

**Non-Goals:**
- Authorization / roles: any CA-issued cert authenticates as an operator. Telling
  operator certs from agent certs is a follow-up (separate CA or cert OU).
- A query UI or richer investigation API — one authenticated view route, reusing
  the existing `View`.
- Changing the ledger's view entry, retention, or the plaintext library path.

## Decisions

**Identity comes from `r.TLS.PeerCertificates[0].Subject.CommonName`.** The handler
runs only under the D55 server config (`RequireAndVerifyClientCert`), so by the
time it executes the certificate is already verified against the CA — the handler
does not re-verify, it reads the established identity. If `r.TLS` is nil or has no
peer certificate (which cannot happen under the required-client-cert config, but
is checked defensively), the request is refused `401` with no view recorded.

**The recorded viewer is `operator:<CN>`.** A namespaced prefix keeps it
distinct from the library path's `unauthenticated:<os-user>`, so a reader can
tell an authenticated view from a self-asserted one at a glance. The CN is
whatever the operator's cert carries; binding CN→human is an operational concern
of whoever issues certs, noted, not enforced here.

**The endpoint is only mounted when TLS is configured.** Without mutual TLS there
is no verified identity to record, so exposing the route in plaintext would
recreate the self-asserted gap. When TLS is off, the authenticated view route
does not exist; the plaintext library `View`/`RecordView` remain for local/dev
use, explicitly marked unauthenticated.

**Record-before-return is preserved.** The handler calls the existing `View`,
which records first and reads second — an attempted view leaves a trail even if
the read fails.

## Risks / Trade-offs

- **Authentication ≠ authorization.** Any valid client cert (including an agent's,
  since enrollment and view share the CA today) authenticates as an operator.
  This is a real limitation, stated in the proposal and docs; the fix (cert
  roles / separate operator CA) is a follow-up. What this change DOES buy: the
  viewer is now cryptographically bound to a held credential, not a free string —
  a strict improvement over self-assertion.
- **CN is only as meaningful as issuance.** A CA that signs a cert with CN "alice"
  for the wrong person mislabels the trail. That is a PKI/operational property,
  the same class as D16; documented, not solved in code.
- **Host root still wins (D16).** An operator key readable by host root is
  compromisable. mTLS raises the bar against remote/self-asserted spoofing, not
  against a compromised host.
