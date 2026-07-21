## Context

D73's `Proxy` classifies plain-HTTP requests and applies a verdict to the live
connection; D74 tunnels HTTPS blind (uninspected). To inspect HTTPS the proxy must
terminate the client's TLS itself (MITM): present a certificate the client trusts
for the requested host, read the decrypted HTTP, and re-forward to the real origin.
The certificate must be signed by a CA the managed endpoints trust — an
interception CA that, by construction, can impersonate any site.

## Goals / Non-Goals

**Goals:**
- Classify HTTPS request bodies by terminating and re-originating TLS.
- Reuse the plain-HTTP pipeline unchanged for the inner request.
- Tunnel cert-pinned/sensitive hosts blind (do-not-intercept list).
- Keep interception opt-in and its CA distinct from the fleet CA.

**Non-Goals:**
- Revocation/rotation for the interception CA; HTTP/2 / QUIC interception; a
  metadata-only audit of tunneled flows; the worker pool.

## Decisions

**A SEPARATE interception CA, never the fleet mTLS CA.** An interception CA signs a
cert for any host on demand, so whoever holds it can impersonate the whole internet
to every endpoint that trusts it — a blast radius far larger than fleet identity
(which authorises agents/operators). Signing MITM leaves with the fleet CA (D60)
would fuse the two. `provision.InterceptionCA()` is a distinct generator (distinct
CN), and the gateway loads it from its own files. Its custody IS the scheme's
security (D16), stated like the escrow and fleet keys.

**On-the-fly SNI leaf minting, cached.** `CertMinter.For` is a
`tls.Config.GetCertificate` callback: it mints an Ed25519 leaf for
`hello.ServerName` (DNSNames=[host]) signed by the interception CA, caches it by
host, and returns it. Empty SNI is rejected — a client that sends no SNI cannot be
MITM'd to a named host, and guessing one would present a wrong cert. Ed25519 leaves
interoperate with Go's TLS; a real deployment may prefer ECDSA for older clients (a
noted compatibility choice, not a correctness one).

**The inner request runs the SAME pipeline as plain HTTP.** `ServeHTTP`'s body is
extracted into `serve(w, r, targetURL, rt)`: read the body bounded, register the
flow, `Process` (classify in the worker, decide, audit), then apply the disposition
(forward via `rt` to `targetURL` / 403 / 302), fail-open on error. The plain path
calls `serve(w, r, r.URL.String(), plainRT)`; the intercept path, after terminating
TLS, reconstructs `https://<sni-host><origin-uri>` and calls `serve(w, r, thatURL,
originRT)`. Classification, enforcement, observe-only and fail-open are therefore
identical for intercepted HTTPS and plain HTTP — one code path, one set of guards.

**Terminate then serve with net/http, not a hand-rolled loop.** `intercept()`
hijacks the client conn, writes `200`, wraps it in `tls.Server` with
`GetCertificate` and `NextProtos:["http/1.1"]` (forcing HTTP/1.1 so request framing
is standard), and serves the decrypted conn with `http.Serve` over a ONE-SHOT
listener. The listener yields the conn once and blocks; the served conn is wrapped
so that when net/http closes it (keep-alive ended), it closes the listener, so
`http.Serve` returns exactly when the connection is done — never while a request is
in flight. This reuses net/http's request parsing, keep-alive and response writing
rather than reimplementing them.

**The do-not-intercept list is the safe default.** Even with interception on, a
host matching the list (exact or domain suffix) is tunneled blind (D74). Cert-pinned
apps BREAK under MITM (the pin rejects the minted leaf), and banking/health egress
is sensitive to inspect — so exclusion is a correctness and a privacy control, not
an afterthought. Interception is opt-in (no CA configured → tunnel everything, D74).

## Risks / Trade-offs

- **The interception CA is a skeleton key.** Its custody is the whole scheme's
  security (D16). Stated as loudly as the escrow/fleet keys; a real deployment fronts
  it with an HSM/short-lived issuance.
- **MITM is legally and ethically weighty** — it reads employees' HTTPS. It is
  opt-in, the do-not-intercept list scopes it, and (like the endpoint) it is subject
  to the notice/DPIA posture the project already documents. Not hidden.
- **Ed25519 leaves may not suit every client.** A compatibility choice; ECDSA is a
  drop-in if needed. Noted.
- **Re-originated TLS validates the real origin normally** (production), so the
  gateway is not a downgrade point; the test injects trust for the httptest origin
  only.
