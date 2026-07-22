## Context

The egress proxy strips hop-by-hop headers; the access proxy did not sanitize identity
headers, so a backend behind the gateway could trust a client-forged identity.

## Goals / Non-Goals

**Goals:** strip spoofable identity/forwarding headers; inject the verified subject.

**Non-Goals:** signing the injected header; SrcIP normalization.

## Decisions

**Strip then inject — the injection is authoritative.** The proxy deletes the known spoofable
identity/forwarding headers (including X-OpenShield-Subject itself, so a client cannot pre-set
it) and then Sets X-OpenShield-Subject to the verified pseudonym. Set overwrites any surviving
value, so the injected subject is authoritative; the strip is defense in depth (and covers the
other identity headers a backend might read).

**The subject is the pseudonym (D23), not the raw identity.** The backend gets the same
one-way pseudonymous subject the pipeline uses — enough to authorize, without leaking the raw
identity.

## Risks / Trade-offs

- **The injected header is unsigned** — a backend on the gateway's trust domain trusts the
  gateway to have authenticated the client. Cross-trust-domain signing is a follow-up.
- **Header name coverage is a denylist** — the common identity/forwarding headers are stripped;
  an exotic custom header a specific backend trusts would need adding. The injected,
  authoritative subject is the positive signal a backend should consume.
