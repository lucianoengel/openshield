# Tasks — SEC-9 access-proxy header hygiene (D121)

## 1. Fix

- [x] 1.1 AccessProxy: sanitizeIdentityHeaders strips spoofable identity/forwarding headers (incl. the trusted one); inject X-OpenShield-Subject = verified pseudonym.

## 2. Proof (real TLS; guards mutation-tested)

- [x] 2.1 **Test**: a spoofed X-Authenticated-User + pre-set X-OpenShield-Subject do not reach the backend; the injected subject = the cert pseudonym; the spoofed X-Forwarded-For value does not survive.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D121.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| don't strip spoofed identity headers | the backend receives X-Authenticated-User=admin |
| don't inject verified subject | the backend has no/wrong X-OpenShield-Subject |
| (trusted header not in strip list) | SURVIVES — the inject Set overwrites a pre-set value; honest defense in depth |
