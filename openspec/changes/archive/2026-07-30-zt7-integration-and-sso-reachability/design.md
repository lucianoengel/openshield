# Design

## Why the handshake had to change and how far

`RequireAndVerifyClientCert` refuses a certificate-less client during the TLS handshake. That is correct for
a fleet endpoint and it makes a bearer token unpresentable: there is no request to read a header from.

`VerifyClientCertIfGiven` is the minimum change that makes SSO reachable. It preserves the property the
mutual-TLS gate was actually for — a certificate that IS presented is verified against the CA, so an
unknown or forged one is still refused at the handshake — and drops only the requirement that one be
present. Absence becomes an authorization question one layer up, where a request with no credential is a
401.

Scoped to SSO-enabled deployments. Applying it unconditionally would widen the unauthenticated surface of
every existing deployment for a feature they have not turned on.

## Separate operator constructors

`NewOIDCVerifier` requires a role claim, and an existing test asserts it. Relaxing that to serve the
operator path would mean a ZTNA gateway missing its role-claim setting constructs happily and fails per
request, where a subject's group cannot be read — converting a startup misconfiguration into a runtime one.
The ZTNA path keeps failing fast; the operator path gets its own constructors, which never wanted the field.

## The vacuous assertion

The forged-certificate case is the assertion that makes the relaxation safe, so it is worth more than the
positive case — a test that only checks "SSO works" passes equally against a listener accepting any
certificate.

The first version was satisfied by the wrong mechanism. A client from a second PKI does not trust this
server's CA, so its handshake fails client-side; the assertion saw an error and concluded the server had
rejected the certificate. Under a mutant that removed server-side verification, it still passed.

Isolating the direction means trusting the server's CA as a ROOT while presenting a leaf from another CA.
Then the only possible failure is the server refusing the client, and the mutation fails.

The general shape: **when asserting that one side rejects something, make sure the other side has no reason
to fail.** A mutual protocol gives two candidate causes for one observed error, and a test that does not
separate them measures whichever happens first.
