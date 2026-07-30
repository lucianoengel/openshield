# Design

## Reuse, not reimplementation

`validateDPoP` already checks the thumbprint against `cnf.jkt`, the signature, `htm`/`htu`, freshness and
single-use `jti`. `VerifySubjectWithProof` is the operator-shaped entry point onto it: raw subject instead of
a pseudonym, no role claim, plus the require-bound switch.

Six checks in one place. A second implementation is a second place for one of them to go missing, which is
the same argument that produced `verifyCore` in D373.

## Three refusals, and the third is the subtle one

1. **Bound token, no proof** — the core replay defence.
2. **Bound token, wrong key or wrong request** — handled by the existing validator.
3. **Bound token, verifier cannot check proofs** — refused rather than downgraded.

The third is the one an implementation naturally gets wrong, because "DPoP is off, so treat it as a bearer"
reads as graceful degradation. It is not: the issuer asked for this token to be unusable without a key, and
honouring it anyway discards that silently. Refusing is the only reading that respects what the token says.

## Why the switch defaults off

Requiring bound tokens before the identity provider issues them locks every operator out of the control
plane — the same failure mode the role-migration fallback exists to avoid (D372), and the same shape of
answer: available, documented as the hardened end state, off by default.

Without the switch at all, a provider that stops binding is invisible: every operator quietly returns to a
credential anyone who captures it can use, and nothing in the product says so.

## Where the tests live, and why they moved

The control-plane cases use a stub verifier. That is right for what they assert — the header is read, the
method and URI are passed, the require-bound flag reaches the verifier — and it is structurally incapable of
testing the validation, because the stub IS the implementation under test there.

The mutation made that concrete: three mutations of the real DPoP code left the control-plane tests green.
So the semantics live in the identity package against a real verifier and real Ed25519 proofs, where the
same three mutations fail.

Worth stating as a rule: **a test that substitutes the component whose behaviour is the claim can only test
the wiring around it.** That is a legitimate thing to test; it is not the claim.
