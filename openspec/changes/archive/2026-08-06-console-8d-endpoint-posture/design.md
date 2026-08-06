# Design — CONSOLE-8d

## Three identities that must agree, or posture is silently ignored

The endpoint signs its posture under `pseudonym.Of(agentID)`; the roster loader keys enrolled public keys
by `pseudonym.Of(<roster name>)`; the access proxy resolves the client certificate's CN through the same
derivation. All three must land on the same string or the update is simply never applied — SEC-12 says
unenrolled posture is discarded, so a mismatch is silent by design.

That is why the engine names the subject it publishes under at startup. It is the only thing that makes a
mismatch debuggable rather than a mystery about why a device is always denied.

## Binary integrity is three states, never two

"I did not check" must not be storable as verified or as mismatched. Verified would let an unconfigured
endpoint satisfy a policy requiring integrity; mismatched would deny every endpoint that has simply not
been configured for it. Every failure path — no key, unreadable key, wrong key length, verification could
not run — returns UNCHECKED rather than guessing.

It is re-checked on every report rather than cached at startup, because a binary can be replaced while the
agent runs and a cached answer would keep vouching for it.

## An unusable key is fatal; an absent key is not

Absent means the operator did not opt in — legitimate, and it degrades to the prior behaviour with a
startup line naming the consequence. Configured-but-unusable means the operator believes this endpoint is
reporting. Starting anyway would have the gateway deny it for "no posture" while nothing anywhere explains
why, so it stops instead.

## Why the test asserts the denial first

Asserting only that a posture-carrying endpoint is allowed would pass against a policy that ignores
posture entirely. The before/after on one gateway — same client, same role, same policy — is what shows
the endpoint's report is the thing that changed the decision.
