# Design — SEC-D four-eyes assurance

## Why record rather than refuse by default

Refusing by default is the instinctive fix and it is wrong here.

Every existing four-eyes flow — case closure, fleet-control publication, high-impact response intents —
runs today on deployments configured exactly as documented, with both hardening switches off for the
migration reason those switches were given. Defaulting a refusal on would break all of them, silently
from the operator's point of view, at the moment someone is trying to approve something. It would look
like the feature is broken rather than like the deployment is unhardened, and the likely response is to
find whatever flag turns it back off.

A recorded weak approval, by contrast, is **visible**, permanent, and costs nothing at the moment of
use. It converts the problem from "the control claims something untrue" into "the control says exactly
what it was" — which is the actual defect. `REQUIRE_STRONG` is there for a deployment that has decided a
weak approval is not an approval, and it is stated at startup so choosing it is a decision rather than a
discovery.

## Why the assessment reads the environment rather than taking parameters

`AssessFourEyes` reads the same two switches the authorization path reads, directly. A parameter would
be a chance for a caller to pass what it wishes were true, and the value would then be a claim by the
caller rather than a fact about the deployment. Both switches are bootstrap-scoped, so this cannot
change under a running process and there is nothing to cache or invalidate.

## Why denials are never gated

The asymmetry is the whole design of the gate, and getting it backwards inverts the control.

A pending approval is a request to do something dangerous — contain a host, disable enforcement
fleet-wide, close a case. If a weak deployment cannot record a DENIAL, that request stays pending and
approvable, and the person blocked is the one trying to stop it. The hardening switch would then be a
mechanism for keeping dangerous things alive.

So the gate reads `approve && !strong && required`. Removing the `approve &&` is a mutation with its own
test.

## Why the column is written at resolution

Assurance is a property of a moment, not of a configuration file. Deriving it at read time would mean
that hardening a deployment silently rewrites the meaning of every historical approval — every past
weak approval would start reading as strong, which is precisely the false attestation this change
exists to remove, reintroduced with a longer reach.

Existing rows get an empty string rather than `weak`. The configuration those approvals were resolved
under is genuinely unknown here, and writing `weak` would be putting a claim into an audit trail that
nothing observed. Empty means "resolved before this was recorded", which is true.

## What is deliberately still not solved

Four-eyes distinguishes two **identities**, never two **people**. Two identities under one person's
control satisfy it, and nothing available at the deployment boundary can tell the difference. Hardening
both switches raises the bar to "two records the deployment maintains, with sender-constrained tokens";
it does not reach "two humans". The startup notice says two approvals are two *people* only in the
strong case, and that sentence is already the optimistic reading — the honest limit belongs in the
threat model, where the CA-issuance-discipline concession already lives.
