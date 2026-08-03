# Design — SEC-A configuration bounds and direction

## Why a bound is not enough, and a direction is the durable half

The four values the review named are refusable: nothing legitimate needs a correlation sweep once a
year, or a retention window of one hour on an evidence store.

Most of the attack is not those values. A twenty-four-hour retention is a defensible choice for a
deployment with storage limits, and an indefensible one made on the day an incident is opened. A bound
cannot tell those apart, because the difference is not in the value.

What the audit trail was missing is the DIRECTION — and unlike "is this value acceptable", which is the
operator's call, "did this change reduce what the deployment can see" has one answer per field, known by
whoever declares the field. Declaring it makes the question computable at the moment of the change
rather than a piece of knowledge a reviewer needs per key.

## Why a disabling value must not order by magnitude

`OPENSHIELD_CORRELATE_INTERVAL=0s` is the sharpest single change available: its own description says
zero disables scheduled correlation, after which incidents are raised only when an operator asks.

Ordered as a number, zero is the smallest interval, and for a field where raising weakens, the smallest
value is the strongest setting. The one change that stops incidents being raised at all would have been
recorded as a hardening — worse than not classifying it, because the record would actively mislead.

`ZeroDisables` marks those fields, and a zero on them sorts to the weakest end of whichever direction the
field points. This is the case the classification exists for and it has its own test.

## Why an allowlist is AnyChangeWeakens rather than "longer is weaker"

Length is nearly the right heuristic and being nearly right is the problem: a change that REPLACES a
benign entry with a command-and-control destination leaves the length unchanged. Nothing available here
distinguishes an added CDN from an added C2 domain, and pretending otherwise would produce a classifier
that is silent exactly when it matters. Treating every edit as worth surfacing is honest, and the volume
is acceptable because allowlists are edited rarely.

## Why the previous value falls back to the DEFAULT

An unset key has no stored value, but the binary was running *something* — the declared default. Treating
"unset" as "no previous value" would make the first edit of any field unclassifiable, and the first edit
is the interesting one: a deployment that has never touched `OVERDUE_THRESHOLD` is exactly the one where
raising it goes unnoticed. Comparing against `""` instead of the default is a mutation this catches.

## Why the judgement is recorded rather than derived

Same argument as the four-eyes assurance in SEC-D: it is a fact about a moment. Deriving it when the
history is read would evaluate today's field declarations against a value set years ago, so editing a
declaration would silently reinterpret every past change. The alert reaches whoever is on call at the
time; the recorded flag is what an investigation reads later, and the two must not be able to disagree.

## Why a tightening change must be silent

An alert on every configuration change is one that gets muted, and the weakening change is then muted
with it. The whole value of this signal is its rarity, so it fires only in the direction that matters,
and that asymmetry has its own test.

## Why the classified set is written out rather than inferred

A heuristic on key names — anything ending in `_THRESHOLD`, `_INTERVAL`, `_RETENTION` — goes stale on the
first field named something else, and it fails open: an unmatched field is unclassified, and
`NotSensitive` is the zero value, so it reads as "irrelevant to detection" rather than "nobody looked".

The explicit list makes both directions of drift visible. Adding a detection setting fails the test until
someone decides which way it points; removing a classification fails it too.
