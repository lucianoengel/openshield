# Design — one replay implementation

## Why extract before there is a second caller

Ordinarily a refactor with one caller is premature. Here it is not, because the second caller is known and
the failure mode of writing it independently is specific and severe: replay's entire value is being the
SAME answer wherever it is asked.

An operator who gets "REPRODUCED" from the console and "DIVERGED" from `openshieldctl` has learned nothing
except that the product cannot be trusted about the one thing it claims to be good at. Two implementations
of a reproducibility check is a contradiction in terms.

`ReplayResultFor` has a real caller today (`Replay`), so this is not inert code.

## The caveat is data, not presentation

The ledger stores no content, so a replay reads the input as it is NOW. A reproduction establishes only
that the policy produces the recorded decision FROM THIS INPUT; a divergence means the policy changed OR
the input did.

Carrying that in the result rather than leaving each surface to remember it is the difference between a
carefully-hedged answer and a confident one. A console that forgot it would report that the original
decision had been verified, which this cannot show.

## Unavailable is not divergence

Kept as a distinct outcome rather than collapsed. "The policy produced something different" and "there is
no record of this decision" call for different responses, and merging them lets a typo in an event id read
as a policy regression.
