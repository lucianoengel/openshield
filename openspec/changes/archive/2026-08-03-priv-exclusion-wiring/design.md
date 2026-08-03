# Design — PRIV-1 exclusion wiring

## Where it goes, and why there

`Engine.Process` — before `Dispatch`, after nothing.

Every endpoint producer funnels through it: the fanotify path via `processOne`, the print source, the
SMTP source, the clipboard mediator, the exec gate's evaluator. Putting the check anywhere further out
would mean repeating it per producer, and the one a future producer forgets is the one that reads the
personal folder.

Putting it *inside* `Process` and *before* `Dispatch` is what makes the spec's claim true rather than
approximately true: content resolution happens in the classifier, which `Dispatch` invokes. Return
before that and the bytes are never read. "The honest way not to surveil something is not to look at
it" is a statement about the classifier, so the check has to be upstream of it.

It deliberately does **not** live in the privileged agent. That would be stronger — the event would
never be constructed at all — and it is not available: the privileged process must not parse or reason
about attacker-influenced paths (D13), and evaluating a prefix list against a path is exactly the kind
of work that boundary exists to keep out. The residual is honest and small: the event struct exists in
the unprivileged engine's memory for the length of one function call, is never read, and is never
recorded anywhere.

## Enforcement is never excluded, and the spec says why

The requirement ends with:

> The operator owns the exclusion list, so it is a privacy control, not a user-invokable DLP evasion.

Applying an exclusion to a permission event breaks that sentence. An exec gate that returns "no
decision" resolves to ALLOW — it must, or the process hangs — so a break-time window would become a
nightly interval in which any binary runs unblocked, reachable by any user who can wait until 12:00.
The same holds for the clipboard mediator, where a suppressed decision means the paste proceeds.

So the rule is: **an exclusion suppresses observation, never a verdict.** `Process` distinguishes the
two by whether the caller is asking for a verdict it will act on, which the engine already knows —
the permission paths call `Process` for a Decision they hand to the kernel or to the mediator, while
the observation paths call it to record.

Rather than infer that from the event, the engine takes it as an explicit argument at the seam:
`ProcessObserved` is the excludable entry, `Process` stays the verdict entry, and the observation
producers are the ones moved onto the new name. A future producer that calls `Process` gets the
non-excluded behaviour, which is the safe default for a privacy control that must not become an
evasion — the failure mode of forgetting is "we observed something we could have excluded", not "an
attacker found a hole".

## The path-less identity forms

`docs/spike-t005-fanotify.md` established that two of the three subject identity forms carry no path:
`FAN_REPORT_FID` gives a file handle, and the parent+name form gives a directory handle and a name.
`core.ResolvedPath` returns `ErrPathUnavailable` for both, deliberately, so a consumer cannot mistake
a missing path for an empty one.

A path exclusion therefore cannot be evaluated for those events. Three options, and only one is
honest:

- **Exclude them** — fail-closed for privacy. An insider who can trigger the path-less form gets a
  blind spot; worse, the blind spot is invisible.
- **Observe them silently** — fail-open for detection. The operator believes personal folders are
  unobserved. This is a false statement to a works council.
- **Observe them, and count the fact that the exclusion could not be applied.** The detection
  behaviour is the safe one, and the privacy claim degrades to something that can be stated
  accurately: *"excluded where the path is known; where it is not, the exclusion could not be applied,
  and here is how often that happened."*

The third. `Engine.ExclusionsUnevaluable` counts it, and the engine says at startup that path
exclusions require a coverage mode that yields resolved paths.

Time windows have no such problem — a window needs only the event's timestamp, so it applies to every
observed event regardless of identity form. That asymmetry is worth stating rather than glossing: the
break-time control is complete, the personal-folder control is conditional on coverage mode.

## Window parsing, validated at load

`HH:MM-HH:MM`, comma-separated. Refused: a malformed time, an end at or before the start, an
out-of-range hour or minute.

Refused rather than skipped, for the reason the escalation ladder and the hunt file are both refused:
a silently-dropped exclusion is a control the operator believes is on. There is no partial success
here — the process starts with no exclusions and says why, rather than with some of them.

A window that crosses midnight (`23:00-02:00`) is refused too, with its own message, because
`TimeWindow.contains` is a half-open `[start, end)` comparison on minutes-since-midnight and would
silently match nothing. Splitting it into two windows is the operator's call to make explicitly, not
something to infer.

## Contradiction check

One, and it is recorded rather than reconciled: the shipped requirement says "The producing path MUST
NOT emit an event", with no carve-out for enforcement. This change adds the carve-out as a new
requirement, deriving it from the same requirement's own "not a user-invokable DLP evasion" clause. A
human should confirm that reading. The alternative — applying exclusions to the exec gate — is
recorded here so the choice is visible and reversible, not buried.
