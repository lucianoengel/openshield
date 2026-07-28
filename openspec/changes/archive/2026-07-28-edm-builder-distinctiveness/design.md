# Design

## The whole change is deleting a loop

`buildEDM` stops constructing the index itself and calls the library function that already implements
the requirement. There is no new logic, no new threshold, and no new flag: `distinctiveEDM` and
`MinEDMTokenLen` already exist and are already unit-tested.

That is deliberate. The temptation with a finding like this is to improve the filter at the same time
— tune the threshold, add an entropy term. Doing that here would mean the fix and a behaviour change
land together and neither can be reviewed on its own.

## Refusing an empty index, and why it is a refusal rather than a warning

The `record` builder already fatals when nothing distinctive survives. The EDM builder should behave
the same, and the reason is stronger than symmetry: an index over zero values **matches nothing**. A
worker loads it, reports the EDM detector as configured, and cannot ever produce a hit. That is the
failure this project keeps finding under a different name — a control that reports itself enabled and
is inert — and the moment it is detectable is at build time, in front of the operator who chose the
column.

A warning would be printed into a build log nobody reads afterwards. A non-zero exit stops a pipeline.

## Reporting the skipped count even when the build succeeds

A column where 3 of 5000 values are distinctive builds an index successfully and protects almost
nothing. The count is the only signal that this happened, and it belongs on stderr next to the
success message rather than behind a verbose flag — the operator who most needs it is the one who did
not think to ask.

## What this does NOT change

- **Existing indexes.** They are signed artefacts and are loaded as-is; nothing revokes or rebuilds
  them. An operator rebuilding will get a smaller index, and the skipped count tells them why.
- **The filter's definition.** `distinctiveEDM` keeps anything containing a digit, requires
  `MinEDMTokenLen` normalised characters, and treats a short purely-alphabetic value as a dictionary
  word. Whether those are the right rules is a separate question from whether the shipped tool
  applies them.
- **The record and document builders.** They already filter.
