# Design

## The distinction being encoded

Two different questions are being conflated by one command:

- **Integrity** — is this set of files the set that some single signature covers? Answerable from
  the download alone, which is why the current command can answer it.
- **Authenticity** — did the project sign this? NOT answerable from the download alone, ever. It
  requires something the attacker cannot supply: a key the operator got from somewhere else.

No amount of care inside the verifier can close that gap, because the input is entirely under the
attacker's control. So the fix is not a better check; it is admitting a second input.

## `--key` semantics

When `--key` is given, `release-key.pub` in the release directory is **not read at all**. Falling
back to it on any condition — unreadable pin file, size mismatch, mismatch between the two — would
reintroduce the whole gap through the error path, and an attacker who can modify the download can
usually arrange the condition. A bad `--key` is a hard failure.

When both are present and DIFFER, that is not a warning: it is the exact signal the flag exists to
produce, and the command refuses.

## Why the unpinned path stays, and stays loud

Removing the unpinned path would make the command unusable for the case it is mostly used in today:
checking that a download did not get corrupted, before an operator has any key at all. That check is
worth having. What is not worth having is an operator believing they got more than they did.

So the unpinned path prints, to stderr, what was and was not established, and how to pin. This
follows D31 (a gap must never be silent) and D50/D51 (silence is not compliance) — the same rule
already applied to the plaintext syslog stream listener, which announces that its sender is not
authenticated.

Exit status is unchanged for the unpinned path: it is a successful integrity check, and turning it
into a failure would break every existing caller for a limitation they may already have accepted.

## Fingerprint rather than the key

`verified ... with key <first 16 hex of SHA-256 of the public key>` — full keys in terminal output
are unreadable and get copied wrongly. A fingerprint is comparable at a glance, and the value being
compared is one an operator can also compute from the key file they were given.

## Honest limits, restated so they are not rediscovered as bugs

- **Key distribution is out of scope.** How the operator gets the real key (the project website, a
  package repository, a colleague) is where the trust actually lives, and this change does not
  improve it. It gives them somewhere to USE the key they obtained.
- **Reproducibility is a separate claim.** A pinned signature proves the project signed these bytes,
  not that these bytes correspond to the source. That is the rebuild, and it is PLAT-6's other half.
- **Keyless/transparency-log signing (Sigstore) remains the better answer for public distribution**,
  and remains a different trust decision rather than a bigger version of this one.
