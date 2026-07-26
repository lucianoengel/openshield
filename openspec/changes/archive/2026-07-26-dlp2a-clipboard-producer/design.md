## Context

Verified at `HEAD`:

- `engine.SetContentResolver(ContentResolver)` exists, is documented for ENG-1 (an SMTP body), and **has no
  callers**. `classifyStage.Run` takes it for any event with no `FilesystemSubject`: if the resolver yields
  bytes, it classifies them in the worker via `ClassifyRequest_Content`; otherwise the event is classified
  metadata-only. That is exactly the path a clipboard event needs.
- `internal/exfil` computes `Channel` from a **path** (`Classify(p string)`), so it has no way to express a
  channel for a pathless event.
- `EventKind` has no clipboard member. The closed-enum guard in `internal/core/schema_test.go` covers
  **`Action`**, not `EventKind` — deliberately, since D14's threat is an open *action* surface. Adding a
  producer's event kind is the sanctioned way a capability arrives (D26).
- `TestEventHasNoUnexpectedBytesFields` walks the whole Event tree and fails on any bytes field not in a
  two-entry allowlist. A clipboard subject with no bytes field keeps it green untouched.
- Host tooling: `xclip`, `wl-paste`, `wl-copy` are present locally; **no Xvfb**. The rooted VM
  (Ubuntu 24.04, headless) now has `Xvfb`, `xclip` and `wl-clipboard` installed, so a real-display test can
  run there.

## Goals / Non-Goals

**Goals:** capture clipboard changes; classify the content in the worker; keep the event content-free; make
the clipboard an exfil channel; bound and dedupe; disable loudly when unusable.

**Non-Goals:** blocking a paste, event-driven capture, non-text flavors, Windows/macOS, print (DLP-2b),
screenshots/OCR.

## Decisions

### D-1: Subprocess clipboard helpers, not in-process display bindings

Wayland reads via `wl-paste --no-newline --type text/plain`; X11 via `xclip -selection clipboard -o`.

*Alternatives:* a pure-Go X11 client (`xgb`) or cgo bindings. Rejected for this increment: both add a
dependency and put display-protocol parsing inside the engine process, and the repo already has the
precedent for shelling out to a privileged-ish helper (`nft`/`iptables` in the gateway). A subprocess also
gives a natural bound — we read its stdout with a cap and kill it on timeout.

The cost is honest: the host must have the helper installed, and each poll costs a fork+exec. Both are
stated in the proposal.

### D-2: Polling, with the interval as the operator's knob

A ticker reads the clipboard; a change is detected by comparing a digest of the content with the last one.

*Alternative: event-driven.* X11 has XFIXES selection-owner notifications, but consuming them means an
in-process X11 connection (D-1's rejected option). Wayland's `wl-paste --watch CMD` runs a command per
change — a process per copy, and a long-lived child whose lifecycle we would have to supervise. Both are
real improvements and both are deferred rather than half-built; the miss window (a copy replaced inside one
interval) is documented, not hidden.

### D-3: The digest is dedup state and nothing else

Change detection hashes the content (SHA-256) and keeps only the digest in memory.

This needs saying explicitly because the project's own rules forbid hashing as a privacy control for
transmitted low-entropy PII (D10/D11): a hash of a CPF is brute-forceable, so it must never leave the host.
Here the digest never leaves the *process*, is never logged, and is never a field on any message. It is the
same role as a file's mtime in a FIM baseline — local state to answer "did this change?".

### D-4: A keyed content store that CHAINS, rather than owning the resolver

`SetContentResolver` holds ONE function. The clipboard producer installs a store that looks up the event id
and, on a miss, delegates to whatever resolver was already installed.

Overwriting would work today (nothing else uses it) and would silently break the first time a second
producer — the SMTP body path the seam was written for — arrives. That failure mode would be a lost
classification with no error, so the chaining behavior gets its own test.

The store is bounded (a small map with a cap) and an entry is **deleted when resolved**, so a producer
cannot grow memory without limit and a stale entry cannot answer a later event.

### D-5: The channel comes from the event kind, not from a path

`exfil.Channel` gains `ChannelClipboard`, and the policy mapping assigns it by KIND rather than calling
`Classify(path)` — a clipboard copy has no path, and inventing one (`"clipboard://"`) to feed the path
classifier would be a fake filesystem entity that other code would eventually try to open.

### D-6: What is real in each test, stated per test

- The **pipeline** test fakes only the `Reader` (the OS seam) and runs the real producer, real classify
  stage, real worker and real policy. It is where the shipped claim lives.
- The **real-display** test runs on the rooted VM under `Xvfb`: `xclip -i` sets a real X11 clipboard and the
  real X11 backend reads it back. It is gated (skips without a display) and therefore cannot run in ordinary
  CI or on this workstation — so it strengthens the claim rather than carrying it.

## Risks / Trade-offs

- **The engine holds clipboard bytes in memory** to forward them. Unavoidable for any clipboard DLP that
  classifies content; the mitigation is that the parser is in the sandboxed worker (D71) and the bytes are
  released after resolution. Stated as a trade, not hidden.
- **Fork+exec per poll** is measurable overhead on a busy desktop. Mitigated by the interval being the
  operator's knob and by the producer being off by default; a lighter capture path is D-2's deferred work.
- **A helper binary is attacker-influenceable in principle** (PATH). The producer resolves the helper with
  `exec.LookPath` at start and reports what it found, so a surprising path is visible rather than implicit.
- **Truncation can split a match** at the cap boundary, so a detection can be missed on a very large copy.
  Accepted — the alternative is an unbounded read in a process that forwards to another process.
- **Polling misses fast replacements.** Documented; the interval is the trade.

## Migration Plan

None: additive and off by default. Enabling it needs `OPENSHIELD_CLIPBOARD_INTERVAL` plus a display and a
helper binary. Proto addition is backward-compatible (a new kind and a new oneof member); an older consumer
sees an unknown kind and no target it recognizes.

## Open Questions

- Should a clipboard copy be attributable to the *application* that copied it? X11 gives the selection
  owner's window, Wayland deliberately does not. Deferred — attribution asymmetry across display servers
  needs its own decision.
- Should paste (not just copy) be observed? A paste is where content leaves the boundary, but it is
  observable only inside the receiving application. Out of scope and probably needs a different mechanism.
