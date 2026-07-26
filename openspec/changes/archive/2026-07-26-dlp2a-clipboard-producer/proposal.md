## Why

The platform watches file writes, removable media and cloud uploads, and does not watch **copy-paste** —
the most-used exfiltration channel on a desktop. "Not a DLP without the exfil channels" is the roadmap's
own standard, and the clipboard is the largest hole in it.

The seam to close it already exists and is unused: `engine.SetContentResolver` (ENG-1) lets a non-file
event supply bytes that the classify stage sends to the **sandboxed worker** as inline content, so the
engine forwards bytes without parsing them (D29/D71 — the model the gateway already uses for request
bodies). Nothing calls it today.

## What Changes

- **A clipboard producer** on the endpoint engine: on a change to the clipboard, it emits a content-free
  `Event` and makes the copied bytes available to the classify stage, so a sensitive copy is classified and
  policy-gated like any other detection.
- **The Event contract gains a clipboard shape:** `EVENT_KIND_CLIPBOARD_COPY` and a
  `ClipboardSubject { byte_count, display_server }`. Both content-free — a size and `"x11"`/`"wayland"`.
  No bytes field, so the Event-carries-no-content guard needs no allowlist change.
- **The clipboard becomes an exfil channel.** `internal/exfil` gains `ChannelClipboard` and the policy
  mapping tags clipboard events with it, so an existing channel-aware policy gates copy-paste the same way
  it gates a cloud-sync write.
- **A `Reader` seam with two Linux backends** (`internal/clipboard`), shelling out to `wl-paste` (Wayland)
  or `xclip` (X11) — the same subprocess discipline already used for `nft`/`iptables`, so no new Go
  dependency and no X11 bindings inside the process. Display server is detected from the environment;
  with no display or no helper binary the producer **disables itself loudly** rather than appearing to work.
- **Bounded and deduplicated:** a hard read cap (a clipboard can hold megabytes) and change detection so
  the same clipboard content is not re-reported every poll.

## Capabilities

### New Capabilities

- `clipboard-monitor`: reading the clipboard through a replaceable OS seam, detecting changes, bounding the
  read, and emitting a content-free clipboard event whose content reaches only the sandboxed classifier.

### Modified Capabilities

- `event-contract`: adds the clipboard event kind and its content-free subject shape.
- `exfil-channel-awareness`: the clipboard is a first-class exfiltration channel alongside removable media
  and cloud sync.

## Impact

- **Code:** `proto/openshield/v1/event.proto` (+ generated), new `internal/clipboard`, `internal/exfil`
  (one channel), `internal/policy` (channel mapping for the new kind), `cmd/openshield-engine` (an
  env-gated producer + a keyed content store chained into the resolver). No change to the frozen core, the
  Action set, the ledger, or the privileged agent — which is not involved at all.
- **Decisions:** depends on **D10/D29** (the Event carries metadata only; content goes to the worker),
  **D71** (the process that holds the bytes is not the process that parses them), **D194** (the exfil
  channel model), **D26** (a capability arrives as a producer, not a core change), and **D13** (the
  privileged binary stays out of this entirely). It establishes no new decision.
- **Deployment:** needs `wl-paste` or `xclip` present, and a session with a display. Neither is required
  for the engine to run — the producer just stays off.

### What this change does NOT claim or cover

- **It is polled, so a copy replaced within one interval is missed.** Event-driven capture needs in-process
  XFIXES bindings (X11) or a process-per-change `wl-paste --watch` (Wayland); both are deferred.
- **Text only.** Images, files and rich-text flavors are not read, so copying a screenshot or a file
  selection is invisible to it.
- **The engine process holds the clipboard bytes in memory** to forward them to the sandboxed worker. The
  parser stays in the worker, and the privileged agent never sees them — but this is not a claim that the
  bytes exist nowhere outside the sandbox. It is the same trade the gateway already makes for bodies.
- **The change-detection hash is local-only dedup state.** It is never emitted, logged or transmitted.
  D10/D11 forbid treating a hash as a privacy control for transmitted low-entropy PII, and this is not
  that — the distinction is worth stating because the code contains a SHA-256 of clipboard content.
- **It does not block a paste.** Observe and alert only; inline clipboard prevention is not in this ticket.
- It does **not** cover the print channel (DLP-2b), Windows/macOS (PLAT-7 enrichment), screenshots, or OCR.
- A clipboard read requires access to the user's session. A copy made in a session the engine cannot reach
  (another user, a different seat, a locked-down compositor) is not observed.
