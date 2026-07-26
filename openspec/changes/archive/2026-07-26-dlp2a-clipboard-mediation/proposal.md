## Why

DLP-2a increment 1 (D246) watches the clipboard. That is not what enterprise DLP does.

Real endpoint clipboard control (Purview Endpoint DLP, Forcepoint, Symantec, Digital Guardian) does four
things this does not:

1. it is **event-driven**, not polled;
2. it knows **which application copied**;
3. it knows **which application is pasting**, and decides per destination — "block paste of classified data
   into a browser or into an RDP/Citrix redirected clipboard" is the canonical rule;
4. it **prevents the paste**, synchronously, rather than reporting afterwards.

The exfiltration happens at **paste**, not at copy, and "someone copied a CPF" is a noisy signal on its own
— users copy sensitive data legitimately all day.

There is also a defect to fix: increment 1 reads **everything** the user copies, including every password
copied out of a vault, and forwards it to the classifier. The platform has exclusion lists as a first-class
policy primitive (D20/L1) and the clipboard producer does not apply them.

X11 makes real mediation possible without injecting into applications, because the clipboard is
**owner-mediated**: the process that owns the CLIPBOARD selection serves every paste request, and each
request names the requesting window. Owning the selection *is* the enforcement point.

## What Changes

- **The producer becomes a MEDIATOR.** It takes ownership of the CLIPBOARD selection and answers paste
  requests itself. That single change turns observation into enforcement and gives destination visibility,
  using the mechanism X11 actually provides rather than hooking applications.
- **Event-driven capture** via the XFIXES `SelectionOwnerNotify` event — a copy is seen when it happens, not
  up to one poll interval later, and the polled backend is retired for X11.
- **Source attribution:** the selection owner's window → `_NET_WM_PID` → the copying process's executable.
- **Destination attribution and per-destination policy:** each `SelectionRequest` names the requestor
  window, which resolves to the pasting process. The policy decides for *that* destination, so the same
  clipboard content can be allowed into an editor and refused into a browser.
- **Enforcement at paste time:** a denied request is answered with a refusal (or empty content), so the
  paste yields nothing. The decision is ledgered like any other enforcement.
- **Exclusions applied BEFORE capture:** a copy from an excluded source (password managers by default, plus
  an operator list) is never read, never classified, and never leaves a record of its content.
- **Honest capability reporting per display server**, replacing increment 1's overstated "X11 + Wayland".

## Capabilities

### Modified Capabilities

- `clipboard-monitor`: becomes clipboard *mediation* — event-driven capture, source and destination
  attribution, per-destination decisions enforced at paste time, and pre-capture exclusions.

## Impact

- **Code:** a new in-process X11 client (`internal/clipboard/x11`) using `github.com/jezek/xgb` — pure Go,
  no cgo, so the all-Go rule (D8) and cross-compilation hold; the polled subprocess path stays as the
  Wayland/fallback backend. Engine wiring gains a decision callback so the mediator can ask the pipeline.
  The privileged agent is untouched and must not gain this dependency (CI already enforces its budget).
- **Decisions:** depends on **D10/D29** (content to the worker, never onto an Event), **D20/L1**
  (exclusions as a first-class primitive), **D14** (the decision is a closed action, not an open command),
  **D17** (fail-open: a mediator that dies must not take the user's clipboard with it), and **D8**
  (all-Go). Adding one dependency is a deliberate departure from the project's dependency minimalism and is
  recorded as such.

### What this change does NOT claim or cover

- **Wayland cannot do per-destination policy, by protocol design.** `wlr-data-control`/`ext-data-control`
  let a client read and offer clipboard data, but Wayland deliberately does not tell an offering client
  *which* client is pasting. So on Wayland this delivers capture, exclusions, classification and
  block-or-allow — **not** destination-aware decisions. That is a protocol limit, stated as one, not an
  implementation gap to be fixed later. Availability also depends on the compositor implementing a
  data-control protocol at all; the producer reports what it actually got.
- **This is not application hooking.** Windows DLP injects into processes to intercept `GetClipboardData`;
  we mediate the selection instead. The practical difference: an application that reads the clipboard
  through a channel we do not own (a compositor-side copy, an X11 client talking to a different display, a
  clipboard manager that already cached the content) is outside our control.
- **A clipboard manager defeats destination policy.** If a clipboard manager takes ownership and caches
  content, later pastes are served by *it*, not by us. Detected and reported; not prevented.
- **It does not cover RDP/Citrix virtual-channel redirection**, which is a first-class case in commercial
  DLP and needs the remote-desktop stack's own hooks.
- **Root can bypass it**, as with every host agent (D16). And an application that already holds the
  content in memory before a policy change is unaffected.
- Increment 1's limits that remain: **text only** (no images, files, rich-text flavors), and no OCR.
- Large transfers use the X11 `INCR` protocol; this implementation refuses rather than streams beyond its
  cap, so a very large paste is denied rather than incrementally served. Stated, not hidden.
