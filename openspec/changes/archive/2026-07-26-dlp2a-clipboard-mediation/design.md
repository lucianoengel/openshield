## Context

Increment 1 (D246) polls `xclip -o`/`wl-paste` through a subprocess and emits an event. It cannot see who
copied, cannot see who is pasting, and cannot stop anything.

How commercial endpoint DLP gets those properties: on Windows, a clipboard-format listener plus **injection
into applications** to intercept `GetClipboardData`, so the agent sits between the paste and the data. There
is no supported equivalent on Linux — but X11 does not need one, because its clipboard is already mediated:

- The CLIPBOARD "selection" has an **owner** (a window). There is no clipboard buffer in the X server.
- A paste is a **request to the owner**: the requestor sets a property on its own window and sends
  `SelectionRequest`; the owner writes the data and replies `SelectionNotify`.
- Every `SelectionRequest` carries the **requestor window id**, which resolves to a PID via `_NET_WM_PID`.
- `XFIXES` delivers `SelectionOwnerNotify` when ownership changes — a copy, observed the instant it happens.

So on X11, **owning the selection is the enforcement point**, and it comes with source and destination
attribution for free. That is the same *architecture* as commercial DLP (mediate the transfer, decide per
destination) implemented through the mechanism the platform actually offers.

Wayland is different by design: `wlr-data-control`/`ext-data-control` let a client read the selection and
offer its own, but the protocol **never identifies the requesting client**. Destination-aware policy is
therefore impossible on Wayland — not hard, impossible — and that asymmetry is a fact to report, not a gap
to hide.

## Goals / Non-Goals

**Goals:** event-driven capture; source attribution; destination attribution and per-destination decisions
on X11; enforcement at paste time; exclusions applied before the content is read; honest per-protocol
capability reporting.

**Non-Goals:** application injection; RDP/Citrix virtual channels; non-text flavors; defeating root; INCR
streaming for very large transfers.

## Decisions

### D-1: Mediate the selection rather than hook applications

The engine becomes an X11 client that takes CLIPBOARD ownership after a copy and serves subsequent paste
requests.

*Alternative: keep polling and "neutralize" by clearing the clipboard when content is sensitive.* Rejected
as the primary design — it destroys the user's clipboard for legitimate destinations, which is exactly the
behavior that gets DLP products disabled by users. Per-destination release is the whole point.

*Alternative: LD_PRELOAD interception of Xlib in every application.* Rejected: fragile, defeated by static
linking and non-Xlib clients, and it puts our code inside every process on the desktop.

### D-2: One dependency, `github.com/jezek/xgb`, and why it is worth it

Pure Go, no cgo, BSD-3. It keeps D8 (all-Go) and cross-compilation intact; the package is Linux-guarded so
no other platform's build changes.

This is a deliberate departure from the project's dependency minimalism, recorded as such: mediation is
**not implementable** through subprocess helpers. `xclip`/`wl-paste` can read and can take ownership, but
they cannot answer a `SelectionRequest` per requestor — which is precisely the capability that separates
observation from enterprise-grade control.

**Security note, stated rather than assumed:** this makes the engine parse X11 protocol from the X server.
The X server is a trusted peer relative to the session, but other clients influence event contents (window
ids, property data). The engine is the unprivileged half (the privileged agent must never gain this
dependency, and CI enforces its budget), and the parsing is bounded by the library plus our own caps.

### D-3: The decision is asked at REQUEST time, not at copy time

On copy: capture, classify once, cache the classification with the content.
On each paste request: resolve the requestor to an application and ask the policy with (classification,
source app, destination app). Serve or refuse accordingly.

Deciding once at copy time would collapse the destination dimension — the thing that makes clipboard DLP
useful rather than noisy. Classifying once and reusing the result keeps the per-paste cost at a policy
evaluation, not a re-scan.

### D-4: Exclusions run before the read, not after

The exclusion check uses the **source application** from the ownership-change event, so an excluded app's
copy is never read into our address space. A post-hoc filter would still have read the password.

Password managers are excluded by default (`keepassxc`, `bitwarden`, `1password`, `gnome-keyring`, `pass`,
`seahorse`, …) with an operator-extensible list. Defaulting to "read everything" for a monitor that sees
every copy is not a defensible starting point.

### D-5: Fail-open, loudly — a monitor must never break the clipboard

If ownership cannot be taken, if the X connection drops, or if the mediator stops, the clipboard must keep
working: we relinquish ownership and let the original owner or the next writer have it. A DLP agent that
leaves the selection owned by a dead handler makes paste hang or return nothing everywhere — the desktop
equivalent of the exec gate wedging exec (D17), and the same answer applies.

### D-6: What is proven where

The X11 protocol work is testable for real, headlessly, on the rooted VM under `Xvfb`:

- a real copy by a real client (`xclip -i`), captured event-driven via XFIXES;
- a real paste by a *separate* real client (`xclip -o`) served or refused by our mediator;
- destination attribution asserted against the requesting process.

That is an end-to-end proof of the actual enforcement claim, not a simulation. Wayland's partial capability
set is asserted by unit tests over the capability reporter, since the protocol path cannot be exercised
without a compositor.

## Risks / Trade-offs

- **A clipboard manager competes for ownership.** Most desktops run one; it will take ownership after us and
  serve later pastes itself, bypassing per-destination policy. Detected (we see ownership move) and
  reported; not prevented. This is the single biggest practical limit and it belongs in the deployment
  guidance, not in a footnote.
- **Ownership churn.** Taking ownership after every copy is visible to other clients and can confuse
  applications that track the owner. Mitigated by taking ownership only when a copy is classified as
  sensitive — a non-sensitive copy is left alone entirely.
- **INCR not implemented:** a transfer beyond the cap is refused rather than streamed. A user pasting a very
  large sensitive blob gets a denial; documented.
- **The X connection is another failure surface** in the engine. Bounded by fail-open (D-5) and by keeping
  the mediator in its own goroutine with its own connection.
- **Wayland asymmetry** will confuse operators who read "clipboard DLP" as one feature. The capability
  report is the mitigation, and the proposal states it plainly.

## Migration Plan

Increment 1's polled backend stays for Wayland and for X11 hosts where XFIXES is unavailable, so behavior
degrades rather than disappears. Mediation is opt-in via configuration; with it off, D246's behavior is
unchanged.

## Open Questions

- Should we take ownership *before* classification finishes (holding the paste) rather than after? It would
  close the race where a paste happens during classification, at the cost of latency on every copy. Needs a
  measurement, not a guess.
- Should a denied paste receive empty content or a protocol refusal? Refusal is more honest; some toolkits
  handle it worse. Start with refusal, revisit with real applications.
