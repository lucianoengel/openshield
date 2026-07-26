package clipboard

import "fmt"

// Capabilities is what clipboard control ACTUALLY obtained on the running display server.
//
// It exists because "clipboard DLP" reads as one feature and is not: X11 and Wayland give fundamentally
// different powers, and the difference is not an implementation gap that a later release closes. Reporting
// a capability we do not have would be the overclaim this project's review rounds exist to catch, so the
// engine logs this at startup and the operator sees exactly what they are getting.
type Capabilities struct {
	// Capture: we can see what was copied.
	Capture bool
	// SourceAttribution: we can identify the application that COPIED.
	SourceAttribution bool
	// DestinationAttribution: we can identify the application that is PASTING, per paste.
	//
	// X11 gives this because every paste is a request that names the requesting window. WAYLAND CANNOT
	// GIVE IT AT ALL: the data-control protocols let a client read and offer clipboard data but never
	// identify the receiving client — deliberate isolation, not an oversight. So on Wayland this is false
	// forever, and destination-aware policy is impossible there.
	DestinationAttribution bool
	// Enforcement: we can prevent a paste from receiving the content.
	Enforcement bool
	// Mechanism names how (e.g. "x11-selection-mediation", "polled-helper").
	Mechanism string
	// Limits are the honest caveats an operator should read alongside the booleans.
	Limits []string
}

// X11MediationCapabilities is the full set: X11's clipboard is owner-mediated, so owning the selection
// yields capture, both attributions, and enforcement at paste time.
func X11MediationCapabilities() Capabilities {
	return Capabilities{
		Capture: true, SourceAttribution: true, DestinationAttribution: true, Enforcement: true,
		Mechanism: "x11-selection-mediation",
		Limits: []string{
			"a clipboard manager that takes ownership after us serves later pastes itself, bypassing " +
				"per-destination policy",
			"transfers beyond the size cap are refused rather than streamed (no INCR)",
			"text targets only (UTF8_STRING/STRING); images, files and rich-text flavors are not mediated",
			"root can stop the agent, as with any host agent (D16)",
		},
	}
}

// PolledHelperCapabilities is what the subprocess backend gives: it can read the clipboard and nothing more.
// It is what Wayland gets, and what an X11 host without XFIXES falls back to.
func PolledHelperCapabilities(display string) Capabilities {
	c := Capabilities{
		Capture: true, SourceAttribution: false, DestinationAttribution: false, Enforcement: false,
		Mechanism: "polled-helper",
		Limits: []string{
			"polled: a copy replaced within one interval is missed",
			"no source attribution, so source EXCLUSIONS (e.g. password managers) cannot be applied",
			"no destination attribution and no enforcement: this observes copies, it does not decide pastes",
			"text only",
		},
	}
	if display == DisplayWayland {
		c.Limits = append(c.Limits,
			"Wayland CANNOT provide destination attribution at any point in future: the data-control "+
				"protocols never identify the client receiving a paste",
			"requires the compositor to implement wlr-data-control or ext-data-control; several do not")
	}
	return c
}

// Summary is a one-line, non-overstated rendering for a startup log.
func (c Capabilities) Summary() string {
	return fmt.Sprintf("mechanism=%s capture=%v source-attribution=%v destination-attribution=%v enforcement=%v",
		c.Mechanism, c.Capture, c.SourceAttribution, c.DestinationAttribution, c.Enforcement)
}
