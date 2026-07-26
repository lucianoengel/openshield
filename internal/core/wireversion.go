package core

// The signed-message wire contract, and the upgrade order it implies (PLAT-9).
//
// Every signed message this platform publishes carries an explicit VERSION, and every consumer REJECTS a
// version it does not understand rather than partially applying it. That is the right failure direction —
// a containment or a fleet disable is the last thing to guess at — but it has a consequence operators
// must know, because it is not obvious and it bites during an upgrade:
//
//	CONSUMERS MUST BE UPGRADED BEFORE PUBLISHERS.
//
// A control plane that publishes vN+1 to endpoints still running vN gets its messages rejected by every
// one of them, silently as far as the publisher is concerned. Upgrading endpoints first is safe: a vN+1
// consumer accepts vN, because the accepted set is a RANGE and the produced version is a point inside it.
//
// The constants live here rather than as literals at each check for a plain reason: there were two
// hardcoded `GetVersion() != 1` comparisons in different packages, and a third would eventually disagree
// with the other two. A version rule spelled in three places is a version rule that has three answers.
const (
	// WireVersion is what this build PRODUCES for signed messages.
	WireVersion uint32 = 1
	// MinAcceptedWireVersion is the OLDEST version this build accepts. Accepting a range is what makes
	// "upgrade consumers first" a safe order rather than a coordinated flag day.
	MinAcceptedWireVersion uint32 = 1
)

// AcceptsWireVersion reports whether this build understands a signed message's version.
//
// Rejecting a NEWER version is deliberate and is not a bug to fix later: a message from a future publisher
// may mean something this build would misapply, and for a containment or a fleet-wide disable, misapplying
// is worse than ignoring. The cost is the upgrade order above, which is documented rather than engineered
// around.
func AcceptsWireVersion(v uint32) bool {
	return v >= MinAcceptedWireVersion && v <= WireVersion
}
