package controlplane

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// THE VIEW AUDIT, APPLIED BY DEFAULT (CONSOLE-5).
//
// docs/threat-model.md bounds the malicious insider holding an operator role with one sentence: "who
// LOOKED is recorded, not only who acted, and the record is written BEFORE the evidence is returned".
// That sentence was true of four routes and false of the console's primary ones. `/alerts`, `/search`,
// `/events`, `/logs`, `/searches/run`, `/incidents`, `/incidents/recurrences` and `/entities` recorded
// nothing — so an analyst could search the fleet aggregate for a named host, read the ingested
// third-party log store and page the entity graph, and the accountability table stayed empty.
//
// THE DEFECT IS THE SHAPE, NOT THE EIGHT MISSING ROWS. Recording was written by hand inside each
// handler, which means a handler written later by someone with no reason to know the invariant exists
// silently does not record. The read surface grew from four routes to more than twenty exactly that
// way. Doing it eight more times would fix today's list and reproduce the defect for CONSOLE-28's bulk
// export, which is "scroll the fleet and leave nothing" with a download button.
//
// So the decision is inverted: ONE wrapper around the whole operator read mux, and a path that is named
// in no table below is RECORDED. Not recording is the case that costs somebody a sentence in
// viewAuditExempt naming the residual it accepts. A route added next month is audited by default and by
// construction, which is the only version of this that survives the people who come after it.
//
// It sits INSIDE the tier gate, so the principal requireGrant resolved is on the context — the identity
// recorded here is the same one the handler would attribute an act to. Deriving a second identity from
// the connection is what CONSOLE-1 exists to remove, and it answers "" for a bearer-authenticated
// operator, which is the sign-on path a console uses.

// viewAuditedInHandler are paths whose HANDLER records the view, so the wrapper must not record a
// second row for the same read (a doubled row makes "how often did this operator look" wrong).
//
// These are not exemptions — they are audited, and better than the wrapper could manage: each knows a
// subject the URL does not carry. `/cases?id=7` records the case's SUBJECT, which is only known after
// the row is loaded; `/subject` and `/incidents/timeline` likewise. Moving them to the wrapper would
// trade a subject id for a query string and break the join that answers "who looked at me".
var viewAuditedInHandler = map[string]string{
	"/view":               "records the event id it serves (D56)",
	"/views":              "records the officer's own read of the audit — nobody is above the record (D470)",
	"/subject":            "records the DSAR against the subject id (PLAT-8)",
	"/cases":              "records the case's subject, known only after the case is loaded (D20)",
	"/incidents/timeline": "records incident:<id> as the subject filter (XDR-5)",
}

// viewAuditExempt are read paths deliberately NOT recorded, each with its reason and the residual it
// accepts. The criterion applied to every one of them:
//
//	A read is evidence-bearing when what it returns — or narrows to — is what the platform holds about a
//	person, an entity, or an endpoint's activity. A read of the platform's OWN state is not.
//
// Two of these are uncomfortable and are written down as such rather than argued away.
var viewAuditExempt = map[string]string{
	"/health": "the control plane's own liveness report; it names no subject and no endpoint's activity",
	"/logs/fields": "the vocabulary /logs accepts — schema, not rows. Residual: it reveals which vendors " +
		"feed the store",
	"/compliance/retention": "the record of purges the platform ran against itself",
	"/report/response":      "MTTA/MTTR aggregates across incidents, with no per-subject rows",
	"/searches": "the saved-search inventory: names, authors, descriptions. RESIDUAL, AND IT IS A REAL " +
		"ONE: a saved search's stored query can itself name a subject, so reading the list shows what " +
		"colleagues are hunting for and leaves no trace. Bounded by: the author is recorded on the row, " +
		"and RUNNING one — the read that returns the rows — is audited",
	"/approvals": "the four-eyes queue. It names the intents' target agents, but the queue exists to be " +
		"read by somebody other than the requester, and every resolution is itself recorded — auditing " +
		"the oversight surface would discourage the oversight",
	"/fleet": "fleet operational state: enrolment, revocation, silence, the agent's own enforcement " +
		"report. RESIDUAL: a list of which endpoints are not enforcing is a target list for the insider " +
		"the threat model names, and reading it leaves nothing. Deliberate — it says nothing about a " +
		"person, and CONSOLE-8 argued this tier boundary in the open",
	"/fleet/controls": "the break-glass register — oversight of an action two named people already took " +
		"under four-eyes",
	"/overdue": "the same fleet state as /fleet, expressed by absence instead of by suppression; the " +
		"same residual and the same reason",
	"/config": "the deployment's own configuration. RESIDUAL: reading which detections are disabled is " +
		"reconnaissance and it is unrecorded. Bounded by: admin tier only, and every config CHANGE is a " +
		"recorded revision with an author",
	"/config/schema":    "which knobs exist — a description of the product, not of anyone",
	"/config/revisions": "the history of configuration changes, each already attributed to its author",
}

// maxViewQueryLen bounds the recorded query. It is operator-controlled text written into an audit table
// on every request: uncapped, it is a write amplification an authenticated insider controls. The
// truncation is MARKED in the stored value — a silently shortened audit record is worse than a bounded
// one, because a reader would believe a partial record complete.
const maxViewQueryLen = 512

// viewQueryTruncated is appended to a query that did not fit. Part of the stored value, deliberately.
const viewQueryTruncated = "…(truncated)"

// canonicalViewQuery renders a request's query string for the audit: parameters sorted by name, values
// preserved, so two spellings of one search compare equal in the record. A console that reorders its
// parameters between releases must not make yesterday's search look like a different one.
func canonicalViewQuery(v url.Values) string {
	if len(v) == 0 {
		return ""
	}
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		for _, val := range v[k] {
			if b.Len() > 0 {
				b.WriteByte('&')
			}
			b.WriteString(url.QueryEscape(k))
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(val))
		}
	}
	q := b.String()
	if len(q) > maxViewQueryLen {
		return q[:maxViewQueryLen] + viewQueryTruncated
	}
	return q
}

// viewAudited wraps the operator read mux so a read is recorded BEFORE it is served.
//
// Only GET and HEAD are recorded. Every mutating route on this surface already produces an attributed
// record of its own — a case note carries its author, an approval both pairs of eyes, an intent its
// publisher, a config change its revision — and writing a view row for those as well would make
// investigation_views a partial, second-class duplicate of the act log that drifts from it (one is
// written before the act, the other after). RESIDUAL: a read implemented as POST would escape this.
// There is none today (`/searches/run` is a GET); nothing enforces that it stays so.
func (s *Server) viewAudited(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			h.ServeHTTP(w, r)
			return
		}
		if _, inHandler := viewAuditedInHandler[r.URL.Path]; inHandler {
			h.ServeHTTP(w, r)
			return
		}
		if _, exempt := viewAuditExempt[r.URL.Path]; exempt {
			h.ServeHTTP(w, r)
			return
		}
		viewer := operatorIdentity(r.Context())
		if viewer == "" {
			// IMPOSSIBLE PAST THE TIER GATE, and that is why it is a 500 rather than a 401: reaching
			// here without a principal means this wrapper was mounted outside requireGrant, which is a
			// wiring bug and not an authorization outcome (see principalFrom). Serving the read anyway
			// would be an unaudited read caused by a mistake in a file nobody edits.
			http.Error(w, "internal error: read reached the view audit with no authenticated principal",
				http.StatusInternalServerError)
			return
		}
		// RECORD, THEN SERVE. The handler is not called when the record fails — an operator who can make
		// the recording fail and still receive the evidence has an unaudited read, which is precisely
		// what this boundary forbids. The cost is accepted and stated: a database that can serve reads
		// but not accept this INSERT takes the console's read surface down. That is the correct
		// direction of failure for an accountability control, and it is the trade /cases and /subject
		// have made since D20.
		if err := s.recordViewDetail(r.Context(), ViewRecord{
			Viewer: viewer,
			// The subject a search NAMED, where the surface has one. It is what the DSAR joins on, so
			// only a genuine subject id in the DSAR's namespace belongs here — an agent id or an entity
			// alias goes in the query, where it cannot produce a false match.
			SubjectFilter: strings.TrimSpace(r.URL.Query().Get("subject")),
			EventID:       strings.TrimSpace(r.URL.Query().Get("event")),
			Route:         r.URL.Path,
			Query:         canonicalViewQuery(r.URL.Query()),
		}); err != nil {
			http.Error(w, "recording the view failed; refusing to serve the read",
				http.StatusInternalServerError)
			return
		}
		h.ServeHTTP(w, r)
	})
}
