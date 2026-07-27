package controlplane

import (
	"errors"
	"net/http"
	"strings"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// The OPERATOR SURFACE for RESPONSE INTENTS (D291, SOAR-7 Tier-2).
//
// `PublishIntents`, `RequestIntentApproval` and `SetIntentBlastRadius` all existed, were tested, and had
// no caller anywhere. The consequence was worse than dead code: the IdP RESPONDER — the consumer that
// verifies an intent and disables an account — WAS wired and running, listening on a subject nothing in
// the product could publish to. A verifier with no possible signer is not a security control; it is an
// inert one that reads as a working one.
//
// TWO STEPS, forced by the gate rather than chosen. A high-impact intent's four-eyes approval is bound to
// an INTENT ID derived from the verb, the subject and the MINUTE it is issued in. An operator therefore
// cannot approve an intent that does not exist yet, and — the sharper problem — a single-step publish
// computes a fresh id from the current clock, so an approval requested at 10:00:59 and granted at
// 10:01:05 binds to an id the publication will never look up. `prepare` returns the id; `publish` sends
// exactly that one.
//
// WHAT THIS SURFACE CANNOT DO, deliberately: it cannot name an arbitrary action. The verb comes from the
// closed IntentVerb vocabulary (D14), and a name outside it is refused here rather than passed through —
// a response surface that accepts an arbitrary operation is an open command channel by another route,
// which is the thing the closed vocabulary exists to make unexpressible.

// intentVerbs is the operator-facing spelling of the closed vocabulary. A map rather than a parse of the
// enum name so the surface's accepted set is written down and testable, and cannot silently grow when a
// new enum value is added for some other purpose.
var intentVerbs = map[string]corev1.IntentVerb{
	"elevate-scrutiny": corev1.IntentVerb_INTENT_VERB_ELEVATE_SCRUTINY,
	"contain":          corev1.IntentVerb_INTENT_VERB_CONTAIN,
	"revoke-trust":     corev1.IntentVerb_INTENT_VERB_REVOKE_TRUST,
}

func intentVerbNames() string {
	names := make([]string, 0, len(intentVerbs))
	for k := range intentVerbs {
		names = append(names, k)
	}
	// Sorted so the error message is stable; an error that reorders itself between calls looks like a
	// different error.
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	return strings.Join(names, ", ")
}

// intentHandlers mounts the response-intent routes.
func (s *Server) intentHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/intents/prepare", s.intentPrepareHandler)
	mux.HandleFunc("/intents/publish", s.intentPublishHandler)
}

// intentPrepareHandler serves POST /intents/prepare?verb=…&subject=…&subject=…&reason=…
//
// It publishes NOTHING. For a high-impact verb it opens one four-eyes request PER SUBJECT and returns the
// ids a second operator must approve; for a low-impact one it returns the ids so the same two-step flow
// works for every verb — one shape an operator learns once, rather than a surface whose steps depend on
// which verb they happened to pick.
//
// SUBJECTS ARE PLURAL, and that is load-bearing rather than convenience. The blast-radius ceiling exists
// to stop a FLEET-WIDE containment, and it is checked where the count is known: on one publication call.
// A surface that could only ever publish one subject per request would make the ceiling unreachable —
// it would be a setting that is read, compared, and can never bind, which is the same class of defect as
// one that is never set at all.
func (s *Server) intentPrepareHandler(w http.ResponseWriter, r *http.Request) {
	op, ok := actor(w, r, http.MethodPost)
	if !ok {
		return
	}
	verb, subjects, reason, ok := intentParams(w, r)
	if !ok {
		return
	}
	at := s.now()
	ids := make([]string, 0, len(subjects))
	approvals := make([]int64, 0, len(subjects))
	for _, subject := range subjects {
		if !HighImpactVerb(verb) {
			ids = append(ids, intentID(subject, verb, at))
			continue
		}
		// ONE APPROVAL PER SUBJECT. A single approval covering a list would mean approving to contain
		// host A also authorized containing host B, which is precisely the (kind, id) binding SOAR-3
		// exists to prevent.
		id, aid, err := s.RequestIntentApproval(r.Context(), verb, subject, op, reason, at)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		ids = append(ids, id)
		approvals = append(approvals, aid)
	}
	resp := map[string]any{
		"intent_ids":  ids,
		"verb":        r.URL.Query().Get("verb"),
		"subjects":    subjects,
		"high_impact": HighImpactVerb(verb),
	}
	if HighImpactVerb(verb) {
		resp["approval_ids"] = approvals
		resp["note"] = "a SECOND operator must approve EVERY approval id before these intents can be published"
	}
	writeJSON(w, resp)
}

// intentPublishHandler serves POST /intents/publish?id=…&reason=…&ttl=…
//
// The id carries the verb, the subject and the issuing minute, so what is published is exactly what was
// prepared — and, for a high-impact verb, exactly what was approved.
func (s *Server) intentPublishHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := actor(w, r, http.MethodPost); !ok {
		return
	}
	raw := r.URL.Query()["id"]
	if len(raw) == 0 {
		http.Error(w, "at least one id is required", http.StatusBadRequest)
		return
	}
	var verb corev1.IntentVerb
	var at time.Time
	subjects := make([]string, 0, len(raw))
	for i, id := range raw {
		v, subject, issued, err := ParseIntentID(strings.TrimSpace(id))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// ONE VERB AND ONE ISSUING MINUTE PER REQUEST. A mixed batch would publish under a single
		// blast-radius check while meaning several different things, and the ids would stop being a
		// faithful description of what was sent.
		if i == 0 {
			verb, at = v, issued
		} else if v != verb || !issued.Equal(at) {
			http.Error(w, "all ids must share one verb and one issuing minute", http.StatusBadRequest)
			return
		}
		subjects = append(subjects, subject)
	}
	ttl := DefaultIntentTTL
	if v := r.URL.Query().Get("ttl"); v != "" {
		d, derr := time.ParseDuration(v)
		if derr != nil {
			http.Error(w, "bad ttl: "+derr.Error(), http.StatusBadRequest)
			return
		}
		ttl = d
	}
	published, err := s.PublishIntentsAt(r.Context(), verb, subjects, r.URL.Query().Get("reason"), ttl, at)
	switch {
	case errors.Is(err, ErrIntentNotApproved), errors.Is(err, ErrBlastRadius):
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	case errors.Is(err, ErrIntentUnsigned):
		// 503, not 500: the control plane is working and deliberately refusing, because publishing
		// unsigned would create a window in which a forging publisher is indistinguishable from it.
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"published": published, "expires_in": ttl.String()})
}

// intentParams reads and validates the common parameters.
func intentParams(w http.ResponseWriter, r *http.Request) (corev1.IntentVerb, []string, string, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get("verb"))
	verb, ok := intentVerbs[raw]
	if !ok {
		http.Error(w, "bad verb: want one of "+intentVerbNames(), http.StatusBadRequest)
		return 0, nil, "", false
	}
	var subjects []string
	for _, v := range r.URL.Query()["subject"] {
		if v = strings.TrimSpace(v); v != "" {
			subjects = append(subjects, v)
		}
	}
	if len(subjects) == 0 {
		http.Error(w, "at least one subject is required", http.StatusBadRequest)
		return 0, nil, "", false
	}
	reason := strings.TrimSpace(r.URL.Query().Get("reason"))
	if reason == "" {
		// An unexplained containment is one nobody can review afterwards, and the reason travels with the
		// intent to its consumers. Required rather than defaulted to "".
		http.Error(w, "reason is required — an intent with no stated reason cannot be reviewed",
			http.StatusBadRequest)
		return 0, nil, "", false
	}
	return verb, subjects, reason, true
}
