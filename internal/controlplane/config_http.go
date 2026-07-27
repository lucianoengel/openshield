package controlplane

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/lucianoengel/openshield/internal/config"
)

// The CONFIGURATION surface (D292) — the one PLAT-5b was built for and never got.
//
// D263 made the database authoritative for every dynamic setting and D285 wired the READING of them.
// Nothing was ever wired to WRITE one. `ApplySettings`, `SettingsSnapshot`, `Revisions`, `RollbackTo`
// and `Describe` had no caller: the revision trail was recorded by nothing, the rollback could not be
// invoked, and the only way to change a dynamic setting in a deployed system was to write SQL by hand.
//
// That is worse than an ordinary unwired feature, because the design leans on it: the owner's stated
// intent is that configuration is set in the console, the scope split exists so the console can be
// authoritative, and the schema is derived from the field declarations expressly so a UI can render it.
// Every part of that was built except the part that lets anything reach it.
//
// It is also a gap MY OWN TESTS PAPERED OVER. The integration suite's `setDynamic` writes to
// `config_settings` with SQL — because that was the only way — so the suite exercised the reading path
// against a store nothing in the product could fill. A test helper that works around a missing surface
// makes the surface look present.
//
// THREE PROPERTIES THE HANDLERS ENFORCE, all of which already existed in ApplySettings and none of which
// an HTTP layer may weaken:
//
//   - A SECRET IS NEVER READABLE BACK, and never storable. Effective() reports `set`, never the value.
//   - A CHANGE IS VALIDATED AND REFUSED IN FULL. One bad key rejects the whole change; partial
//     application leaves a deployment in a state no operator chose.
//   - EVERY CHANGE IS A REVISION with an author, and rollback restores values as a NEW revision. An
//     audit trail you can rewind by erasing is not one.

// configHandlers mounts the configuration routes.
func (s *Server) configHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/config", s.configHandler)
	mux.HandleFunc("/config/schema", s.configSchemaHandler)
	mux.HandleFunc("/config/revisions", s.configRevisionsHandler)
	mux.HandleFunc("/config/rollback", s.configRollbackHandler)
}

// SetConfigResolver installs the resolver the configuration surface validates and reports against.
//
// Passed in rather than constructed here because the resolver is the PROCESS's — it carries the live
// database snapshot and the environment this binary actually booted with, and a second one built inside
// the handler would answer "what is this deployment running with" for a process that does not exist.
func (s *Server) SetConfigResolver(r *config.Resolver) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.configResolver = r
}

func (s *Server) resolver() *config.Resolver {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.configResolver
}

// configHandler serves GET /config (what this process is honouring, with origins) and
// POST /config (apply a change set).
func (s *Server) configHandler(w http.ResponseWriter, r *http.Request) {
	res := s.resolver()
	if res == nil {
		http.Error(w, "configuration surface not installed", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if _, ok := actor(w, r, http.MethodGet); !ok {
			return
		}
		writeJSON(w, map[string]any{"effective": res.Effective(), "revision": s.appliedRevision()})
	case http.MethodPost:
		op, ok := actor(w, r, http.MethodPost)
		if !ok {
			return
		}
		s.applyConfig(w, r, res, op)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// applyConfig reads a change set and records it as a revision.
func (s *Server) applyConfig(w http.ResponseWriter, r *http.Request, res *config.Resolver, op string) {
	var req struct {
		Note    string            `json:"note"`
		Changes map[string]string `json:"changes"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	// An unknown field is a REFUSAL, not something to ignore: a console sending `change` instead of
	// `changes` would otherwise get a cheerful 200 and change nothing.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "bad request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	rev, err := s.ApplySettings(r.Context(), res, op, req.Note, req.Changes)
	if err != nil {
		var fieldErrs config.Errors
		if errors.As(err, &fieldErrs) {
			// FIELD-SCOPED, so a console can put the message next to the input that caused it rather
			// than showing one banner for a form with twenty fields.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": fieldErrs})
			return
		}
		switch {
		case errors.Is(err, ErrUnknownSetting), errors.Is(err, ErrNotDynamic), errors.Is(err, ErrSecretNotStorable):
			http.Error(w, err.Error(), http.StatusBadRequest)
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	writeJSON(w, map[string]any{"revision": rev, "author": op, "changed": len(req.Changes)})
}

// configSchemaHandler serves GET /config/schema — the field declarations a console renders from.
//
// Derived from the declarations rather than hand-maintained, so a new setting appears in the console
// because it exists, not because someone remembered to add it twice.
func (s *Server) configSchemaHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := actor(w, r, http.MethodGet); !ok {
		return
	}
	res := s.resolver()
	if res == nil {
		http.Error(w, "configuration surface not installed", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, res.Describe())
}

// configRevisionsHandler serves GET /config/revisions?limit=N — who changed what, and from what.
func (s *Server) configRevisionsHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := actor(w, r, http.MethodGet); !ok {
		return
	}
	limit := 50
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			http.Error(w, "bad limit", http.StatusBadRequest)
			return
		}
		limit = n
	}
	revs, err := s.Revisions(r.Context(), limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if revs == nil {
		revs = []ConfigRevision{}
	}
	writeJSON(w, revs)
}

// configRollbackHandler serves POST /config/rollback?to=N.
//
// The honest limit, repeated here because it is the thing an operator will assume otherwise: this
// restores VALUES, not behaviour. A revision applied while a connector was unreachable is not undone by
// putting the setting back.
func (s *Server) configRollbackHandler(w http.ResponseWriter, r *http.Request) {
	op, ok := actor(w, r, http.MethodPost)
	if !ok {
		return
	}
	res := s.resolver()
	if res == nil {
		http.Error(w, "configuration surface not installed", http.StatusServiceUnavailable)
		return
	}
	to, ok := int64Param(w, r, "to")
	if !ok {
		return
	}
	rev, err := s.RollbackTo(r.Context(), res, to, op)
	if err != nil {
		var fieldErrs config.Errors
		if errors.As(err, &fieldErrs) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": fieldErrs})
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"revision": rev, "restored_to": to, "author": op,
		"note": "values are restored as a NEW revision; this does not undo what happened while they were in effect"})
}

// appliedRevision is the revision THIS process has caught up to — the answer to "has this host applied
// my change yet", which is a different question from "what is the latest revision".
func (s *Server) appliedRevision() int64 {
	res := s.resolver()
	if res == nil {
		return 0
	}
	return res.DBRevision()
}
