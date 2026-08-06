package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// SAVED SEARCHES (SIEM-14).
//
// A SOC's hunts are institutional knowledge, and they were living in people's shell history. The cost is
// not the typing. It is that the hunt which found something last quarter is not repeatable by whoever is
// on shift tonight — and a detection only one analyst can perform is not a detection the team has.
//
// THE STORED FORM IS THE QUERY STRING, not a parsed structure. There is then no second representation to
// drift from the first, running a saved search is re-parsing exactly what was saved, and a parameter
// added to a search surface later is expressible the same day with no change here.
//
// AND IT IS VALIDATED WHEN IT IS SAVED, by the surface's own parser — the same one the live endpoint
// uses, not a copy. That is what makes this a feature rather than a JSON blob store: a saved search that
// cannot run is refused at the moment someone writes it, in front of them, instead of failing during the
// incident it was saved for. It is the discipline the routing table and the escalation ladder already
// use, for the same reason.

// The surfaces a search can be saved against. CLOSED, because the parameters are not interchangeable:
// `kind` selects an event kind on /events and nothing at all on /search, so a surface-less saved search
// would silently run somewhere it does not apply and return an empty result that reads as a finding.
const (
	SurfaceAlerts = "alerts" // /search — peer-UEBA alerts
	SurfaceEvents = "events" // /events — the fleet event aggregate
	SurfaceLogs   = "logs"   // /logs — ingested third-party logs
)

var (
	// ErrUnknownSurface names a surface outside the closed set.
	ErrUnknownSurface = errors.New("controlplane: not a search surface")
	// ErrBadSavedSearch is a query the surface's own parser refuses.
	ErrBadSavedSearch = errors.New("controlplane: the saved query is not valid for its surface")
	// ErrNoSuchSearch is a name that is not saved.
	ErrNoSuchSearch = errors.New("controlplane: no such saved search")
)

// SavedSearch is one named hunt.
type SavedSearch struct {
	Name        string    `json:"name"`
	Surface     string    `json:"surface"`
	Query       string    `json:"query"`
	Description string    `json:"description,omitempty"`
	CreatedBy   string    `json:"created_by"`
	UpdatedBy   string    `json:"updated_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// validateSearch runs the surface's REAL parser over the query, so a saved search is refused now rather
// than at the moment someone needs it.
//
// It builds a request rather than duplicating the parsing, deliberately. A second copy of the validation
// is a copy that drifts, and it would drift toward accepting things the endpoint rejects — i.e. toward
// saving searches that cannot run, which is exactly what this is for.
func validateSearch(surface, query string) error {
	if _, err := url.ParseQuery(query); err != nil {
		return fmt.Errorf("%w: %v", ErrBadSavedSearch, err)
	}
	req, err := http.NewRequest(http.MethodGet, "/?"+query, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadSavedSearch, err)
	}
	switch surface {
	case SurfaceAlerts:
		_, err = parseAlertFilter(req)
	case SurfaceEvents:
		_, err = parseEventFilter(req)
	case SurfaceLogs:
		_, err = parseExternalLogFilter(req)
	default:
		return fmt.Errorf("%w: %q", ErrUnknownSurface, surface)
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadSavedSearch, err)
	}
	return nil
}

// SaveSearch creates or replaces a named search, recording who wrote it.
//
// Replacing rather than versioning: a saved search is a working tool, and a rename is how an analyst
// keeps the old one. created_by survives a replacement — the person who introduced a hunt is a different
// question from who last touched it, and overwriting the first with the second loses the answer to both.
func (s *Server) SaveSearch(ctx context.Context, sv SavedSearch, operator string) error {
	if operator == "" {
		return ErrNoViewer
	}
	name := strings.TrimSpace(sv.Name)
	if name == "" {
		return fmt.Errorf("%w: a saved search needs a name", ErrBadSavedSearch)
	}
	if err := validateSearch(sv.Surface, sv.Query); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO saved_searches (name, surface, query, description, created_by, updated_by)
		 VALUES ($1,$2,$3,$4,$5,$5)
		 ON CONFLICT (name) DO UPDATE SET surface = EXCLUDED.surface, query = EXCLUDED.query,
		        description = EXCLUDED.description, updated_by = EXCLUDED.updated_by, updated_at = now()`,
		name, sv.Surface, sv.Query, sv.Description, operator)
	return err
}

// SavedSearches lists every saved search, by surface then name — a stable order, because this is a list
// people read.
func (s *Server) SavedSearches(ctx context.Context) ([]SavedSearch, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT name, surface, query, description, created_by, updated_by, created_at, updated_at
		   FROM saved_searches ORDER BY surface, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SavedSearch
	for rows.Next() {
		var v SavedSearch
		if err := rows.Scan(&v.Name, &v.Surface, &v.Query, &v.Description, &v.CreatedBy, &v.UpdatedBy,
			&v.CreatedAt, &v.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// SavedSearchByName returns one saved search.
func (s *Server) SavedSearchByName(ctx context.Context, name string) (SavedSearch, error) {
	var v SavedSearch
	err := s.pool.QueryRow(ctx,
		`SELECT name, surface, query, description, created_by, updated_by, created_at, updated_at
		   FROM saved_searches WHERE name = $1`, name).
		Scan(&v.Name, &v.Surface, &v.Query, &v.Description, &v.CreatedBy, &v.UpdatedBy,
			&v.CreatedAt, &v.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return SavedSearch{}, ErrNoSuchSearch
	}
	return v, err
}

// DeleteSavedSearch removes one. A name that is not saved is ErrNoSuchSearch, not a silent success:
// "deleted" when nothing was deleted lets an operator believe a hunt is gone that is still there.
func (s *Server) DeleteSavedSearch(ctx context.Context, name string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM saved_searches WHERE name = $1`, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSuchSearch
	}
	return nil
}

// RunSavedSearch executes a saved search and returns its results.
//
// It re-parses the stored query with the surface's own parser and calls the same Search* the live
// endpoint calls, so a saved search and the equivalent typed query cannot diverge in what they return.
//
// A search saved against a surface whose parser has since become stricter FAILS LOUDLY here rather than
// silently returning something narrower. A hunt that quietly stopped covering what it used to cover is
// the worst outcome available: it goes on producing results, and nobody has any reason to look.
func (s *Server) RunSavedSearch(ctx context.Context, name string) (string, any, error) {
	sv, err := s.SavedSearchByName(ctx, name)
	if err != nil {
		return "", nil, err
	}
	return s.runResolvedSearch(ctx, sv)
}

// runResolvedSearch executes an ALREADY-RESOLVED saved search.
//
// Split out of RunSavedSearch so the HTTP handler can resolve the name, record what the search actually
// filters on, and only then touch the stores the results come from (D483). The saved-search row is not
// the evidence; the alerts, events and logs it selects are, and none of those is read until after the
// record is written — so record-then-serve still holds.
func (s *Server) runResolvedSearch(ctx context.Context, sv SavedSearch) (string, any, error) {
	req, err := http.NewRequest(http.MethodGet, "/?"+sv.Query, nil)
	if err != nil {
		return sv.Surface, nil, fmt.Errorf("%w: %v", ErrBadSavedSearch, err)
	}
	switch sv.Surface {
	case SurfaceAlerts:
		f, perr := parseAlertFilter(req)
		if perr != nil {
			return sv.Surface, nil, fmt.Errorf("%w: %v", ErrBadSavedSearch, perr)
		}
		res, rerr := s.SearchPeerAlerts(ctx, f)
		return sv.Surface, res, rerr
	case SurfaceEvents:
		f, perr := parseEventFilter(req)
		if perr != nil {
			return sv.Surface, nil, fmt.Errorf("%w: %v", ErrBadSavedSearch, perr)
		}
		res, rerr := s.SearchTelemetry(ctx, f)
		return sv.Surface, res, rerr
	case SurfaceLogs:
		f, perr := parseExternalLogFilter(req)
		if perr != nil {
			return sv.Surface, nil, fmt.Errorf("%w: %v", ErrBadSavedSearch, perr)
		}
		res, rerr := s.SearchExternalLogs(ctx, f)
		return sv.Surface, res, rerr
	}
	return sv.Surface, nil, fmt.Errorf("%w: %q", ErrUnknownSurface, sv.Surface)
}

// savedSearchHandler serves GET /searches — the list.
//
// Listing and SAVING are separate PATHS, not two methods on one, because the role gate is per-path:
// mounting the write on the same path as the read would grant either every analyst the ability to
// rewrite the team's hunts, or nobody the ability to read them. Same split as /incidents vs
// /incidents/ack.
func (s *Server) savedSearchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	out, err := s.SavedSearches(r.Context())
	if err != nil {
		http.Error(w, "read failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, out)
}

// savedSearchSaveHandler serves POST /searches/save.
func (s *Server) savedSearchSaveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	operator := operatorIdentity(r.Context())
	if operator == "" {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	q := r.URL.Query()
	sv := SavedSearch{
		Name:        q.Get("name"),
		Surface:     q.Get("surface"),
		Query:       q.Get("query"),
		Description: q.Get("description"),
	}
	switch err := s.SaveSearch(r.Context(), sv, operator); {
	case err == nil:
		writeJSON(w, map[string]any{"name": sv.Name, "surface": sv.Surface, "by": operator})
	case errors.Is(err, ErrUnknownSurface), errors.Is(err, ErrBadSavedSearch):
		// 400 carrying the parser's OWN message: the analyst is standing there and can fix it now,
		// which is the entire reason validation happens at save.
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		http.Error(w, "save failed", http.StatusInternalServerError)
	}
}

// savedSearchRunHandler serves GET /searches/run?name=N.
//
// IT RECORDS ITS OWN VIEW (D483), which is why `/searches/run` is in viewAuditedInHandler rather than
// left to the wrapper. The wrapper can only see the URL, and this URL carries a NAME: a mutable,
// deletable pointer. `SaveSearch` is upsert-on-name and `/searches/delete` is a hard delete, both at
// RESPONDER tier — so an audit row saying "they ran team-hunt" can be made to mean anything, or nothing,
// by a colleague afterwards, at a lower tier than the one that reviews the audit. Migration 053 says the
// query column is "the filter that selected the rows"; for this route the name is not that.
//
// It also lifts the saved search's own `subject=` into subject_filter, for the same reason /search does.
// Without it, saving a subject-naming search and running it by name is a way to read someone's file
// without appearing in that person's access report — a launder, not an audit.
func (s *Server) savedSearchRunHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing name", http.StatusBadRequest)
		return
	}
	viewer := operatorIdentity(r.Context())
	if viewer == "" {
		// Impossible past the tier gate; reaching here means this route was mounted outside it. Same
		// reasoning as viewAudited's own branch — a wiring fault, not an authorization outcome.
		http.Error(w, "internal error: read reached the view audit with no authenticated principal",
			http.StatusInternalServerError)
		return
	}

	// RESOLVE, RECORD, THEN RUN. A name that does not resolve is still recorded, with the name and
	// nothing else: an attempted read of an investigation is worth recording whether or not it found
	// anything, which is what the 404 cases below already assume.
	sv, resolveErr := s.SavedSearchByName(r.Context(), name)
	rec := ViewRecord{Viewer: viewer, Query: canonicalViewQuery(url.Values{"name": {name}})}
	if resolveErr == nil {
		rec.Query = canonicalViewQuery(url.Values{
			"name": {name}, "surface": {sv.Surface}, "query": {sv.Query},
		})
		if stored, perr := url.ParseQuery(sv.Query); perr == nil {
			rec.SubjectFilter = strings.TrimSpace(stored.Get("subject"))
		}
	}
	if err := s.recordRequestView(r, rec); err != nil {
		http.Error(w, "recording the view failed; refusing to run the search",
			http.StatusInternalServerError)
		return
	}

	var (
		surface string
		results any
		err     = resolveErr
	)
	if resolveErr == nil {
		surface, results, err = s.runResolvedSearch(r.Context(), sv)
	}
	switch {
	case err == nil:
		writeJSON(w, map[string]any{"name": name, "surface": surface, "results": results})
	case errors.Is(err, ErrNoSuchSearch):
		http.Error(w, "no such saved search", http.StatusNotFound)
	case errors.Is(err, ErrBadSavedSearch), errors.Is(err, ErrUnknownSurface):
		// 409, not 500: the request is fine and the STORED search is no longer runnable. Distinguishing
		// them is what tells an operator to fix the search rather than page whoever runs the server.
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		http.Error(w, "search failed", http.StatusInternalServerError)
	}
}

// savedSearchDeleteHandler serves POST /searches/delete?name=N.
func (s *Server) savedSearchDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing name", http.StatusBadRequest)
		return
	}
	switch err := s.DeleteSavedSearch(r.Context(), name); {
	case err == nil:
		writeJSON(w, map[string]any{"name": name, "deleted": true})
	case errors.Is(err, ErrNoSuchSearch):
		http.Error(w, "no such saved search", http.StatusNotFound)
	default:
		http.Error(w, "delete failed", http.StatusInternalServerError)
	}
}
