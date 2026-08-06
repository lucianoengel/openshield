package controlplane

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lucianoengel/openshield/internal/xdr"
)

// CONSOLE-9: the entity surface.
//
// The device⋈user graph (D203) and per-entity risk (D255) have both been live and BOTH DATABASE-ONLY. No
// route exposed either, and `xdr.Store` had no reader at all — Resolve, LookupAny and Link each answer
// "what is the id for THIS name" and none can answer "what does the platform know". So the coalescing
// this whole lane exists to perform was invisible to the operators it was performed for.
//
// TIER: ANALYST, and the privacy boundary is worth stating because this sits next to the CONSOLE-1 split.
// The graph is PSEUDONYM⋈PSEUDONYM — a device's canonical pseudonym linked to the pseudonym of a user
// identity (IDENT-1/D23), never a name. Resolving a pseudonym to a person is `/subject`, which is the
// privacy officer's and no tier reaches. This surface answers "these detections concern one asset",
// which is precisely the analyst's pivot from an alert, and hiding it from the tier that triages alerts
// would leave them reading one asset's activity as several unrelated ones.

// EntityView is one entity with the risk we currently hold for it.
type EntityView struct {
	xdr.Entity
	// Risk is ABSENT when no alert in the window concerns this entity. Deliberately a pointer: a zero
	// score would read as "we assessed this asset and it is fine", and the truth is "nothing has been
	// seen recently" — the difference between a quiet asset and an assessed one, which is the whole
	// question an operator brings to this page.
	Risk *float64 `json:"risk,omitempty"`
}

// EntitiesWithRisk lists the graph joined to the risk scored over the window.
func (s *Server) EntitiesWithRisk(ctx context.Context, window time.Duration, now time.Time,
	limit int) ([]EntityView, error) {
	ents, err := s.Entities(ctx, limit)
	if err != nil {
		return nil, err
	}
	risk, err := s.EntityRisk(ctx, window, now)
	if err != nil {
		return nil, err
	}
	byEntity := make(map[int64]float64, len(risk))
	for _, r := range risk {
		byEntity[r.EntityID] = r.Score
	}
	out := make([]EntityView, 0, len(ents))
	for _, e := range ents {
		v := EntityView{Entity: e}
		if score, ok := byEntity[e.ID]; ok {
			v.Risk = &score
		}
		out = append(out, v)
	}
	return out, nil
}

// Entities lists the entity graph. Separate from EntitiesWithRisk so a caller that does not want the
// second query does not pay for it.
func (s *Server) Entities(ctx context.Context, limit int) ([]xdr.Entity, error) {
	return xdr.NewStore(s.pool).Entities(ctx, limit)
}

// EntityFor resolves one alias value to its entity and every other name it is known by.
func (s *Server) EntityFor(ctx context.Context, value string, window time.Duration,
	now time.Time) (EntityView, bool, error) {
	e, ok, err := xdr.NewStore(s.pool).EntityFor(ctx, value)
	if err != nil || !ok {
		return EntityView{}, ok, err
	}
	v := EntityView{Entity: e}
	risk, err := s.EntityRisk(ctx, window, now)
	if err != nil {
		return EntityView{}, false, err
	}
	for _, r := range risk {
		if r.EntityID == e.ID {
			score := r.Score
			v.Risk = &score
			break
		}
	}
	return v, true, nil
}

// entitiesHandler serves GET /entities — the graph, or one entity by `value`.
func (s *Server) entitiesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	window, err := parseEntityWindow(r)
	if err != nil {
		// SEC-8: a malformed window is a 400, not a silent fall-back — a caller who asked for 24h and
		// silently got 1h would read "no risk" as "nothing happened today".
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	limit, err := parseFleetLimit(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	now := s.now()

	// THE PIVOT: one alias in, every name that asset is known by out.
	if value := strings.TrimSpace(r.URL.Query().Get("value")); value != "" {
		v, ok, ferr := s.EntityFor(r.Context(), value, window, now)
		if ferr != nil {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		if !ok {
			// 404, not an empty list. "No entity is known by that name" and "this entity has nothing
			// recorded" are different answers, and a console that rendered both as an empty page would
			// let a typo look like a clean asset.
			http.Error(w, "no entity is known by that value", http.StatusNotFound)
			return
		}
		writeJSON(w, v)
		return
	}

	ents, err := s.EntitiesWithRisk(r.Context(), window, now, limit)
	if err != nil {
		http.Error(w, "read failed", http.StatusInternalServerError)
		return
	}
	if ents == nil {
		ents = []EntityView{} // never `null`: an empty graph and an unreadable one must not look alike
	}
	writeJSON(w, ents)
}

// parseEntityWindow reads the risk window, defaulting to an hour — the same default EntityRisk applies.
func parseEntityWindow(r *http.Request) (time.Duration, error) {
	v := strings.TrimSpace(r.URL.Query().Get("window"))
	if v == "" {
		return time.Hour, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("window %q is not a duration", v)
	}
	if d <= 0 {
		return 0, fmt.Errorf("window %q is not positive", v)
	}
	return d, nil
}
