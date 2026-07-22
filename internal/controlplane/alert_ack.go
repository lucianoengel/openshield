package controlplane

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
)

// ErrAlertNotFound is returned when an ack targets a peer alert id that does not exist —
// distinct from "already acknowledged", which is a no-op success (the ack is idempotent, so a
// retried request is not an error, but acking a phantom alert is a client mistake worth surfacing).
var ErrAlertNotFound = errors.New("controlplane: peer alert not found")

// AcknowledgeAlert marks a peer alert acknowledged by the given (VERIFIED) operator. The first
// ack wins: the WHERE acknowledged_at IS NULL guard means a later ack on an already-acknowledged
// alert changes nothing and reports newlyAcked=false, preserving the original triager and time.
// A non-existent alert id is ErrAlertNotFound, not a silent no-op — the two zero-row outcomes
// (already-acked vs never-existed) are disambiguated by an existence check, so the caller can
// tell "you already handled this" from "there is no such alert".
func (s *Server) AcknowledgeAlert(ctx context.Context, id int64, operator string) (newlyAcked bool, err error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE peer_alerts SET acknowledged_at = now(), acknowledged_by = $1, status = 'triaged'
		  WHERE id = $2 AND acknowledged_at IS NULL`, operator, id)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 1 {
		return true, nil
	}
	// Zero rows: either the alert is already acknowledged, or it does not exist. Disambiguate — but
	// a genuine DB error here must NOT masquerade as "not found" (SEC-11 error-vs-absence honesty):
	// only pgx.ErrNoRows means the alert does not exist; any other error is infrastructure failure.
	var exists bool
	err = s.pool.QueryRow(ctx, `SELECT true FROM peer_alerts WHERE id = $1`, id).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrAlertNotFound
	}
	if err != nil {
		return false, err // a down DB is not "no such alert"
	}
	return false, nil // exists but was already acknowledged — idempotent no-op
}

// alertAckHandler serves POST /alerts/ack?id=N. The acknowledging operator is taken from the
// VERIFIED client certificate (D56), never a request field — an ack is an accountable action, so
// an unattributable one is refused. Mounted under the operator-role gate + mutual TLS.
func (s *Server) alertAckHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	operator := operatorIdentity(r.TLS)
	if operator == "" {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad or missing id", http.StatusBadRequest)
		return
	}
	newly, err := s.AcknowledgeAlert(r.Context(), id, operator)
	if err != nil {
		if errors.Is(err, ErrAlertNotFound) {
			http.Error(w, "no such alert", http.StatusNotFound)
			return
		}
		http.Error(w, "ack failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"id": id, "acknowledged": true, "newly_acknowledged": newly, "by": operator})
}
