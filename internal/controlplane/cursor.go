package controlplane

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// KEYSET PAGINATION CURSORS (CONSOLE-6).
//
// `/events` capped at 1000 rows with no cursor and no signal that more existed. Against 90-day retention
// that is not a hunting surface: an analyst got the top 1000 and had no way to reach row 1001 — and no
// way to know row 1001 was there. A truncated result that LOOKS COMPLETE is the failure, not the
// truncation.
//
// KEYSET, NOT OFFSET, and the reason is the live stream. `OFFSET 1000` re-runs the query and discards
// rows; against a table being written continuously, rows arriving at the head shift every later row down,
// so page 2 repeats what page 1 showed and skips what it did not. An analyst would be reading a result
// set that quietly lies about its own contents. A keyset walk starts from a fixed point, so new rows land
// above it and are simply not in the walk — a limit that is STATED rather than a corruption that is not.

// ErrCursor means the cursor could not be decoded.
//
// Refused, never ignored: silently restarting from the beginning hands page 1 to a client that believes
// it is on page 5, so the client renders duplicates and concludes the underlying data changed under it.
var ErrCursor = errors.New("controlplane: cursor is not readable")

// cursorVersion prefixes the encoding so a future change is a clean refusal rather than a
// misinterpretation of old bytes as new ones.
const cursorVersion = "v1"

// eventCursor is a position in the `(received_at DESC, id DESC)` ordering.
//
// A POSITION AND NOTHING ELSE — this is the CONSOLE-1 inherited requirement, and it is a design decision
// rather than an omission. A cursor that also carried scope would be honoured as authority, and the moment
// a cursor is a capability, replaying someone else's is privilege escalation. Authority is re-derived from
// the principal on the request context on every page (D470), so a cursor lifted from another operator's
// session yields that operator's POSITION and the lifter's AUTHORITY — which is the intended outcome.
//
// OPAQUE BUT NOT SECRET. Opaque so clients do not build on the internals and the encoding can change;
// deliberately not secret, because treating it as a secret is the first step to treating it as a
// capability.
type eventCursor struct {
	ReceivedAt time.Time
	ID         int64
}

// encode renders the cursor for a client. base64url so it survives a query string untouched.
func (c eventCursor) encode() string {
	raw := fmt.Sprintf("%s:%d:%d", cursorVersion, c.ReceivedAt.UTC().UnixNano(), c.ID)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeEventCursor parses a client-supplied cursor. Every failure path is an error; none falls back to
// "start from the beginning".
func decodeEventCursor(s string) (eventCursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return eventCursor{}, fmt.Errorf("%w: not base64url", ErrCursor)
	}
	parts := strings.Split(string(raw), ":")
	if len(parts) != 3 {
		return eventCursor{}, fmt.Errorf("%w: wrong shape", ErrCursor)
	}
	if parts[0] != cursorVersion {
		return eventCursor{}, fmt.Errorf("%w: unknown version %q", ErrCursor, parts[0])
	}
	nanos, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return eventCursor{}, fmt.Errorf("%w: bad timestamp", ErrCursor)
	}
	id, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return eventCursor{}, fmt.Errorf("%w: bad row id", ErrCursor)
	}
	return eventCursor{ReceivedAt: time.Unix(0, nanos).UTC(), ID: id}, nil
}

// SIBLING CURSORS FOR /alerts, /search AND /incidents (CONSOLE-6b).
//
// `peer_alerts` and `incidents` both carry `id BIGSERIAL PRIMARY KEY`, so `(detected_at, id)` and
// `(last_seen, id)` are already unique and monotone — the same property `(received_at, id)` supplies for
// /events. No migration and no new tiebreaker column: the walk boundary is exact rather than approximate
// because two rows sharing a timestamp are still ordered by id.
//
// ⚠️ THE VERSION TAG IS ALSO A NAMESPACE, AND THAT IS THE POINT. All three cursors encode an identical
// shape (timestamp + int64, colon-joined, base64url). With no discriminator, an /alerts cursor — a
// position in the peer_alerts id space — presented to /incidents DECODES SUCCESSFULLY and serves a page
// that is wrong but entirely plausible: row-identity corruption dressed as a normal result. The tag makes
// that a refusal instead, in the same error class and with the same 400 a malformed cursor already gets.
//
// THIS IS NOT THE AUTHORITY REQUIREMENT and must not be read as one — see the eventCursor block above,
// which still governs. The tag says "this position belongs to the alerts walk"; it never says who may
// walk it. Nothing about the caller is encoded, and authority is re-derived per page from the credential.
const (
	alertCursorVersion    = "a1"
	incidentCursorVersion = "i1"
)

// alertCursor is a position in the `(detected_at DESC, id DESC)` ordering over peer_alerts.
type alertCursor struct {
	DetectedAt time.Time
	ID         int64
}

func (c alertCursor) encode() string { return encodeKeyset(alertCursorVersion, c.DetectedAt, c.ID) }

// decodeAlertCursor parses a client-supplied /alerts or /search cursor. A cursor minted by another
// surface fails here, rather than being honoured against the wrong table.
func decodeAlertCursor(s string) (alertCursor, error) {
	at, id, err := decodeKeyset(alertCursorVersion, s)
	if err != nil {
		return alertCursor{}, err
	}
	return alertCursor{DetectedAt: at, ID: id}, nil
}

// incidentCursor is a position in the `(last_seen DESC, id DESC)` ordering over incidents.
type incidentCursor struct {
	LastSeen time.Time
	ID       int64
}

func (c incidentCursor) encode() string { return encodeKeyset(incidentCursorVersion, c.LastSeen, c.ID) }

// decodeIncidentCursor parses a client-supplied /incidents cursor.
func decodeIncidentCursor(s string) (incidentCursor, error) {
	at, id, err := decodeKeyset(incidentCursorVersion, s)
	if err != nil {
		return incidentCursor{}, err
	}
	return incidentCursor{LastSeen: at, ID: id}, nil
}

// encodeKeyset / decodeKeyset are the shared codec for the two cursors added here. They exist so the two
// cannot drift apart in what they accept, which is exactly the kind of divergence that would let one
// surface honour bytes the other refuses.
//
// decodeEventCursor deliberately does NOT route through them. Its wire format and its error strings are
// shipped and asserted, and rewriting a working codec for tidiness spends blast radius on the one surface
// that proves the mechanism works. The formats are byte-identical by construction, not by sharing code.
func encodeKeyset(version string, at time.Time, id int64) string {
	raw := fmt.Sprintf("%s:%d:%d", version, at.UTC().UnixNano(), id)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeKeyset(version, s string) (time.Time, int64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("%w: not base64url", ErrCursor)
	}
	parts := strings.Split(string(raw), ":")
	if len(parts) != 3 {
		return time.Time{}, 0, fmt.Errorf("%w: wrong shape", ErrCursor)
	}
	if parts[0] != version {
		// A well-formed cursor for ANOTHER surface lands here, and so does a cursor from an older
		// encoding. Both are the same answer: these bytes are not a position in this walk.
		return time.Time{}, 0, fmt.Errorf("%w: unknown version %q", ErrCursor, parts[0])
	}
	nanos, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("%w: bad timestamp", ErrCursor)
	}
	id, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("%w: bad row id", ErrCursor)
	}
	return time.Unix(0, nanos).UTC(), id, nil
}
