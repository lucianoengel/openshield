package gateway

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// ACCESS TICKETS (ZT-12), the credential SOCKS5 can actually carry.
//
// SOCKS5 was deferred with a real reason: it has nowhere to put a client certificate or a bearer token.
// Its only credential channel is RFC 1929's username/password, capped at 255 bytes each — a JWT does not
// fit, and inventing a place to put one would mean a bespoke extension no SOCKS client speaks.
//
// A ticket is the design that reason called for. The client authenticates ONCE over the HTTP access
// proxy, where the full dual credential already works — mutual TLS for the device, a verified OIDC token
// for the user — and receives a short opaque string it can present over SOCKS5.
//
// THE TICKET IS BOUND TO THE DEVICE, and that binding is what makes it safe to hand out. A ticket is a
// bearer credential and bearer credentials get stolen; this one is useless to the thief, because
// redeeming it requires presenting the same client certificate it was issued to. The SOCKS listener is
// mutually authenticated for exactly that reason — the ticket names the USER, and the certificate proves
// the DEVICE, so the pair reconstructs the dual credential the HTTP path checks directly.
//
// SHORT-LIVED BY DEFAULT, because the alternative to expiry is a credential that outlives the session,
// the posture check and the risk score that justified it. Re-issuing costs one authenticated request.

// DefaultTicketTTL is how long an access ticket stays valid.
//
// Ten minutes: long enough that a client opening several connections in a session does not re-authenticate
// per connection, short enough that a leaked ticket is worth little. It is not a session lifetime — the
// tunnel's own re-authorization (ZT-9) is what bounds a session, and a ticket only has to survive long
// enough to open one.
const DefaultTicketTTL = 10 * time.Minute

// ErrBadTicket is returned for any ticket that cannot be redeemed.
//
// ONE error for unknown, expired and wrong-device, deliberately. Distinguishing them tells a holder of a
// stolen ticket which of those three they are up against, which is the only information they lack.
var ErrBadTicket = errors.New("gateway: the access ticket is unknown, expired, or was issued to a " +
	"different device")

// ticket is one issued credential.
type ticket struct {
	deviceSubject string
	userSubject   string
	userRole      string
	expires       time.Time
}

// TicketStore issues and redeems access tickets. The zero value is usable.
//
// IN MEMORY, and that is a deliberate limit rather than an oversight: a ticket is worth ten minutes and
// a gateway restart is exactly when every session should be re-established anyway. Persisting them would
// mean a restarted gateway honouring credentials issued under a posture check it no longer has any
// record of.
type TicketStore struct {
	TTL time.Duration
	Now func() time.Time // nil = time.Now

	mu sync.Mutex
	m  map[string]ticket
}

func (s *TicketStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *TicketStore) ttl() time.Duration {
	if s.TTL > 0 {
		return s.TTL
	}
	return DefaultTicketTTL
}

// Issue mints a ticket for a device⋈user pair and returns the opaque string to present over SOCKS5.
//
// The value is 32 bytes of crypto/rand, base64url-encoded — well inside RFC 1929's 255-byte password
// field, with room to spare. It carries NO structure: a ticket that encoded the subject would let a
// holder read who it was for, and one that encoded an expiry would let them read how long they had.
func (s *TicketStore) Issue(deviceSubject, userSubject, userRole string) (string, error) {
	if deviceSubject == "" {
		return "", errors.New("gateway: a ticket needs a device subject to bind to — an unbound ticket " +
			"is a bearer credential with nothing stopping a thief using it")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	tok := base64.RawURLEncoding.EncodeToString(raw)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]ticket{}
	}
	s.pruneLocked()
	s.m[tok] = ticket{
		deviceSubject: deviceSubject,
		userSubject:   userSubject,
		userRole:      userRole,
		expires:       s.now().Add(s.ttl()),
	}
	return tok, nil
}

// Redeem validates a ticket against the device presenting it and returns the user it names.
//
// The device subject comes from the CERTIFICATE on the connection, never from the client's own claim —
// that is the whole binding. Comparison is constant-time: a ticket is a secret, and a byte-by-byte
// comparison that returns early leaks its prefix to anyone who can time a lot of attempts.
//
// A redeemed ticket is NOT consumed. It is a session credential, not a nonce: a client opening three
// tunnels in one session would otherwise need three round trips to re-authenticate, and would be
// encouraged to hold a longer-lived credential instead — which is the opposite of what this is for.
func (s *TicketStore) Redeem(tok, deviceSubject string) (userSubject, userRole string, err error) {
	if tok == "" || deviceSubject == "" {
		return "", "", ErrBadTicket
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.m[tok]
	if !ok {
		return "", "", ErrBadTicket
	}
	if !s.now().Before(t.expires) {
		delete(s.m, tok)
		return "", "", ErrBadTicket
	}
	if subtle.ConstantTimeCompare([]byte(t.deviceSubject), []byte(deviceSubject)) != 1 {
		return "", "", ErrBadTicket
	}
	return t.userSubject, t.userRole, nil
}

// Len reports how many tickets are held, for tests and for a metric.
func (s *TicketStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	return len(s.m)
}

// pruneLocked drops expired tickets.
//
// On ISSUE rather than on a timer: issuance is the only path that grows the map, so pruning there bounds
// it without a goroutine whose failure would be silent. A gateway nobody is issuing tickets on has
// nothing to prune.
func (s *TicketStore) pruneLocked() {
	now := s.now()
	for k, v := range s.m {
		if !now.Before(v.expires) {
			delete(s.m, k)
		}
	}
}
