package gateway

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/gateway/identity"
)

// SOCKS5 THROUGH THE ACCESS BROKER (ZT-12).
//
// CONNECT (ZT-9) reaches non-HTTP services from any client that speaks HTTP proxying. SOCKS5 reaches the
// ones that do not — which is most desktop tooling: ssh's ProxyCommand, database clients, and anything
// pointed at a system-wide proxy setting. Leaving it out meant those users had a VPN beside the gate,
// and a Zero-Trust gate with a VPN next to it is a VPN.
//
// IT WAS DEFERRED FOR A REAL REASON, AND THAT REASON IS ANSWERED RATHER THAN WAIVED. SOCKS5 has nowhere
// to put a client certificate or a bearer token; its only credential channel is RFC 1929's
// username/password, capped at 255 bytes. So:
//
//   - the DEVICE credential is the mutual-TLS client certificate on the connection, exactly as on the
//     HTTP path — this listener requires and verifies one, and a client without it never gets to speak
//     SOCKS at all;
//   - the USER credential is an ACCESS TICKET (ZT-12, ticket.go) presented as the password: minted over
//     the HTTP access proxy where the full dual credential already works, bound to the device it was
//     issued to, and short-lived.
//
// The pair reconstructs the dual credential the HTTP path checks directly. A stolen ticket is useless
// without the certificate it was bound to.
//
// WHAT IS DELIBERATELY NOT HERE. BIND and UDP ASSOCIATE are refused: BIND asks the gateway to accept an
// inbound connection on the client's behalf, which is a listening socket into the protected network on
// someone else's say-so, and UDP ASSOCIATE is a second data path with its own decision points. Both are
// real SOCKS features and both are absent; a client asking for either is told so with the protocol's own
// "command not supported" rather than left to time out. And, as with every tunnel here, the bytes are
// BROKERED AND NOT INSPECTED.

// SOCKS5 protocol constants, named so the wire handling reads as protocol rather than as magic numbers.
const (
	socksVersion   = 0x05
	authVersion    = 0x01 // RFC 1929 username/password sub-negotiation
	methodUserPass = 0x02
	methodNone     = 0x00
	methodRefused  = 0xFF

	cmdConnect      = 0x01
	cmdBind         = 0x02
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess             = 0x00
	repGeneralFailure      = 0x01
	repNotAllowed          = 0x02
	repHostUnreachable     = 0x04
	repCommandNotSupported = 0x07
	repAddrNotSupported    = 0x08
)

// socksHandshakeTimeout bounds the negotiation. A client that opens a connection and says nothing holds
// a goroutine and a socket; the handshake is three short exchanges and has no reason to be slow.
const socksHandshakeTimeout = 20 * time.Second

// socksCounters are the observable outcomes. Refusals matter more than successes: a rising refusal count
// on a mutually-authenticated listener is somebody presenting tickets they do not hold.
//
// EVERY REFUSAL BELOW IS COUNTED BEFORE IT IS ANSWERED, and that order is deliberate. These counters are
// the only evidence a refusal happened at all — the connection is closed and the client is gone — so a
// count made after the reply leaves anyone who reacts to the refusal and then reads the count (a test, a
// probe, an operator reproducing the case with the dashboard open) reading a number that is wrong for as
// long as this goroutine is not scheduled. Counting first costs nothing and makes the count sound: a peer
// cannot hold the answer without the count already being made. The CONNECT tunnel beside this one has
// always counted first; SOCKS was the deviation, and it was found as an intermittently red CI run.
type socksCounters struct {
	Refused    atomic.Int64
	Revoked    atomic.Int64
	DialFailed atomic.Int64
}

// SOCKSRefused, SOCKSRevoked and SOCKSDialFailures expose the counters where the gateway already reports.
func (p *AccessProxy) SOCKSRefused() int64      { return p.socks.Refused.Load() }
func (p *AccessProxy) SOCKSRevoked() int64      { return p.socks.Revoked.Load() }
func (p *AccessProxy) SOCKSDialFailures() int64 { return p.socks.DialFailed.Load() }

// SetTicketStore enables ticket-authenticated access (ZT-12). Without one the SOCKS listener refuses
// every connection: a SOCKS proxy that authenticated only the device would be a weaker door into the same
// services the HTTP path guards with two credentials, and the weaker door is the one that gets used.
func (p *AccessProxy) SetTicketStore(s *TicketStore) { p.tickets = s }

// ServeSOCKS accepts SOCKS5 connections on ln until ctx is done.
//
// ln MUST already be mutually authenticated — the handler reads the verified peer certificate off the
// connection and has no way to check that the listener demanded one. The caller wires that; this refuses
// any connection that arrives without a certificate anyway, so a misconfigured listener fails closed
// rather than silently dropping the device credential.
func (p *AccessProxy) ServeSOCKS(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go p.handleSOCKS(ctx, conn)
	}
}

// handleSOCKS runs one SOCKS5 conversation.
func (p *AccessProxy) handleSOCKS(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(socksHandshakeTimeout))

	deviceSubject, err := socksDeviceSubject(conn)
	if err != nil {
		p.socks.Refused.Add(1)
		p.logger.Warn("gateway: SOCKS connection without a usable client certificate", "err", err)
		return
	}
	if p.tickets == nil {
		p.socks.Refused.Add(1)
		p.logger.Error("gateway: SOCKS is listening with NO ticket store — refusing every connection " +
			"rather than authenticating the device alone, which would be a weaker door into the same " +
			"services the HTTP path guards with two credentials")
		return
	}

	// socksNegotiateMethod counts its OWN refusals: it writes the "no acceptable method" answer itself,
	// so a caller counting afterwards could not put the count before the write.
	if err := socksNegotiateMethod(conn, &p.socks); err != nil {
		return
	}
	tok, err := socksReadUserPass(conn)
	if err != nil {
		p.socks.Refused.Add(1)
		return
	}
	userSubject, userRole, rerr := p.tickets.Redeem(tok, deviceSubject)
	if rerr != nil {
		// The RFC 1929 failure status, so a client reports "authentication failed" rather than hanging.
		p.socks.Refused.Add(1)
		_, _ = conn.Write([]byte{authVersion, 0x01})
		p.logger.Warn("gateway: SOCKS ticket refused", "device", deviceSubject)
		return
	}
	if _, err := conn.Write([]byte{authVersion, 0x00}); err != nil {
		return
	}

	cmd, host, err := socksReadRequest(conn)
	if err != nil {
		p.socks.Refused.Add(1)
		return
	}
	if cmd != cmdConnect {
		// BIND asks the gateway to open a listening socket into the protected network on a client's
		// say-so; UDP ASSOCIATE is a second data path with its own decision points. Both are refused
		// with the protocol's own code, so a client is told rather than left to time out.
		p.socks.Refused.Add(1)
		_ = socksReply(conn, repCommandNotSupported)
		p.logger.Info("gateway: SOCKS command refused (only CONNECT is supported)",
			"cmd", cmd, "device", deviceSubject)
		return
	}

	// THE CLIENT NAMES A SERVICE; THE CATALOGUE CHOOSES THE ADDRESS — the same rule as the CONNECT
	// tunnel, and for the same reason. An address taken from the request would make the allow-list
	// constrain the name and leave the address free: an open relay wearing a catalogue.
	svc, ok := p.catalog.Resolve(host)
	if !ok || svc.tcpAddr == "" {
		p.socks.Refused.Add(1)
		_ = socksReply(conn, repNotAllowed)
		p.logger.Info("gateway: SOCKS target is not a catalogued tcp service",
			"host", host, "device", deviceSubject)
		return
	}

	id := &identity.Identity{Subject: userSubject, Role: userRole}
	decide := func(c context.Context) (*corev1.Decision, error) {
		return p.gw.Process(c, &Request{
			FlowID:   newFlowID(),
			SrcIP:    conn.RemoteAddr().String(),
			Protocol: "tcp",
			Host:     svc.name,
			Method:   "SOCKS5",
			Identity: p.identityContext(id, deviceSubject),
		})
	}
	dec, derr := decide(ctx)
	if derr != nil || dec == nil {
		// FAIL CLOSED, like every access decision (D87).
		p.socks.Refused.Add(1)
		_ = socksReply(conn, repGeneralFailure)
		p.logger.Error("gateway: SOCKS decision failed, denying (fail-closed)", "err", derr,
			"service", svc.name)
		return
	}
	if dec.GetAction() != corev1.Action_ACTION_ALLOW {
		p.socks.Refused.Add(1)
		_ = socksReply(conn, repNotAllowed)
		return
	}

	upstream, uerr := net.DialTimeout("tcp", svc.tcpAddr, tunnelDialTimeout)
	if uerr != nil {
		p.socks.DialFailed.Add(1)
		_ = socksReply(conn, repHostUnreachable)
		p.logger.Error("gateway: SOCKS dial failed", "service", svc.name, "err", uerr)
		return
	}
	defer upstream.Close()
	if err := socksReply(conn, repSuccess); err != nil {
		return
	}
	// The handshake deadline must go before the splice, or a long-lived session is cut at twenty
	// seconds — which would look like the service dropping the connection.
	_ = conn.SetDeadline(time.Time{})
	p.logger.Info("gateway: SOCKS tunnel established", "service", svc.name, "device", deviceSubject)

	// The SAME clock re-authorization as the CONNECT tunnel (ZT-9): a session outlives the decision that
	// opened it, so without it one authentication is a permanent grant.
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(p.recheckInterval())
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				c, cancel := context.WithTimeout(context.Background(), tunnelDialTimeout)
				d, err := decide(c)
				cancel()
				if err != nil || d == nil {
					// A failed re-check leaves the session up, exactly as for CONNECT: the door fails
					// closed because admitting on an error is unrecoverable, but disconnecting an
					// already-authorized session because the pipeline blinked is a self-inflicted outage.
					continue
				}
				if d.GetAction() != corev1.Action_ACTION_ALLOW {
					p.socks.Revoked.Add(1)
					p.logger.Warn("gateway: SOCKS session revoked by re-authorization",
						"service", svc.name, "device", deviceSubject)
					upstream.Close()
					conn.Close()
					return
				}
			}
		}
	}()

	go func() {
		_, _ = io.Copy(upstream, conn)
		upstream.Close()
		conn.Close()
	}()
	_, _ = io.Copy(conn, upstream)
	upstream.Close()
	conn.Close()
	close(done)
}

// socksDeviceSubject reads the verified client certificate off the connection and resolves the device.
//
// IT COMPLETES THE HANDSHAKE FIRST, and that is not a formality. A TLS conn handshakes lazily, on the
// first read or write — and SOCKS5 is a protocol where the CLIENT speaks first, so nothing has forced it
// yet. ConnectionState() at this point returns an empty state with no peer certificates, which reads
// exactly like a client that presented none: the device credential would be silently absent on every
// connection, and the listener would refuse everything while looking correctly configured.
func socksDeviceSubject(conn net.Conn) (string, error) {
	tc, ok := conn.(interface {
		HandshakeContext(context.Context) error
		ConnectionState() tls.ConnectionState
	})
	if !ok {
		return "", errors.New("gateway: the SOCKS listener is not TLS — the device credential is the " +
			"client certificate, and without TLS there is none")
	}
	hctx, cancel := context.WithTimeout(context.Background(), socksHandshakeTimeout)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		return "", fmt.Errorf("gateway: TLS handshake: %w", err)
	}
	st := tc.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return "", errors.New("gateway: no client certificate")
	}
	id, err := identity.FromClientCert(st.PeerCertificates[0])
	if err != nil {
		return "", err
	}
	return id.Subject, nil
}

// socksNegotiateMethod performs the method negotiation, selecting username/password.
//
// It REFUSES a client that does not offer it, rather than falling back to "no authentication". A SOCKS
// proxy into a protected network that accepts unauthenticated clients is an open relay, and the fallback
// is the one a permissive default would take.
//
// IT COUNTS ITS OWN REFUSALS rather than returning an error for the caller to count, and that is not
// tidiness — it is the only place the count can be made BEFORE the answer. This function writes the
// "no acceptable method" byte itself, so a caller counting on the way out of it necessarily counts after
// the client already has the refusal. The caller therefore counts NONE of these; counting in both places
// would double every refused negotiation.
func socksNegotiateMethod(conn net.Conn, c *socksCounters) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		c.Refused.Add(1)
		return err
	}
	if head[0] != socksVersion {
		c.Refused.Add(1)
		return fmt.Errorf("gateway: SOCKS version %d, want 5", head[0])
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		c.Refused.Add(1)
		return err
	}
	for _, m := range methods {
		if m == methodUserPass {
			if _, err := conn.Write([]byte{socksVersion, methodUserPass}); err != nil {
				c.Refused.Add(1) // the negotiation did not complete; no session was opened
				return err
			}
			return nil
		}
	}
	c.Refused.Add(1)
	_, _ = conn.Write([]byte{socksVersion, methodRefused})
	return errors.New("gateway: the client offered no username/password method")
}

// socksReadUserPass reads the RFC 1929 sub-negotiation and returns the PASSWORD, which carries the
// access ticket. The username is read and discarded: the identity comes from the ticket and the
// certificate, never from a field the client fills in.
func socksReadUserPass(conn net.Conn) (string, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", err
	}
	if head[0] != authVersion {
		return "", fmt.Errorf("gateway: auth sub-negotiation version %d, want 1", head[0])
	}
	uname := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, uname); err != nil {
		return "", err
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return "", err
	}
	passwd := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return "", err
	}
	return string(passwd), nil
}

// socksReadRequest reads the request and returns the command and the target host.
//
// A DOMAIN target is required for a catalogued service, but an IP literal is read too so the refusal
// below is the catalogue's rather than a parse failure — "that address is not a catalogued service" is
// an answer a client can act on.
func socksReadRequest(conn net.Conn) (cmd byte, host string, err error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return 0, "", err
	}
	if head[0] != socksVersion {
		return 0, "", fmt.Errorf("gateway: SOCKS version %d in request", head[0])
	}
	cmd = head[1]
	switch head[3] {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return 0, "", err
		}
		host = net.IP(b).String()
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return 0, "", err
		}
		host = net.IP(b).String()
	case atypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return 0, "", err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, b); err != nil {
			return 0, "", err
		}
		host = string(b)
	default:
		return 0, "", fmt.Errorf("gateway: unsupported SOCKS address type %d", head[3])
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(conn, port); err != nil {
		return 0, "", err
	}
	// The PORT IS READ AND DISCARDED, like the CONNECT tunnel's: the catalogue supplies the address,
	// and honouring the client's port would leave the allow-list constraining the name alone.
	_ = binary.BigEndian.Uint16(port)
	return cmd, host, nil
}

// socksReply writes a reply with a zero bind address — standard for a proxy that does not report one.
func socksReply(conn net.Conn, rep byte) error {
	_, err := conn.Write([]byte{socksVersion, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// TicketHandler serves POST /ticket on the ACCESS PROXY — the one place the full dual credential is
// already checked, which is why the ticket is minted here and nowhere else (ZT-12).
//
// It is mounted on the HTTP access surface, so a request reaching it has already presented a verified
// client certificate at the TLS layer and, when OIDC is configured, a verified bearer token. The ticket
// it returns carries that user and is bound to that device; a client then presents it over SOCKS5, where
// neither credential fits.
func (p *AccessProxy) TicketHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if p.tickets == nil {
		http.Error(w, "ticket issuance is not configured", http.StatusNotFound)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	deviceID, err := identity.FromClientCert(r.TLS.PeerCertificates[0])
	if err != nil {
		http.Error(w, errDeviceUnknown.Error(), http.StatusForbidden)
		return
	}
	// The SAME user resolution as every other access request: an OIDC token when one is configured, the
	// device certificate otherwise. Duplicating it here would let the ticket path drift into accepting
	// something the request path refuses — and the ticket is the credential that then bypasses both.
	id, status, uerr := p.resolveUser(r, deviceID)
	if uerr != nil {
		http.Error(w, uerr.Error(), status)
		return
	}
	tok, ierr := p.tickets.Issue(deviceID.Subject, id.Subject, id.Role)
	if ierr != nil {
		http.Error(w, "issuing a ticket failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// The TTL is returned so a client knows when to renew rather than discovering it from a refused
	// connection mid-session.
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ticket":      tok,
		"expires_in":  int(p.tickets.ttl().Seconds()),
		"device":      deviceID.Subject,
		"socks_usage": "present the ticket as the SOCKS5 password (RFC 1929); the username is ignored",
	})
}
