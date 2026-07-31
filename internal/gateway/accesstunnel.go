package gateway

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/gateway/identity"
)

// CONNECT TUNNELS THROUGH THE ACCESS PROXY (ZT-9).
//
// The topology has always said users reach "web apps, file servers and databases" through the gateway.
// The broker spoke HTTP only, so two thirds of that was aspiration: a database or an SSH host could not
// be reached through the gate at all, which in practice means a VPN beside it — and a Zero-Trust gate
// with a VPN next to it is a VPN.
//
// NOT THE SAME AS THE EGRESS TUNNEL. The forward proxy has tunnelled CONNECT since D78, but that is the
// outbound direction: an internal client reaching the internet, decided on destination. This is the
// INBOUND broker — an authenticated device and user reaching a catalogued internal service, decided on
// identity, posture and risk. The two share a verb and nothing else, including their fail direction.
//
// A CONNECT arrives on the SAME mutually-authenticated connection as every other access request, so it
// inherits the device certificate, the OIDC user, the posture and the risk without inventing a second
// authentication path. That is the whole reason CONNECT and not SOCKS — see the deferral note below.
//
// WHAT A TUNNEL IS NOT: INSPECTED. The bytes inside are opaque to this product. No classification runs,
// no DLP verdict is reached, nothing in the payload is examined — the decision is made ONCE, at connect
// time, on identity, service, posture and risk. Saying so plainly matters more than the feature does:
// "brokered" and "inspected" are different claims, and a product that blurs them is telling an operator
// their database traffic is being examined when it is not.
//
// WHAT IS DEFERRED, AND WHY. SOCKS5 is not here and is not next. It carries no place for a client
// certificate or a bearer token, so it would need an authentication design of its own rather than
// inheriting this one — a separate ticket, not a switch. Split DNS is likewise absent: a client still
// resolves the service name itself.

// tunnelDefaults bound a tunnel's lifecycle.
const (
	// tunnelDialTimeout bounds reaching the internal service.
	tunnelDialTimeout = 10 * time.Second
	// DefaultTunnelRecheckInterval is how often an ESTABLISHED tunnel is re-authorized.
	//
	// Re-authorization is not optional decoration. A tunnel outlives the decision that opened it, so
	// without it a single CONNECT is a permanent grant — the subject's risk rises, their device falls
	// out of compliance, their access is revoked, and the session opened five minutes earlier carries
	// on regardless. Continuous verification (D89) that stops at the handshake is not continuous.
	DefaultTunnelRecheckInterval = 30 * time.Second
)

// tunnelCounters are the observable facts about tunnels. A tunnel torn down by re-authorization is the
// interesting one: it is the moment continuous verification did something, and it happens with nobody
// watching the connection.
// There is deliberately NO "tunnels opened" counter. Every establishment is already logged with its
// service and device, which is strictly more than a count would say, and adding a number whose only
// reader is its own test is the defect D418/D419 exist to prevent — not something to reintroduce while
// writing the guard's own comment into a new file.
type tunnelCounters struct {
	Refused    atomic.Int64
	Revoked    atomic.Int64 // re-authorization withdrew access from a live tunnel
	DialFailed atomic.Int64
}

// TunnelsRefused, TunnelsRevoked and TunnelDialFailures expose the counters, so they are readable where
// the gateway already reports (D419: a counter nothing reads is not observability).
func (p *AccessProxy) TunnelsRefused() int64     { return p.tunnels.Refused.Load() }
func (p *AccessProxy) TunnelsRevoked() int64     { return p.tunnels.Revoked.Load() }
func (p *AccessProxy) TunnelDialFailures() int64 { return p.tunnels.DialFailed.Load() }

// SetTunnelRecheckInterval overrides how often a live tunnel is re-authorized. Zero or negative restores
// the default — there is deliberately no way to turn re-authorization OFF, because a configuration flag
// that converts every tunnel into a permanent grant is a footgun disguised as a tuning knob.
func (p *AccessProxy) SetTunnelRecheckInterval(d time.Duration) {
	if d <= 0 {
		d = DefaultTunnelRecheckInterval
	}
	p.recheck = d
}

func (p *AccessProxy) recheckInterval() time.Duration {
	if p.recheck <= 0 {
		return DefaultTunnelRecheckInterval
	}
	return p.recheck
}

// serveConnect handles an authenticated, authorized CONNECT.
//
// The caller has already resolved both credentials and built the identity context; this decides, dials
// and splices. It is a separate function from ServeHTTP because everything after the decision is
// connection surgery rather than request handling, and mixing the two is how the authorization step ends
// up accidentally skippable.
func (p *AccessProxy) serveConnect(w http.ResponseWriter, r *http.Request, svc *service,
	id *identity.Identity, deviceSubject string) {
	// THE CLIENT NAMES A SERVICE; THE GATEWAY CHOOSES THE ADDRESS. The host:port in the CONNECT line
	// is used only to look the service up — the dial target comes from the catalogue. Honouring the
	// client's address would make the allow-list a suggestion and the gateway an open relay into the
	// protected network, which is precisely what the catalogue exists to prevent (D88).
	target := svc.tcpAddr

	// RE-ENRICHED ON EVERY CALL, not captured once. Re-authorizing a live tunnel against the context
	// built when it opened would re-derive the opening verdict forever, so the subject's risk could
	// rise and the tunnel would never notice. That was the first version of this code, and the
	// revocation test caught it — which is the only reason it is not still here.
	decide := func(ctx context.Context) (*corev1.Decision, error) {
		return p.gw.Process(ctx, &Request{
			FlowID:   newFlowID(),
			SrcIP:    r.RemoteAddr,
			Protocol: "tcp",
			Host:     svc.name,
			Method:   http.MethodConnect,
			Identity: p.identityContext(id, deviceSubject),
		})
	}

	dec, err := decide(r.Context())
	if err != nil || dec == nil {
		// FAIL CLOSED, like every other access decision (D87).
		p.tunnels.Refused.Add(1)
		p.logger.Error("gateway: tunnel decision failed, denying (fail-closed)",
			"err", err, "service", svc.name)
		http.Error(w, "access denied (decision unavailable)", http.StatusForbidden)
		return
	}
	if dec.GetAction() != corev1.Action_ACTION_ALLOW {
		p.tunnels.Refused.Add(1)
		http.Error(w, "access denied by policy", http.StatusForbidden)
		return
	}

	// Dial BEFORE hijacking. Once the connection is hijacked there is no ResponseWriter left to report
	// a failure through, so a dial error would have to be delivered as a silent close — which a client
	// cannot distinguish from the service being down, or from being denied.
	upstream, err := net.DialTimeout("tcp", target, tunnelDialTimeout)
	if err != nil {
		p.tunnels.DialFailed.Add(1)
		p.logger.Error("gateway: tunnel dial failed", "service", svc.name, "err", err)
		http.Error(w, "gateway: internal service unreachable", http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		p.logger.Error("gateway: server does not support hijacking; CONNECT unavailable")
		http.Error(w, "gateway: tunnelling unsupported", http.StatusInternalServerError)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		p.logger.Error("gateway: hijack failed", "err", err)
		http.Error(w, "gateway: tunnelling failed", http.StatusInternalServerError)
		return
	}
	if _, err := buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		upstream.Close()
		client.Close()
		return
	}
	if err := buf.Flush(); err != nil {
		upstream.Close()
		client.Close()
		return
	}
	p.logger.Info("gateway: tunnel established", "service", svc.name, "device", deviceSubject)

	// Re-authorize on a clock for as long as the tunnel lives. A withdrawal closes BOTH ends: leaving
	// either open would leave the peer waiting on a session the gateway has decided is over.
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(p.recheckInterval())
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				ctx, cancel := context.WithTimeout(context.Background(), tunnelDialTimeout)
				d, derr := decide(ctx)
				cancel()
				// A failed re-check does NOT tear the tunnel down. The access decision fails closed at
				// the door because admitting on an error is unrecoverable; killing an established
				// session because the control plane blinked is a self-inflicted outage, and the
				// session was already authorized once. The counter above is how a run of failures
				// becomes visible instead.
				if derr != nil || d == nil {
					p.logger.Warn("gateway: tunnel re-authorization failed, leaving the tunnel up",
						"service", svc.name, "err", derr)
					continue
				}
				if d.GetAction() != corev1.Action_ACTION_ALLOW {
					p.tunnels.Revoked.Add(1)
					p.logger.Warn("gateway: tunnel revoked by re-authorization",
						"service", svc.name, "device", deviceSubject, "action", d.GetAction().String())
					upstream.Close()
					client.Close()
					return
				}
			}
		}
	}()

	// Splice. Each direction closes the other side when it finishes, so a half-closed peer does not
	// leave the opposite copy blocked forever on a connection nobody will write to again.
	go func() {
		_, _ = io.Copy(upstream, buf) // buf may hold bytes already read from the client
		upstream.Close()
		client.Close()
	}()
	_, _ = io.Copy(client, upstream)
	upstream.Close()
	client.Close()
	close(done)
}
