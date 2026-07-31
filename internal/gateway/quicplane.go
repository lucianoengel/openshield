package gateway

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/quicpeek"
)

// THE INLINE QUIC PLANE (NIPS-12).
//
// The transparent TCP plane decides a flow on its SNI and its client fingerprint. QUIC moved both inside
// an encrypted transport, so a browser preferring HTTP/3 walks past all of it — and a deployment that
// inspects HTTP and HTTP/2 while ignoring UDP/443 covers only whatever has not upgraded yet.
//
// This is the UDP counterpart, and it decides on the FIRST DATAGRAM. QUIC's Initial packet is encrypted
// with keys derived from a connection ID that travels in the clear (internal/quicpeek), so the ClientHello
// inside it is readable by anyone on the path — so the SAME SNI parser and the SAME JA3 fingerprinter the
// TLS path uses decide the flow, over a handshake message QUIC delivers without TLS's record layer (see
// tlsRecordOf, which is the whole of the difference).
//
// ENFORCEMENT IS A DROP, AND THAT IS THE WHOLE MECHANISM. There is no way to refuse a QUIC connection
// politely: the protocol has no plaintext error a client would believe. Dropping the Initial is what every
// QUIC deployment does, and the CONSEQUENCE is the point — a client that gets no answer falls back to TCP,
// onto a path this gateway can actually inspect. Blocking QUIC is a way of RECOVERING inspectability, not
// a way of inspecting QUIC, and it must never be described as the latter.
//
// AN ALLOWED FLOW IS NOT INSPECTED. Only the handshake was read; application data is encrypted under keys
// that were negotiated rather than derived, and nobody off-path has them. An allowed QUIC flow is exactly
// as uninspected as a blind CONNECT tunnel and is recorded the same way.
//
// FAIL-OPEN, like every egress decision (ADR-8/D73/D17): an unreadable packet, an unsupported version or a
// pipeline error FORWARDS. Inline prevention on the egress path degrades to a passive wire, never to a
// network outage — and QUIC is where that matters most, because getting it wrong breaks the web.

const (
	// quicIdle bounds a flow by idleness. UDP has no close, so nothing else can retire an entry: one that
	// outlived its flow would hold a socket per dead connection, and on a busy gateway sockets are the
	// resource that runs out first. Longer than a handshake, far shorter than a session.
	quicIdle = 30 * time.Second

	// maxQUICFlows caps the table.
	//
	// THIS IS THE ONE PLACE THE PLANE IS NOT FAIL-OPEN, and it is deliberate. Past the cap a new flow is
	// dropped rather than tracked, because leaking a socket per flow takes the whole gateway down while
	// refusing one QUIC flow does not. It is also barely a refusal in practice: a dropped QUIC flow falls
	// back to TCP, which is the path this gateway inspects anyway — so saturation degrades toward MORE
	// coverage, not less. Reaching it is still counted and logged, because a plane silently at its ceiling
	// looks identical to a quiet network.
	maxQUICFlows = 4096
)

// QUICCounters are the observable outcomes.
//
// Unreadable is the interesting one. It counts flows the plane FORWARDED because it could not read them —
// an unsupported version, a ClientHello spanning datagrams, a packet that would not authenticate. Each is a
// QUIC flow that passed undecided, and a rising count is coverage draining away as clients adopt something
// this build cannot parse. Without it, "we allow everything we cannot read" looks exactly like "everything
// is fine".
type QUICCounters struct {
	Decided    atomic.Int64
	Blocked    atomic.Int64
	Unreadable atomic.Int64
	Saturated  atomic.Int64
	Failed     atomic.Int64
}

// QUICPlane decides redirected QUIC flows.
type QUICPlane struct {
	gw     *Gateway
	log    *slog.Logger
	Counts QUICCounters

	mu    sync.Mutex
	flows map[string]*quicFlow
}

// quicFlow is one client→destination pair. A blocked flow holds NO socket: the decision is remembered so
// the rest of the flow is dropped without re-deciding, and nothing is dialed for traffic going nowhere.
type quicFlow struct {
	up      *net.UDPConn
	blocked bool
	expires time.Time
}

// NewQUICPlane builds a plane over a gateway pipeline.
func NewQUICPlane(gw *Gateway, log *slog.Logger) *QUICPlane {
	if log == nil {
		log = slog.Default()
	}
	return &QUICPlane{gw: gw, log: log, flows: map[string]*quicFlow{}}
}

// Serve reads redirected datagrams from pc until ctx is done.
//
// pc must come from listenQUICRedirect so each datagram's ORIGINAL destination is recoverable — a nat
// REDIRECT rewrites it before delivery, and the destination is the one fact an egress decision needs.
func (p *QUICPlane) Serve(ctx context.Context, pc *net.UDPConn) error {
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	go p.sweep(ctx)
	go p.report(ctx)

	buf := make([]byte, 2048)
	oob := make([]byte, 1024)
	for {
		n, oobn, _, client, err := pc.ReadMsgUDP(buf, oob)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		dst, derr := originalDst(oob[:oobn])
		if derr != nil {
			// No original destination means the socket is not receiving the cmsg. Forwarding blind is
			// impossible, so the datagram is dropped — loudly, because this is a misconfiguration rather
			// than traffic, and a plane that swallowed it would look like a working QUIC blackhole.
			p.Counts.Failed.Add(1)
			p.log.Error("quic: datagram carries no original destination — the plane cannot tell where it "+
				"was going, so it can neither decide nor forward", "err", derr)
			continue
		}
		datagram := make([]byte, n)
		copy(datagram, buf[:n])
		p.handle(ctx, pc, client, dst, datagram)
	}
}

// handle decides a flow once and forwards the rest of it.
func (p *QUICPlane) handle(ctx context.Context, pc *net.UDPConn, client, dst *net.UDPAddr, datagram []byte) {
	key := client.String() + "->" + dst.String()

	p.mu.Lock()
	f, known := p.flows[key]
	if known {
		f.expires = time.Now().Add(quicIdle)
	}
	p.mu.Unlock()

	if known {
		if f.blocked {
			return // decided on the first datagram; the decision stands for the flow
		}
		_, _ = f.up.Write(datagram)
		return
	}

	// A NEW FLOW. Only an Initial carries a decision. Anything else on a flow the plane has not seen is a
	// stray or a migrated connection, and is forwarded rather than judged on nothing.
	block := false
	if quicpeek.IsQUICInitial(datagram) {
		block = p.decide(ctx, datagram, client, dst)
	}

	if block {
		p.remember(key, &quicFlow{blocked: true, expires: time.Now().Add(quicIdle)})
		p.Counts.Blocked.Add(1)
		p.log.Info("quic: flow DROPPED by policy — the client will fall back to TCP, where this gateway "+
			"can inspect it", "dst", dst.String())
		return
	}

	up, err := p.forwardSocket(client, dst)
	if err != nil {
		p.Counts.Failed.Add(1)
		p.log.Error("quic: cannot open a transparent forward socket, so the flow is dropped (the client "+
			"falls back to TCP)", "client", client.String(), "dst", dst.String(), "err", err)
		return
	}
	f = &quicFlow{up: up, expires: time.Now().Add(quicIdle)}
	if !p.remember(key, f) {
		up.Close()
		p.Counts.Saturated.Add(1)
		p.log.Warn("quic: flow table is at its ceiling — this flow is dropped and will fall back to TCP",
			"ceiling", maxQUICFlows, "dst", dst.String())
		return
	}
	_, _ = up.Write(datagram)
}

// remember installs a flow, reporting false when the table is at its ceiling.
func (p *QUICPlane) remember(key string, f *quicFlow) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.flows) >= maxQUICFlows {
		return false
	}
	p.flows[key] = f
	return true
}

// CanForwardTransparently reports whether this process can bind a socket to an address it does not own.
//
// IT MUST BE CHECKED BEFORE THE DIVERT IS INSTALLED. IP_TRANSPARENT needs CAP_NET_ADMIN. A plane holding
// enough privilege to install the firewall rule but not to bind transparently — a capability set trimmed
// to CAP_NET_RAW, a container that dropped one and kept the other — would take delivery of the host's
// entire UDP/443 and forward none of it. That is a total QUIC blackhole hiding behind a rule that
// installed successfully and a plane whose logs say it is running.
//
// Found by a unit test that ran unprivileged and watched every allowed flow disappear.
func (p *QUICPlane) CanForwardTransparently() error {
	c, err := p.forwardSocket(
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if err != nil {
		return err
	}
	return c.Close()
}

// forwardSocket opens the forward leg, bound to the CLIENT'S OWN ADDRESS.
//
// This is the whole return path. The destination replies to the client, that reply is an ordinary
// forwarded packet through this gateway, and it is not UDP/443 — so the divert rule ignores it and the
// kernel delivers it. Nothing relays it, nothing forges a source address, and there is no second socket to
// keep alive. The plane is inline for the decision and out of the way afterwards.
func (p *QUICPlane) forwardSocket(client, dst *net.UDPAddr) (*net.UDPConn, error) {
	d := net.Dialer{Timeout: 5 * time.Second, Control: transparentControl, LocalAddr: client}
	c, err := d.Dial("udp", dst.String())
	if err != nil {
		return nil, err
	}
	uc, ok := c.(*net.UDPConn)
	if !ok {
		c.Close()
		return nil, errQUICUnsupported
	}
	return uc, nil
}

// decide reads the handshake and runs the pipeline over what it found.
func (p *QUICPlane) decide(ctx context.Context, datagram []byte, client, dst *net.UDPAddr) bool {
	peek, err := quicpeek.PeekInitial(datagram)
	if err != nil {
		// FAIL OPEN, AND COUNT IT. This is a QUIC flow passing undecided, and the count is the only way an
		// operator sees coverage draining as clients adopt shapes this build cannot read.
		p.Counts.Unreadable.Add(1)
		p.log.Warn("quic: the handshake could not be read — forwarding UNDECIDED (fail-open). This flow "+
			"was NOT inspected.", "dst", dst.String(), "version", peek.Version, "err", err)
		return false
	}
	record := tlsRecordOf(peek.ClientHello)
	sni := extractSNI(record)
	ja3, _ := ja3Of(record)

	dstIP, dstPort := addrHostPort(dst)
	srcIP, srcPort := addrHostPort(client)
	dec, perr := p.gw.Process(ctx, &Request{
		FlowID:    newFlowID(),
		SrcIP:     srcIP,
		SrcPort:   srcPort,
		DstIP:     dstIP,
		DstPort:   dstPort,
		Protocol:  "udp",
		Host:      sni,
		JA3:       ja3,
		Direction: corev1.NetworkDirection_NETWORK_DIRECTION_EGRESS,
	})
	if perr != nil || dec == nil {
		p.Counts.Failed.Add(1)
		p.log.Warn("quic: pipeline error — forwarding (fail-open)", "dst", dst.String(), "err", perr)
		return false
	}
	p.Counts.Decided.Add(1)
	return dec.GetAction() == corev1.Action_ACTION_BLOCK
}

// report emits the plane's outcomes on an interval, and ONLY when they have moved.
//
// This is the counter contract this project keeps re-learning (D348/D415/D419): a counter nothing reads
// gives the appearance of the never-silent property and none of its substance. Unreadable is the one that
// most needs saying out loud — it counts QUIC flows this plane FORWARDED WITHOUT DECIDING, and without a
// line in the log an operator cannot distinguish a quiet network from a plane that has stopped
// understanding the traffic crossing it.
func (p *QUICPlane) report(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	var last [5]int64
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := [5]int64{
				p.Counts.Decided.Load(), p.Counts.Blocked.Load(), p.Counts.Unreadable.Load(),
				p.Counts.Saturated.Load(), p.Counts.Failed.Load(),
			}
			if now == last {
				continue // a quiet plane says nothing
			}
			last = now
			p.log.Info("quic: plane outcomes",
				slog.Int64("decided", now[0]), slog.Int64("blocked", now[1]),
				slog.Int64("unreadable_forwarded_undecided", now[2]),
				slog.Int64("dropped_at_flow_ceiling", now[3]), slog.Int64("failed", now[4]))
		}
	}
}

// sweep retires idle flows.
//
// Nothing else can. UDP has no close, and this plane never reads from its forward sockets — the return
// path goes around it — so there is no read deadline to expire anything. Without the sweep the table grows
// for the lifetime of the process on exactly the traffic whose volume a client controls: a blocked
// destination is one it will keep retrying, and an allowed flow holds a file descriptor.
func (p *QUICPlane) sweep(ctx context.Context) {
	t := time.NewTicker(quicIdle / 2)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			p.sweepOnce(now)
		}
	}
}

// tlsRecordOf wraps a bare TLS handshake message in the record header the gateway's readers expect.
//
// QUIC DELETED THE TLS RECORD LAYER. A CRYPTO frame carries the handshake message directly, starting with
// 0x01 (ClientHello) — but extractSNI and JA3 were written for TCP, where the first thing on the wire is a
// record header, and both reject anything whose first byte is not 0x16. Handing them a QUIC ClientHello
// unwrapped returns "" from each, so the plane would decide EVERY QUIC flow with no server name and no
// fingerprint: the policy would see an anonymous flow, allow it under any sane rule, and the plane would
// report itself as deciding traffic it had learned nothing about.
//
// Wrapping is the right fix rather than teaching both readers a second entry shape: it keeps one parser
// for both transports, and the parser stays the one that has been fuzzed.
//
// A handshake too large for a single record returns nil, which the readers report as unreadable — the
// honest answer, since this reader does not reassemble across datagrams either.
func tlsRecordOf(handshake []byte) []byte {
	if len(handshake) == 0 || len(handshake) > 0xffff {
		return nil
	}
	rec := make([]byte, 0, 5+len(handshake))
	rec = append(rec, 0x16, 0x03, 0x01, byte(len(handshake)>>8), byte(len(handshake)))
	return append(rec, handshake...)
}

// sweepOnce is one pass, split out so a test drives the REAL retirement rule rather than a copy of it.
func (p *QUICPlane) sweepOnce(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, f := range p.flows {
		if !now.After(f.expires) {
			continue
		}
		if f.up != nil {
			f.up.Close()
		}
		delete(p.flows, k)
	}
}
