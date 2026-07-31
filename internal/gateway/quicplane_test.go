package gateway

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/policy"
	"github.com/lucianoengel/openshield/internal/quicpeek"
)

// blockEverythingGateway is a pipeline that refuses every flow it is asked about.
//
// It is deliberately the OPPOSITE of the expected outcome in the fail-open tests below: if the plane ever
// consults it, the flow is blocked and the test fails. An allow-everything stand-in would let a plane that
// wrongly consulted the pipeline pass anyway, which is how a fail-open test proves nothing.
func blockEverythingGateway(t *testing.T) *Gateway {
	t.Helper()
	pol, err := policy.New(context.Background(), "quic-test", "1", `package openshield
import rego.v1
decision := {"action":"BLOCK","reason":"everything","confidence":1.0}`)
	if err != nil {
		t.Fatal(err)
	}
	return New(sigClassifier{marker: "\x00never-matches\x00"}, pol, noopLedger{}, nil, time.Second)
}

// quietLogger keeps the plane's (deliberately loud) lines out of the test output.
func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func testPlane(t *testing.T) *QUICPlane {
	t.Helper()
	return NewQUICPlane(blockEverythingGateway(t), quietLogger())
}

// initialWithUnknownVersion builds a QUIC long-header Initial announcing a version this build does not
// know. IsQUICInitial accepts it (it IS QUIC) but the keys cannot be derived, so the handshake is
// unreadable — which is exactly the shape a client negotiating a future version presents.
func initialWithUnknownVersion() []byte {
	pkt := []byte{0xc0}
	pkt = binary.BigEndian.AppendUint32(pkt, 0xdeadbeef)
	pkt = append(pkt, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x00) // 8-byte DCID, empty SCID
	pkt = append(pkt, make([]byte, 64)...)
	return pkt
}

// A QUIC FLOW THIS BUILD CANNOT READ IS FORWARDED, AND SAID OUT LOUD.
//
// This is the fail-open contract on the egress path (ADR-8/D73/D17) at the point where it is most easily
// got wrong: the packet IS QUIC, it just is not a version this build understands. Refusing it would break
// the web for every client that got ahead of the gateway; forwarding it silently would let coverage drain
// away invisibly as adoption moved. So it forwards AND increments Unreadable.
//
// Mutations, both of which this kills:
//   - block on an unreadable handshake → the flow is refused → FAIL (the plane consulted nothing, so this
//     could only come from a fail-CLOSED default)
//   - forward but do not count → Unreadable stays 0 → FAIL
func TestAQUICFlowThisBuildCannotReadIsForwardedAndCounted(t *testing.T) {
	p := testPlane(t)
	pkt := initialWithUnknownVersion()

	if !quicpeek.IsQUICInitial(pkt) {
		t.Fatal("the fixture is not classified as a QUIC Initial, so this test exercises the wrong path")
	}
	blocked := p.decide(context.Background(), pkt,
		&net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5000},
		&net.UDPAddr{IP: net.IPv4(93, 184, 216, 34), Port: 443})

	if blocked {
		t.Fatal("an unreadable QUIC handshake was BLOCKED. Inline prevention on the egress path must " +
			"degrade to a passive wire, never to a network outage — and the pipeline here refuses " +
			"everything, so this verdict came from a fail-closed default rather than from policy")
	}
	if got := p.Counts.Unreadable.Load(); got != 1 {
		t.Fatalf("Unreadable = %d, want 1. A flow that passed UNDECIDED and was not counted is coverage "+
			"draining away invisibly: 'we allow everything we cannot read' then looks exactly like "+
			"'everything is fine'", got)
	}
	if got := p.Counts.Decided.Load(); got != 0 {
		t.Fatalf("Decided = %d, want 0 — an undecided flow must not be counted as decided, or the "+
			"coverage number reports work that never happened", got)
	}
}

// A DATAGRAM THAT IS NOT AN INITIAL IS NOT JUDGED.
//
// Mid-flow packets, migrated connections and strays carry no ClientHello. Deciding on them would mean
// deciding on nothing — an empty SNI and an empty JA3, which policy would evaluate as a real flow with no
// name. The plane forwards them instead, and the counters stay untouched so nothing claims to have
// examined them.
func TestANonInitialDatagramIsForwardedWithoutBeingJudged(t *testing.T) {
	p := testPlane(t)
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	// A short-header (1-RTT) datagram: valid QUIC, no handshake in it.
	p.handle(context.Background(), pc,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5000},
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9},
		append([]byte{0x40}, make([]byte, 32)...))

	if got := p.Counts.Blocked.Load(); got != 0 {
		t.Fatalf("Blocked = %d: a datagram carrying no handshake was judged. The pipeline here refuses "+
			"everything, so a plane that decided on an empty SNI would block every mid-flow packet it "+
			"saw and break connections it had already allowed", got)
	}
	if got := p.Counts.Decided.Load() + p.Counts.Unreadable.Load(); got != 0 {
		t.Fatalf("the counters moved (%d) for a datagram that carries nothing to decide on", got)
	}
	// Whether it was actually put on the wire cannot be checked here: forwarding binds a transparent
	// socket, which needs CAP_NET_ADMIN, so this test would fail as an ordinary user for a reason that has
	// nothing to do with what it is asserting. That half is proven under root, end to end, by
	// TestAnUnmodifiedClientsQUICFlowIsDecidedOnItsServerName.
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, f := range p.flows {
		if f.blocked {
			t.Fatal("a mid-flow datagram was recorded as a BLOCKED flow — it carries nothing to decide " +
				"on, so refusing it would break connections this plane had already allowed")
		}
	}
}

// A BLOCKED FLOW IS REMEMBERED, AND HOLDS NO SOCKET.
//
// Two properties in one, because they are the same design choice. Re-deciding every datagram of a refused
// flow would run the pipeline once per packet on exactly the traffic a client retries hardest; dialing an
// upstream for it would hold a socket open for a conversation that is going nowhere.
func TestABlockedFlowIsRememberedWithoutHoldingASocket(t *testing.T) {
	p := testPlane(t)
	key := "10.0.0.1:5000->93.184.216.34:443"
	p.remember(key, &quicFlow{blocked: true, expires: time.Now().Add(quicIdle)})

	p.mu.Lock()
	f := p.flows[key]
	p.mu.Unlock()
	if f == nil || !f.blocked {
		t.Fatal("the blocked decision was not remembered, so every datagram of a refused flow would " +
			"re-enter the pipeline")
	}
	if f.up != nil {
		t.Fatal("a blocked flow is holding an upstream socket — a refused conversation is going nowhere " +
			"and must not cost a file descriptor")
	}
}

// THE FLOW TABLE HAS A CEILING, and reaching it is reported rather than survived quietly.
//
// This is the one place the plane is not fail-open, which is why it is tested explicitly: past the cap a
// new flow is dropped rather than tracked, because leaking a socket per flow takes the whole gateway down.
// A dropped QUIC flow falls back to TCP — the path this gateway inspects — so saturation degrades toward
// more coverage, not less.
func TestTheFlowTableRefusesToGrowWithoutBound(t *testing.T) {
	p := testPlane(t)
	for i := 0; i < maxQUICFlows; i++ {
		if !p.remember(string(rune(i))+"-flow", &quicFlow{blocked: true, expires: time.Now()}) {
			t.Fatalf("the table refused a flow at %d, below its own ceiling of %d", i, maxQUICFlows)
		}
	}
	if p.remember("one-too-many", &quicFlow{blocked: true, expires: time.Now()}) {
		t.Fatalf("the table accepted a flow past its ceiling of %d — the cap is decorative, and a "+
			"gateway under QUIC pressure would run out of sockets instead of shedding load", maxQUICFlows)
	}
}

// EXPIRED BLOCKED FLOWS ARE SWEPT.
//
// Blocked entries hold no socket, so they have no read deadline to retire them; without the sweep the
// table grows for the process lifetime on exactly the traffic whose volume a client controls — a blocked
// destination is one it will keep retrying.
func TestBlockedFlowsDoNotAccumulateForever(t *testing.T) {
	p := testPlane(t)
	p.remember("stale", &quicFlow{blocked: true, expires: time.Now().Add(-time.Hour)})
	p.remember("fresh", &quicFlow{blocked: true, expires: time.Now().Add(time.Hour)})

	p.sweepOnce(time.Now()) // the REAL retirement rule, not a copy of it in the test

	p.mu.Lock()
	_, staleLeft := p.flows["stale"]
	_, freshLeft := p.flows["fresh"]
	p.mu.Unlock()

	if staleLeft {
		t.Fatal("an expired blocked flow survived the sweep")
	}
	if !freshLeft {
		t.Fatal("the sweep retired a flow that is still live — the client's next datagram would re-enter " +
			"the pipeline and be re-decided")
	}
}

// ORIGINAL DESTINATION IS AN ERROR WHEN ABSENT, never a guess.
//
// "This datagram was going nowhere in particular" is not a thing that can be true. If the cmsg is missing
// the socket is not configured for it, and a plane that defaulted the address would decide every flow
// against the wrong destination while looking perfectly healthy.
func TestAMissingOriginalDestinationIsAnErrorRatherThanAGuess(t *testing.T) {
	if _, err := originalDst(nil); err == nil {
		t.Fatal("a datagram with no control messages yielded a destination. Policy is written against " +
			"destinations, so a guessed one is a decision made about the wrong flow")
	}
}

// QUIC'S CLIENTHELLO REACHES THE SAME READERS THE TLS PATH USES.
//
// QUIC deleted TLS's record layer: a CRYPTO frame carries the handshake message directly, starting with
// 0x01, while extractSNI and JA3 both reject anything whose first byte is not 0x16. Nothing crashes when
// this is wrong — both simply return "", and the plane decides every QUIC flow with no server name and no
// fingerprint. Policy then sees an anonymous flow, allows it under any sane rule, and the plane reports
// itself as deciding traffic it learned nothing about.
//
// Mutation (pass peek.ClientHello straight to the readers instead of wrapping it): the SNI is empty and
// the JA3 is absent → FAIL. Verified by running it.
func TestAQUICClientHelloIsReadableByTheTLSPathsOwnReaders(t *testing.T) {
	hello := realClientHello(t) // a genuine Go TLS ClientHello, as a TCP record
	if hello[0] != 0x16 {
		t.Fatalf("the fixture is not a TLS record (first byte %#x), so this test proves nothing", hello[0])
	}
	// What QUIC actually delivers: the handshake message, with the record header stripped.
	quicForm := hello[5:]

	if sni := extractSNI(quicForm); sni != "" {
		t.Fatalf("extractSNI read %q from a bare handshake message — the premise of this test is wrong "+
			"and the wrapper it guards may be unnecessary", sni)
	}

	rewrapped := tlsRecordOf(quicForm)
	sni := extractSNI(rewrapped)
	if sni == "" {
		t.Fatal("a QUIC ClientHello yielded NO server name. Every QUIC flow would then be decided as an " +
			"anonymous one — allowed by any sane policy — while the plane counted it as decided")
	}
	if _, ok := ja3Of(rewrapped); !ok {
		t.Fatal("a QUIC ClientHello yielded no JA3. The fingerprint is the half of the decision that " +
			"still works when the server name is absent or lied about")
	}
	// And it agrees with what the TCP path would have said about the same client.
	if want := extractSNI(hello); sni != want {
		t.Fatalf("the QUIC path read %q where the TCP path reads %q — the two transports must not "+
			"disagree about the same client", sni, want)
	}
}

// AN OVERSIZED OR EMPTY HANDSHAKE IS REFUSED RATHER THAN TRUNCATED.
//
// The record length is 16 bits. Silently wrapping something larger would produce a record claiming a
// length it does not have, and the readers would parse whatever happened to be at that offset — a
// fingerprint and a server name assembled from the wrong bytes are worse than none, because both look
// like real answers.
func TestAHandshakeThatCannotBeWrappedIsRefused(t *testing.T) {
	if got := tlsRecordOf(nil); got != nil {
		t.Error("an empty handshake produced a record")
	}
	if got := tlsRecordOf(make([]byte, 0x10000)); got != nil {
		t.Error("a handshake too large for a TLS record was wrapped anyway — the length field would " +
			"wrap and the readers would parse the wrong bytes into a real-looking answer")
	}
}
