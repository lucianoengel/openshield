package gateway

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/lucianoengel/openshield/internal/enforcers/flow"
)

// DefaultMaxBody caps the request body the proxy buffers — it both classifies and
// forwards the body, so it must hold it. A body over the cap is refused (413): a
// bounded proxy, and the refusal is logged, not silent.
const DefaultMaxBody = 8 << 20 // 8 MiB

// Proxy is a plain-HTTP forward proxy that runs each request through the gateway
// pipeline and applies the verdict to the live connection.
//
// Plain HTTP only: HTTPS bodies are opaque until TLS interception (N1.3), and this
// handler does not pretend otherwise. The verdict reaches the connection through
// the flow Table's disposition (set by the enforcer, applied HERE), so the
// enforcer never closes a socket the handler owns.
type Proxy struct {
	gw          *Gateway
	table       *Table
	rt          http.RoundTripper
	redirectURL string
	maxBody     int64
	logger      *slog.Logger
}

// NewProxy wires a Proxy. enforce turns blocking ON: with it false the proxy is
// observe-only (D1) — it classifies, decides and audits, but the flow enforcer is
// not registered, so every disposition stays allow and every flow is forwarded.
func NewProxy(gw *Gateway, table *Table, rt http.RoundTripper, redirectURL string, maxBody int64, enforce bool, logger *slog.Logger) *Proxy {
	if rt == nil {
		rt = http.DefaultTransport
	}
	if maxBody <= 0 {
		maxBody = DefaultMaxBody
	}
	if logger == nil {
		logger = slog.Default()
	}
	if enforce {
		gw.Enforcers = append(gw.Enforcers, flow.New(table))
	}
	return &Proxy{gw: gw, table: table, rt: rt, redirectURL: redirectURL, maxBody: maxBody, logger: logger}
}

func newFlowID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return "flow_" + hex.EncodeToString(b[:])
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		// HTTPS: the client tunnels through CONNECT and runs TLS end to end with
		// the origin. The proxy relays ciphertext and inspects nothing here —
		// seeing the body requires terminating that TLS (interception, N1.3b).
		p.handleConnect(w, r)
		return
	}

	body, tooLarge, err := readBounded(r.Body, p.maxBody)
	if err != nil {
		http.Error(w, "gateway: reading request body", http.StatusBadGateway)
		return
	}
	if tooLarge {
		// A body larger than the proxy can hold is refused, not silently
		// truncated (truncating would forward a corrupt request and classify an
		// incomplete one). A real, stated size limit.
		p.logger.Warn("gateway: request body over cap, refused", "cap", p.maxBody, "host", r.Host)
		http.Error(w, "gateway: request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	flowID := newFlowID()
	p.table.Register(flowID)
	defer p.table.Deregister(flowID)

	req := requestFromHTTP(flowID, r, body)
	if _, perr := p.gw.Process(r.Context(), req); perr != nil {
		// Fail OPEN, loudly (D17/D18). Process already recorded the failure via
		// the audit sink, so the flow is forwarded rather than turning a
		// classifier failure into a denial of service on all egress.
		p.logger.Error("gateway: pipeline error, failing open (flow forwarded, failure audited)",
			"err", perr, "flow", flowID, "host", r.Host)
		p.forward(w, r, body)
		return
	}

	switch p.table.Disposition(flowID) {
	case DispositionBlock:
		http.Error(w, "blocked by OpenShield policy", http.StatusForbidden)
	case DispositionRedirect:
		w.Header().Set("Location", p.redirectURL)
		w.WriteHeader(http.StatusFound)
	default:
		p.forward(w, r, body)
	}
}

// handleConnect establishes a BLIND TCP tunnel for an HTTPS CONNECT: the TLS
// session is end to end between the client and the origin, so the proxy relays
// ciphertext and classifies NOTHING. Tunneled HTTPS bodies are therefore
// uninspected — a stated coverage gap that TLS interception (N1.3b) closes. The
// tunnel is logged so the gap is operationally visible, not silent (D16).
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	upstream, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "gateway: upstream dial failed", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "gateway: cannot tunnel (no hijack support)", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		client.Close()
		upstream.Close()
		return
	}
	p.logger.Info("gateway: tunneling HTTPS (not inspected — TLS interception is N1.3b)",
		"host", r.Host)
	go relay(client, upstream)
	go relay(upstream, client)
}

// relay copies one direction of a tunnel and closes both ends when it finishes, so
// the other direction unblocks. Close on an already-closed conn is a harmless
// no-op — the standard tunnel teardown.
func relay(dst, src net.Conn) {
	_, _ = io.Copy(dst, src)
	dst.Close()
	src.Close()
}

// forward sends the buffered request upstream and copies the response back. For a
// forward-proxy request r.URL is absolute, so it names the upstream directly.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, body []byte) {
	out, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "gateway: building upstream request", http.StatusBadGateway)
		return
	}
	copyHeader(out.Header, r.Header)
	out.Host = r.Host

	resp, err := p.rt.RoundTrip(out)
	if err != nil {
		http.Error(w, "gateway: upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// requestFromHTTP builds a gateway.Request from an incoming proxy request. The
// 5-tuple is best-effort (RemoteAddr for the source, the request URL for the
// destination); the metadata drives the policy, the buffered body is classified.
func requestFromHTTP(flowID string, r *http.Request, body []byte) *Request {
	srcIP, srcPort := splitHostPort(r.RemoteAddr)
	dstIP := r.URL.Hostname()
	dstPort := uint32(80)
	if ps := r.URL.Port(); ps != "" {
		if n, err := strconv.Atoi(ps); err == nil {
			dstPort = uint32(n)
		}
	}
	return &Request{
		FlowID:   flowID,
		SrcIP:    srcIP,
		SrcPort:  srcPort,
		DstIP:    dstIP,
		DstPort:  dstPort,
		Protocol: "tcp",
		Host:     r.Host,
		Method:   r.Method,
		Path:     r.URL.Path,
		Body:     body,
	}
}

func splitHostPort(addr string) (string, uint32) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	n, _ := strconv.Atoi(portStr)
	return host, uint32(n)
}

// readBounded reads up to max bytes; tooLarge reports whether the body exceeded it.
func readBounded(r io.Reader, max int64) (body []byte, tooLarge bool, err error) {
	if r == nil {
		return nil, false, nil
	}
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(b)) > max {
		return nil, true, nil
	}
	return b, false, nil
}

// hopHeaders are per-connection headers a proxy must not forward (RFC 7230 §6.1).
var hopHeaders = map[string]bool{
	"Connection": true, "Proxy-Connection": true, "Keep-Alive": true,
	"Proxy-Authenticate": true, "Proxy-Authorization": true, "Te": true,
	"Trailer": true, "Transfer-Encoding": true, "Upgrade": true,
}

func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		if hopHeaders[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}
