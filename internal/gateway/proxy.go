package gateway

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/enforcers/flow"
)

// DefaultMaxBody caps the request body the proxy buffers — it both classifies and
// forwards the body, so it must hold it. A body over the cap is refused (413): a
// bounded proxy, and the refusal is logged, not silent.
const DefaultMaxBody = 8 << 20 // 8 MiB

// Proxy is a forward proxy that runs each request through the gateway pipeline and
// applies the verdict to the live connection.
//
// Plain HTTP is classified directly. HTTPS is tunneled blind by default (D74); with
// interception configured (a cert minter), a host not on the do-not-intercept list
// is TLS-terminated, its inner request classified through the same path as plain
// HTTP, and re-forwarded over origin TLS (D75). The verdict reaches the connection
// through the flow Table's disposition (set by the enforcer, applied HERE), so the
// enforcer never closes a socket the handler owns.
type Proxy struct {
	gw          *Gateway
	table       *Table
	rt          http.RoundTripper
	redirectURL string
	maxBody     int64
	logger      *slog.Logger

	// Interception (D75). minter == nil means interception OFF: all HTTPS is
	// tunneled blind (D74). noIntercept is the safe-default exclusion list; a match
	// is tunneled even when interception is on. originRT dials the real origin for
	// re-forwarded intercepted requests.
	minter      *CertMinter
	noIntercept []string
	originRT    http.RoundTripper

	// inspectResponses turns on response-body classification (NIPS-4). Off by
	// default: buffering every response is opt-in, so the default streaming
	// behavior and performance are unchanged.
	inspectResponses bool
}

// SetInspectResponses enables response-body classification (NIPS-4): the forward
// path buffers the response (memory-bounded), gzip-decodes it, and classifies it
// through the pipeline as an inbound event — observe-only, always delivering the
// exact upstream bytes and failing open.
func (p *Proxy) SetInspectResponses(on bool) { p.inspectResponses = on }

// NewProxy wires a Proxy. enforce turns blocking ON: with it false the proxy is
// observe-only (D1) — it classifies, decides and audits, but the flow enforcer is
// not registered, so every disposition stays allow and every flow is forwarded.
// Interception is OFF; call EnableInterception to turn it on (D75).
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
	return &Proxy{gw: gw, table: table, rt: rt, redirectURL: redirectURL, maxBody: maxBody, logger: logger, originRT: http.DefaultTransport}
}

// EnableInterception turns TLS interception ON: HTTPS to any host NOT on noIntercept
// is terminated with a leaf minted by minter and its inner request classified;
// excluded and unconfigured hosts are tunneled blind (D74). originRT dials the real
// origin (nil → http.DefaultTransport, which validates the origin normally). This is
// a deliberate, scary capability — the minter's CA can impersonate any site (D75).
func (p *Proxy) EnableInterception(minter *CertMinter, noIntercept []string, originRT http.RoundTripper) {
	if originRT == nil {
		originRT = http.DefaultTransport
	}
	p.minter = minter
	p.noIntercept = noIntercept
	p.originRT = originRT
}

// Intercepting reports whether TLS interception is enabled (a CA is configured).
func (p *Proxy) Intercepting() bool { return p.minter != nil }

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

	// A plain-HTTP forward-proxy request: r.URL is absolute and names the upstream.
	p.serve(w, r, r.URL.String(), p.rt)
}

// serve runs one request through the pipeline and applies the verdict to the
// connection. It is shared by the plain-HTTP path and the intercepted-HTTPS path
// (D75), so classify → decide → audit → disposition (forward/block/redirect) and
// fail-open are identical for both. targetURL is the absolute upstream URL and rt
// dials it (plain transport for HTTP, origin-TLS transport for intercepted HTTPS).
func (p *Proxy) serve(w http.ResponseWriter, r *http.Request, targetURL string, rt http.RoundTripper) {
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
		p.forward(w, r, body, targetURL, rt)
		return
	}

	switch p.table.Disposition(flowID) {
	case DispositionBlock:
		http.Error(w, "blocked by OpenShield policy", http.StatusForbidden)
	case DispositionRedirect:
		w.Header().Set("Location", p.redirectURL)
		w.WriteHeader(http.StatusFound)
	default:
		p.forward(w, r, body, targetURL, rt)
	}
}

// handleConnect handles an HTTPS CONNECT. If interception is enabled and the host
// is not on the do-not-intercept list, it terminates the TLS and classifies the
// inner request (D75); otherwise it establishes a BLIND TCP tunnel (D74) — the
// proxy relays ciphertext and classifies nothing, a stated, logged coverage gap.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := hostOnly(r.Host)
	if p.intercepts(host) {
		p.startIntercept(w, r)
		return
	}

	// This flow is tunneled uninspected — record it as metadata so the audit trail
	// shows uninspected egress rather than silence (D78). Reason distinguishes "no
	// interception configured" from "excluded by the do-not-intercept list".
	reason := "interception-disabled"
	if p.minter != nil {
		reason = "do-not-intercept"
	}
	p.gw.RecordTunnel(r.Context(), host, reason)

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

// intercepts reports whether a CONNECT host should be TLS-intercepted: interception
// must be configured (a minter) AND the host must not be on the do-not-intercept
// list. With no minter, everything tunnels (D74).
func (p *Proxy) intercepts(host string) bool {
	if p.minter == nil {
		return false
	}
	for _, ex := range p.noIntercept {
		ex = strings.TrimSpace(strings.ToLower(ex))
		if ex == "" {
			continue
		}
		h := strings.ToLower(host)
		// Exact host or domain suffix (".example.com" matches a.example.com and
		// example.com). Cert-pinned/sensitive hosts are tunneled, not MITM'd.
		if h == ex || strings.HasSuffix(h, "."+ex) {
			return false
		}
	}
	return true
}

// startIntercept acknowledges the CONNECT and hands the hijacked client connection
// to the TLS-termination path.
func (p *Proxy) startIntercept(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "gateway: cannot intercept (no hijack support)", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		return
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		client.Close()
		return
	}
	p.intercept(client, hostOnly(r.Host))
}

// intercept terminates the client's TLS with a minted leaf, then serves the
// decrypted HTTP/1.1 connection, running each inner request through the SAME
// pipeline as plain HTTP (D75). It blocks until the connection is done.
func (p *Proxy) intercept(client net.Conn, connectHost string) {
	p.logger.Info("gateway: intercepting HTTPS", "host", connectHost)
	tlsConn := tls.Server(client, &tls.Config{
		// SNI names the host; fall back to the CONNECT host when the client sends
		// no SNI (e.g. an IP literal), so the presented leaf still matches.
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = connectHost
			}
			return p.minter.ForHost(name)
		},
		// Force HTTP/1.1 so request framing is standard net/http (HTTP/2 and QUIC
		// interception are out of scope, D75).
		NextProtos: []string{"http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		p.logger.Warn("gateway: intercept handshake failed", "host", connectHost, "err", err.Error())
		client.Close()
		return
	}

	ln := newOneShotListener(tlsConn)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Inside the terminated TLS the request is origin-form (r.URL is path-only,
		// r.Host is the origin). Reconstruct the absolute https URL and re-forward
		// over origin TLS.
		target := "https://" + r.Host + r.URL.RequestURI()
		p.serve(w, r, target, p.originRT)
	})
	// http.Serve returns when the served connection closes (the one-shot listener
	// closes itself then), i.e. exactly when this tunnel is done.
	_ = http.Serve(ln, handler)
}

// oneShotListener yields a single connection to http.Serve, then blocks until that
// connection closes — at which point Accept returns an error so Serve returns.
// Without the block, Serve would Accept again immediately and return while the
// request was still in flight.
type oneShotListener struct {
	ch   chan net.Conn
	conn net.Conn
	once sync.Once
}

var errListenerDone = errors.New("gateway: intercept connection closed")

func newOneShotListener(c net.Conn) *oneShotListener {
	l := &oneShotListener{ch: make(chan net.Conn, 1), conn: c}
	// Wrap so that when net/http closes the served conn, the listener shuts and
	// http.Serve's next Accept returns — Serve returns only when the conn is done.
	l.ch <- &closeNotifyConn{Conn: c, onClose: l.shut}
	return l
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	c, ok := <-l.ch
	if !ok {
		return nil, errListenerDone
	}
	return c, nil
}

func (l *oneShotListener) Close() error   { l.shut(); return nil }
func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }
func (l *oneShotListener) shut()          { l.once.Do(func() { close(l.ch) }) }

// closeNotifyConn fires onClose once, the first time the connection is closed.
type closeNotifyConn struct {
	net.Conn
	once    sync.Once
	onClose func()
}

func (c *closeNotifyConn) Close() error {
	c.once.Do(c.onClose)
	return c.Conn.Close()
}

// hostOnly strips the port from a host:port authority, leaving the host.
func hostOnly(hostPort string) string {
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		return h
	}
	return hostPort
}

// forward sends the buffered request to targetURL via rt and copies the response
// back. targetURL is absolute (the request URL for plain HTTP; the reconstructed
// https origin URL for intercepted requests), and rt is the matching transport.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, body []byte, targetURL string, rt http.RoundTripper) {
	out, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "gateway: building upstream request", http.StatusBadGateway)
		return
	}
	copyHeader(out.Header, r.Header)
	out.Host = r.Host

	resp, err := rt.RoundTrip(out)
	if err != nil {
		http.Error(w, "gateway: upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if p.inspectResponses {
		p.forwardInspected(w, r, resp)
		return
	}
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// forwardInspected classifies the response body (NIPS-4) and delivers the exact
// upstream bytes. Over-cap or on error it fails open (delivers, audits the gap);
// observe-only, so the response is always delivered.
func (p *Proxy) forwardInspected(w http.ResponseWriter, r *http.Request, resp *http.Response) {
	prefix, tooLarge, err := readBoundedKeep(resp.Body, p.maxBody)
	if err != nil {
		// Fail open: deliver whatever remains rather than break the client's response.
		p.logger.Error("gateway: response read error, failing open (delivered uninspected)",
			"err", err, "host", r.Host)
		p.deliver(w, resp, io.MultiReader(bytes.NewReader(prefix), resp.Body))
		return
	}
	if tooLarge {
		// A response over the cap cannot be buffered — deliver it intact, uninspected,
		// and record the coverage gap (never refuse or truncate the client's response).
		p.gw.RecordTunnel(r.Context(), hostOnly(r.Host), "response-over-cap-uninspected")
		p.logger.Warn("gateway: response over cap, delivered uninspected (NIPS-4 gap)",
			"cap", p.maxBody, "host", r.Host)
		p.deliver(w, resp, io.MultiReader(bytes.NewReader(prefix), resp.Body))
		return
	}

	// Classify the DECODED content (gzip-decoded if needed), but forward the ORIGINAL
	// bytes so the client's negotiated encoding is honored.
	plain := maybeGunzip(prefix, resp.Header, p.maxBody)
	req := requestFromHTTP(newFlowID(), r, plain)
	req.Direction = corev1.NetworkDirection_NETWORK_DIRECTION_INGRESS
	if _, perr := p.gw.Process(r.Context(), req); perr != nil {
		// The failure is audited by Process; deliver the response anyway (fail open).
		p.logger.Error("gateway: response classify error, failing open (delivered)",
			"err", perr, "host", r.Host)
	}
	p.deliver(w, resp, bytes.NewReader(prefix))
}

// deliver copies the response headers/status and the given body to the client.
func (p *Proxy) deliver(w http.ResponseWriter, resp *http.Response, body io.Reader) {
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, body)
}

// requestFromHTTP builds a gateway.Request from an incoming proxy request. The
// 5-tuple is best-effort (RemoteAddr for the source, the request URL for the
// destination); the metadata drives the policy, the buffered body is classified.
func requestFromHTTP(flowID string, r *http.Request, body []byte) *Request {
	srcIP, srcPort := splitHostPort(r.RemoteAddr)
	// The destination authority is r.Host in both forms: a plain proxy request
	// carries the target host, and an intercepted (origin-form) request carries the
	// origin host, whereas r.URL is path-only once TLS is terminated.
	dstIP, dstPort := splitHostPort(r.Host)
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

// readBoundedKeep is like readBounded but RETURNS the read prefix even when the
// input exceeds max — so an over-cap RESPONSE can still be delivered (the prefix
// plus the unread remainder), unlike a request which is refused.
func readBoundedKeep(r io.Reader, max int64) (prefix []byte, tooLarge bool, err error) {
	if r == nil {
		return nil, false, nil
	}
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return b, false, err
	}
	if int64(len(b)) > max {
		return b, true, nil
	}
	return b, false, nil
}

// maybeGunzip returns the decompressed body when the response is gzip-encoded, so
// the detectors classify the actual content, not compressed noise. Bounded
// (decompression-bomb safe): at most max bytes are decompressed. A decode failure
// degrades to the raw bytes — never a failure of delivery.
func maybeGunzip(body []byte, header http.Header, max int64) []byte {
	if !strings.Contains(strings.ToLower(header.Get("Content-Encoding")), "gzip") {
		return body
	}
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return body
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, max))
	if err != nil || len(out) == 0 {
		return body
	}
	return out
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
