// Package ztna is the ENDPOINT side of Zero-Trust access (ZT-4): the agent-brokered client.
//
// OpenShield's access proxy already authorizes a request with device certificate + OIDC user + attestation
// + posture (D86–D88, ZT-1/ZT-3). That is the server half. Every commercial ZTNA (Zscaler ZPA, Cloudflare
// Access, Tailscale) also ships the ENDPOINT half: an agent applications talk to, which presents the
// DEVICE's identity to the broker so the connection is authorized by the device, not by whatever the
// application happened to configure.
//
// This is that agent. Applications point at it with the ordinary HTTP_PROXY convention — no application
// changes, no root, no kernel interface.
//
// WHAT IT IS NOT, and this is stated here because the name invites the wrong reading: it BROKERS access, it
// does not PREVENT bypass. An application with a direct route to the internal network can still take it.
// Commercial ZTNA clients enforce the path with routing and firewall rules; OpenShield has the mechanism
// for that (the NIPS-1 transparent inline plane) but wiring it here is a separate ticket. Until then this
// is an access broker, not a network jail.
package ztna

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrNoDeviceIdentity means the client has no device certificate to present.
//
// It is fatal on purpose: a broker that starts without the identity it exists to present would forward
// traffic unauthenticated while looking like protection, which is worse than not running at all.
var ErrNoDeviceIdentity = errors.New("ztna: no device certificate — the broker will not start without the identity it exists to present")

// Client is the endpoint broker.
type Client struct {
	// BrokerURL is the access proxy's base URL (https://…).
	BrokerURL *url.URL
	// DeviceCert is the enrolled device certificate presented as the TLS client identity (ZT-3).
	DeviceCert tls.Certificate
	// RootCAs verifies the broker.
	RootCAs *tls.Config
	// Token is the user's bearer credential, attached per request. Never logged.
	Token string
	// Timeout bounds one brokered request.
	Timeout time.Duration
	// Logf is optional.
	Logf func(format string, a ...any)

	http *http.Client
}

// New builds a broker client, refusing without a device identity.
func New(broker *url.URL, cert tls.Certificate, tlsCfg *tls.Config, token string) (*Client, error) {
	if len(cert.Certificate) == 0 {
		return nil, ErrNoDeviceIdentity
	}
	if broker == nil {
		return nil, errors.New("ztna: no broker URL")
	}
	cfg := tlsCfg.Clone()
	cfg.Certificates = []tls.Certificate{cert}
	c := &Client{BrokerURL: broker, DeviceCert: cert, RootCAs: cfg, Token: token, Timeout: 30 * time.Second}
	c.http = &http.Client{
		Timeout:   c.Timeout,
		Transport: &http.Transport{TLSClientConfig: cfg},
		// A brokered request must not be silently redirected somewhere else: the broker's answer is the
		// answer, and following a redirect could take the request off the authorized path.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c, nil
}

// ListenAndServe serves the local proxy. addr MUST be a loopback address: a broker bound to a routable
// interface is a relay that anyone on the LAN could drive with THIS DEVICE's identity.
func (c *Client) ListenAndServe(addr string) error {
	if err := requireLoopback(addr); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return http.Serve(ln, c)
}

// requireLoopback refuses any bind address that is not loopback.
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("ztna: bad listen address %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("ztna: refusing to listen on %q — the broker must bind loopback only, or any host "+
			"on the network could use this device's identity to reach internal services", addr)
	}
	return nil
}

// ServeHTTP brokers one application request.
//
// It NEVER falls back: a refusal from the broker is returned to the application as an error, and no direct
// connection to the internal service is attempted. A client that "helpfully" retried would turn a
// Zero-Trust denial into an ordinary network request — the worst available outcome.
func (c *Client) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	target := *c.BrokerURL
	target.Path = r.URL.Path
	target.RawQuery = r.URL.RawQuery

	body := io.Reader(r.Body)
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), body)
	if err != nil {
		http.Error(w, "ztna: building the brokered request: "+err.Error(), http.StatusBadGateway)
		return
	}
	copyHeaders(req.Header, r.Header)
	// The internal service is selected by the requested HOST; the broker resolves it through its allow-list
	// catalog (D88), so an uncatalogued host is refused there rather than reachable from here.
	req.Host = r.Host
	req.Header.Set("Host", r.Host)
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		// A transport failure is NOT a reason to try the internal service directly.
		http.Error(w, "ztna: broker unreachable: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		// Surface the broker's own reason: an operator debugging "why can't I reach the wiki" needs
		// "access denied by policy", not an opaque failure.
		reason, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if c.Logf != nil {
			c.Logf("ztna: broker REFUSED %s %s: %s", r.Method, r.Host, strings.TrimSpace(string(reason)))
		}
		http.Error(w, "ztna: access refused by the broker: "+strings.TrimSpace(string(reason)), resp.StatusCode)
		return
	}
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		// Hop-by-hop headers must not be forwarded.
		switch strings.ToLower(k) {
		case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade", "te", "trailer":
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}
