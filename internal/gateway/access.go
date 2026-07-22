package gateway

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/gateway/identity"
	"github.com/lucianoengel/openshield/internal/xdr"
)

// AccessProxy is the identity-aware reverse/access proxy (D87): a BeyondCorp-style
// access broker that authenticates a client by certificate (D86), authorizes the
// request per-identity through the pipeline (D85), and reverse-proxies allowed
// requests to an internal service. It is the REVERSE of the egress forward proxy
// (D73): a client connects TO the gateway to reach an internal service.
//
// ACCESS FAILS CLOSED. The egress proxy fails OPEN on a pipeline error (availability
// of monitored traffic, D73/D17); the access proxy DENIES on an error, because
// granting entry to a guarded service on a failure is the one thing a Zero-Trust
// gate must never do. The two directions protect opposite things and therefore fail
// in opposite directions.
type AccessProxy struct {
	gw      *Gateway
	catalog *Catalog
	maxBody int64
	logger  *slog.Logger

	// risk, when set, supplies published per-subject risk for continuous
	// verification (D89): the access decision context is enriched with it so the
	// LOCAL policy can step-up/deny on rising risk. nil = no risk enrichment.
	risk *RiskStore

	// posture, when set, supplies published per-subject device posture (D92): the
	// access decision context is enriched with it. A subject with NO published
	// posture keeps HasPosture=false and a posture-requiring policy denies it (the
	// D85 tamper-lockout). nil = no posture enrichment.
	posture *PostureStore

	// oidc, when set, resolves the USER identity from a verified OIDC/JWT bearer token (ZT-2, SSO)
	// — layered on the mTLS DEVICE certificate the connection already requires. nil = the client
	// certificate is the identity (the pre-SSO behavior).
	oidc *identity.OIDCVerifier

	// attest, when set, supplies the gateway's SERVER-VERIFIED hardware-attestation
	// verdict per device (ZT-1). It overlays DevicePosture.Attested with the gateway's
	// own conclusion from verifying a TPM quote — never a self-reported value — so a
	// policy can require a hardware-attested device. nil = no attestation enrichment.
	attest *AttestationVerifier

	// graph, when set, is the XDR entity graph (XDR-1-WIRE): a dual-credential request links its
	// DEVICE (cert CN pseudonym) and USER (OIDC subject) aliases to one entity, so a device and the
	// user on it coalesce. Best-effort and asynchronous — never on the request's critical path.
	graph *xdr.Store
	// EntityLinkFailures counts best-effort device⋈user links that failed — observable, never fatal.
	EntityLinkFailures atomic.Int64
}

// SetAttestationVerifier enables hardware-attestation-aware access (ZT-1): the access
// handler sets DevicePosture.Attested from the gateway's own verification of the
// device's TPM quote, independent of (and unforgeable by) the self-reported posture.
func (p *AccessProxy) SetAttestationVerifier(v *AttestationVerifier) { p.attest = v }

// SetOIDCVerifier enables SSO identity: the access handler resolves the request's user identity from
// a verified OIDC/JWT bearer token (ZT-2). The device certificate is still required at the TLS layer;
// the token supplies the user's subject+role. When set, a request MUST carry a valid token.
func (p *AccessProxy) SetOIDCVerifier(v *identity.OIDCVerifier) { p.oidc = v }

// SetPostureStore enables device-posture-aware access (D92): the access handler
// enriches each request's identity context with the connecting subject's published
// posture, so a policy can require an attested, compliant device (D85). A device with
// no published posture fails closed (the tamper-lockout).
func (p *AccessProxy) SetPostureStore(s *PostureStore) { p.posture = s }

// SetRiskStore enables risk-driven continuous verification (D89): the access handler
// enriches each request's identity context with the connecting subject's published
// risk, and the local policy decides step-up/deny. The server publishes risk (data);
// the gateway decides (T2) — the server never commands.
func (p *AccessProxy) SetRiskStore(r *RiskStore) { p.risk = r }

// SetEntityGraph enables device⋈user population of the XDR entity graph (XDR-1-WIRE): when a request
// authenticates with both a device certificate and a distinct OIDC user, the proxy links them into one
// entity, asynchronously and best-effort. nil = no graph population (the pre-XDR behavior).
func (p *AccessProxy) SetEntityGraph(g *xdr.Store) { p.graph = g }

// linkDeviceUser fires a best-effort, ASYNC device⋈user link so a proxied request never waits on a
// graph write (XDR-1-WIRE). A failure is counted, never surfaced to the request.
func (p *AccessProxy) linkDeviceUser(deviceSubject, userSubject string) {
	if p.graph == nil || deviceSubject == "" || userSubject == "" || deviceSubject == userSubject {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := p.graph.Link(ctx, xdr.KindDevice, deviceSubject, xdr.KindUser, userSubject); err != nil {
			p.EntityLinkFailures.Add(1)
			p.logger.Warn("gateway: entity-graph device-user link failed", "err", err)
		}
	}()
}

// NewAccessProxy fronts the catalog of internal services (D88). The server that runs
// it MUST require and verify a client certificate at the TLS layer
// (RequireAndVerifyClientCert) — this handler reads the already-verified peer cert.
func NewAccessProxy(gw *Gateway, catalog *Catalog, maxBody int64, logger *slog.Logger) *AccessProxy {
	if maxBody <= 0 {
		maxBody = DefaultMaxBody
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &AccessProxy{gw: gw, catalog: catalog, maxBody: maxBody, logger: logger}
}

// resolveUser determines the request's USER identity given the already-resolved DEVICE identity
// (ZT-3, dual-credential). When an OIDC verifier is configured (ZT-2, SSO), the user comes from a
// verified bearer token — required and verified; otherwise the device certificate IS the user
// (single-credential). Error messages are generic (no token/verifier detail leaked).
func (p *AccessProxy) resolveUser(r *http.Request, deviceID *identity.Identity) (*identity.Identity, int, error) {
	if p.oidc == nil {
		return deviceID, 0, nil // single-credential: the device cert is the identity
	}
	tok := bearerToken(r.Header.Get("Authorization"))
	if tok == "" {
		return nil, http.StatusUnauthorized, errNoBearer
	}
	// R34-10: pass the DPoP proof (if any) and the request binding so a sender-constrained token
	// (cnf.jkt) is only accepted from the device that holds the bound key. A non-DPoP token verifies
	// unchanged. htu is the method-agnostic request URI; scheme+host+path per RFC 9449 (query/fragment
	// excluded by the proof issuer) — we use the effective request URI the gateway received.
	id, err := p.oidc.VerifyWithProof(tok, r.Header.Get("DPoP"), r.Method, requestURI(r))
	if err != nil {
		return nil, http.StatusForbidden, errBadBearer
	}
	return id, 0, nil
}

// requestURI reconstructs the htu the DPoP proof must be bound to: scheme://host/path with no query
// or fragment (RFC 9449 §4.3). TLS presence picks the scheme; the Host header names the authority.
func requestURI(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.Path
}

var (
	errNoBearer      = errAccess("bearer token required")
	errBadBearer     = errAccess("invalid bearer token")
	errDeviceUnknown = errAccess("device not enrolled")
)

type errAccess string

func (e errAccess) Error() string { return string(e) }

// bearerToken extracts the token from an "Authorization: Bearer <token>" header, or "" if absent or
// not a bearer scheme (case-insensitive scheme, exactly one space).
func bearerToken(authz string) string {
	const prefix = "bearer "
	if len(authz) <= len(prefix) {
		return ""
	}
	if !strings.EqualFold(authz[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(authz[len(prefix):])
}

func (p *AccessProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Authenticate: a verified client (device) certificate is ALWAYS required at the TLS layer (D86).
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	// The DEVICE credential (ZT-3): the enrolled client certificate. Required always — dual
	// credential means BOTH a valid device AND (when OIDC is on) a valid user.
	deviceID, err := identity.FromClientCert(r.TLS.PeerCertificates[0])
	if err != nil {
		http.Error(w, errDeviceUnknown.Error(), http.StatusForbidden)
		return
	}
	// The USER credential: a verified OIDC token (ZT-2) or the device cert itself (single-credential).
	id, status, err := p.resolveUser(r, deviceID)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	// XDR-1-WIRE: with a distinct user (OIDC on), link device⋈user in the entity graph — async and
	// best-effort, so it neither delays nor can fail this request.
	p.linkDeviceUser(deviceID.Subject, id.Subject)

	// Route to a catalogued internal service. An unknown service is refused (404),
	// never forwarded — the gateway is an allow-list, not an open relay (D88).
	svc, ok := p.catalog.Resolve(hostOnly(r.Host))
	if !ok {
		http.Error(w, "unknown service", http.StatusNotFound)
		return
	}

	// Buffer the body: it is both classified (DLP on the request) and forwarded.
	body, tooLarge, err := readBounded(r.Body, p.maxBody)
	if err != nil {
		http.Error(w, "gateway: reading request body", http.StatusBadGateway)
		return
	}
	if tooLarge {
		http.Error(w, "gateway: request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	// Resolve the identity context, enriched with the subject's PUBLISHED risk for
	// continuous verification (D89): the policy can step-up/deny a subject whose risk
	// rose mid-session. Absent risk is left unset (not high) — the opposite
	// fail-direction from posture (D85).
	idCtx := id.Context()
	if p.risk != nil {
		if score, ok := p.risk.Get(id.Subject); ok {
			idCtx.RiskScore = score
			idCtx.HasRiskScore = true
		}
	}
	// Enrich device posture (D92), keyed by the DEVICE certificate — NOT the user (ZT-3). Posture is
	// about the device the user connects FROM (the agent reports its own device's posture, keyed by
	// the device identity, SEC-12). So a user with a valid token on an UNATTESTED device is still
	// denied by a posture-requiring policy: dual credential requires a valid user AND a compliant
	// device. A device with NO published posture keeps HasPosture=false — the D85 tamper-lockout.
	if p.posture != nil {
		if dp, ok := p.posture.Get(deviceID.Subject); ok {
			idCtx.DevicePosture = dp
		}
	}
	// Overlay the gateway's SERVER-VERIFIED attestation verdict (ZT-1). Attested is
	// set ONLY from the gateway's own quote verification, never from the endpoint's
	// self-reported posture — so a compromised endpoint cannot claim attestation. An
	// attested device also has posture present (we verified something about it); an
	// unverified device keeps Attested=false, and a policy requiring it fails closed.
	if p.attest != nil {
		if p.attest.IsAttested(deviceID.Subject) {
			idCtx.DevicePosture.Attested = true
			idCtx.DevicePosture.HasPosture = true
		} else {
			idCtx.DevicePosture.Attested = false
		}
	}

	// Authorize through the pipeline on the verified identity AND the target service
	// (D88): Host is the resolved service, so the policy can microsegment per service.
	req := &Request{
		FlowID:   newFlowID(),
		SrcIP:    r.RemoteAddr,
		Protocol: "tcp",
		Host:     svc.name,
		Method:   r.Method,
		Path:     r.URL.Path,
		Body:     body,
		Identity: idCtx,
	}
	dec, perr := p.gw.Process(r.Context(), req)
	if perr != nil || dec == nil {
		// FAIL CLOSED (D87): a pipeline error denies access — the opposite of the
		// egress proxy's fail-open. A Zero-Trust gate never admits on an error.
		p.logger.Error("gateway: access decision failed, denying (fail-closed)",
			"err", perr, "subject", id.Subject)
		http.Error(w, "access denied (decision unavailable)", http.StatusForbidden)
		return
	}
	if dec.GetAction() != corev1.Action_ACTION_ALLOW {
		http.Error(w, "access denied by policy", http.StatusForbidden)
		return
	}

	// Allowed: reverse-proxy to the resolved internal service with the body reset.
	// SEC-9: strip any client-supplied identity/forwarding headers so a backend cannot be
	// fed a SPOOFED identity, and inject the gateway-authoritative verified subject so the
	// backend can consume the REAL (pseudonymous, D23) identity. A client that sets
	// X-Authenticated-User (or pre-sets X-OpenShield-Subject) must not have it trusted.
	sanitizeIdentityHeaders(r.Header)
	r.Header.Set(subjectHeader, id.Subject)
	r.Body = io.NopCloser(bytes.NewReader(body))
	svc.proxy.ServeHTTP(w, r)
}

// subjectHeader is the gateway-authoritative verified-subject header injected for backends.
const subjectHeader = "X-Openshield-Subject"

// spoofableIdentityHeaders are client-supplied headers a backend might mistake for an
// authenticated identity or a trustworthy forwarding chain. The access proxy STRIPS them
// (SEC-9) so only the gateway-injected subjectHeader carries identity.
var spoofableIdentityHeaders = []string{
	"X-Openshield-Subject", // never let a client pre-set the trusted header
	"X-Authenticated-User",
	"X-Auth-User",
	"X-User",
	"X-Remote-User",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Forwarded-User",
	"X-Real-Ip",
	"Forwarded",
}

func sanitizeIdentityHeaders(h http.Header) {
	for _, name := range spoofableIdentityHeaders {
		h.Del(name)
	}
}
