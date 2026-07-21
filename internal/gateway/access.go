package gateway

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/gateway/identity"
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
}

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

func (p *AccessProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Authenticate: a verified client certificate is required (D86).
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	id, err := identity.FromClientCert(r.TLS.PeerCertificates[0])
	if err != nil {
		http.Error(w, "not a valid client identity", http.StatusForbidden)
		return
	}

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
	// Enrich device posture (D92): a subject with published posture gets it (with
	// HasPosture=true); a subject with NONE keeps HasPosture=false and a
	// posture-requiring policy denies it — the D85 tamper-lockout.
	if p.posture != nil {
		if dp, ok := p.posture.Get(id.Subject); ok {
			idCtx.DevicePosture = dp
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
	r.Body = io.NopCloser(bytes.NewReader(body))
	svc.proxy.ServeHTTP(w, r)
}
