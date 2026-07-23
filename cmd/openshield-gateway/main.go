// Command openshield-gateway runs the network gateway data plane (N1.2b).
//
// It is a plain-HTTP forward proxy: it accepts a client connection, runs each
// request through the gateway pipeline (classify in the sandboxed worker, D72 →
// policy → decide → audit), and applies the verdict to the live connection —
// forward, block, or redirect. Like the engine (D62) it is unprivileged and
// network-capable, holding the ledger and OPA but NOT the parser: it spawns the
// worker rather than classifying itself, so a parser bug is not an RCE in the
// process holding the network sockets (D72).
//
// Observe-only by DEFAULT (D1): unless OPENSHIELD_ENFORCE is set, the proxy
// classifies, decides and audits but forwards every flow. HTTPS is tunneled blind
// unless an interception CA is configured (OPENSHIELD_INTERCEPT_CA_CERT/KEY, D75),
// in which case non-excluded hosts are TLS-intercepted and their bodies classified;
// the do-not-intercept list (OPENSHIELD_NO_INTERCEPT) tunnels pinned/sensitive
// hosts blind.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	enrollpkg "github.com/lucianoengel/openshield/internal/agent/enroll"
	"github.com/lucianoengel/openshield/internal/agent/identity"
	"github.com/lucianoengel/openshield/internal/agent/privileged"
	"github.com/lucianoengel/openshield/internal/casb"
	"github.com/lucianoengel/openshield/internal/core"
	"github.com/lucianoengel/openshield/internal/dnsredirect"
	"github.com/lucianoengel/openshield/internal/dnssink"
	identitypkg "github.com/lucianoengel/openshield/internal/gateway/identity"
	"github.com/lucianoengel/openshield/internal/attest"
	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/nips"
	"github.com/lucianoengel/openshield/internal/policy"
	"github.com/lucianoengel/openshield/internal/retain"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lucianoengel/openshield/internal/store/postgres"
	"github.com/lucianoengel/openshield/internal/xdr"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
	"github.com/nats-io/nats.go"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	listen := env("OPENSHIELD_LISTEN", "127.0.0.1:8080")
	dsn := env("OPENSHIELD_DSN", "postgres://openshield:dev@127.0.0.1:55432/openshield?sslmode=disable")
	workerBin := env("OPENSHIELD_WORKER_BIN", "/usr/local/bin/openshield-worker")
	signerFile := env("OPENSHIELD_SIGNER_FILE", "/var/lib/openshield/gateway-signer.state")
	redirectURL := env("OPENSHIELD_REDIRECT_URL", "https://openshield.invalid/coaching")
	enforce := os.Getenv("OPENSHIELD_ENFORCE") != ""

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	signer, err := loadOrCreateSigner(signerFile, log)
	if err != nil {
		fatal(log, "signer", err)
	}
	ledger, err := postgres.Open(ctx, dsn, signer)
	if err != nil {
		fatal(log, "opening ledger", err)
	}
	defer ledger.Close()

	// Enforce local-ledger retention on a timer (D81): tombstone bounded-class
	// entries past their age so content is erased while the hash chain stays
	// verifiable (D36). The Purge exists (T-013) but was never scheduled (D20).
	go retain.Loop(ctx, envDuration("OPENSHIELD_RETENTION_INTERVAL", 24*time.Hour), func(ctx context.Context) {
		n, err := ledger.Purge(ctx, time.Now())
		if err != nil {
			log.Error("retention purge failed", slog.String("err", err.Error()))
			return
		}
		if n > 0 {
			log.Info("retention purge tombstoned entries", slog.Int64("rows", n))
		}
	})

	// DLP-5b: compliance packs (OPENSHIELD_POLICY_PACK[S], + optional OPENSHIELD_POLICY_CUSTOM)
	// COMPOSE with the observe-only default under a most-restrictive-wins lattice (ADR-5) — selecting
	// a pack never disables the default's protections. An unknown pack aborts startup: a compliance
	// control must not silently fall back to a permissive policy.
	pol, err := policy.SelectFromEnv(ctx)
	if err != nil {
		fatal(log, "loading policy", err)
	}
	log.Info("policy loaded (DLP-5b: packs compose with the default)", slog.String("bundle", pol.Bundle()))

	poolSize := envInt("OPENSHIELD_WORKER_POOL", 4)
	pool, err := privileged.StartPool(ctx, workerBin, poolSize)
	if err != nil {
		fatal(log, "starting worker pool", err)
	}
	defer pool.Close()

	// Zero-Trust ACCESS MODE (D90): a gateway runs as EITHER an egress forward proxy
	// (below) OR a client-cert access proxy — different roles, different ports. When
	// OPENSHIELD_ACCESS_MODE is set, run the access proxy and return.
	if os.Getenv("OPENSHIELD_ACCESS_MODE") != "" {
		runAccessMode(ctx, log, pool, ledger)
		return
	}

	// The pool satisfies gateway.New's classifier interface (same Classify method as
	// a single worker), so concurrent flows classify in parallel (D76).
	gw := gateway.New(pool, pol, ledger, log, 30*time.Second)
	applyThreatFeed(ctx, gw, log)
	applyCasbCatalog(ctx, log)
	applyTProxy(ctx, gw, log)
	applyDNSSink(ctx, gw, log)
	table := gateway.NewTable()
	proxy := gateway.NewProxy(gw, table, nil, redirectURL, gateway.DefaultMaxBody, enforce, log)
	// NIPS-4: opt-in response-body inspection (classify + audit the response, not only
	// the request). Off by default — buffering every response is a deliberate choice.
	if os.Getenv("OPENSHIELD_INSPECT_RESPONSES") != "" {
		proxy.SetInspectResponses(true)
		log.Info("gateway: NIPS-4 response-body inspection enabled (observe-only, fail-open)")
	}

	// TLS interception is OPT-IN: only when an interception CA is configured. It is
	// a deliberate, scary capability — the CA can impersonate any site (D75) — so it
	// is never on by default. The do-not-intercept list tunnels pinned/sensitive
	// hosts blind even when it is on.
	if caCert, caKey := os.Getenv("OPENSHIELD_INTERCEPT_CA_CERT"), os.Getenv("OPENSHIELD_INTERCEPT_CA_KEY"); caCert != "" && caKey != "" {
		certPEM, err := os.ReadFile(caCert)
		if err != nil {
			fatal(log, "reading interception CA cert", err)
		}
		keyPEM, err := os.ReadFile(caKey)
		if err != nil {
			fatal(log, "reading interception CA key", err)
		}
		minter, err := gateway.NewCertMinter(certPEM, keyPEM)
		if err != nil {
			fatal(log, "interception CA", err)
		}
		proxy.EnableInterception(minter, splitList(os.Getenv("OPENSHIELD_NO_INTERCEPT")), nil)
		log.Warn("gateway: TLS INTERCEPTION ENABLED — the interception CA can impersonate any site (D75)",
			slog.Int("do_not_intercept", len(splitList(os.Getenv("OPENSHIELD_NO_INTERCEPT")))))

		// SIGHUP hot-rotates the interception CA without a restart (D79): reload the
		// CA files and Rotate. A reload error is logged and the old CA keeps serving
		// (fail-safe) — a bad rotation must not break interception.
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		go func() {
			for range hup {
				nc, err1 := os.ReadFile(caCert)
				nk, err2 := os.ReadFile(caKey)
				if err1 != nil || err2 != nil {
					log.Error("gateway: CA reload read failed (old CA still serving)", slog.Any("cert_err", err1), slog.Any("key_err", err2))
					continue
				}
				if err := minter.Rotate(nc, nk); err != nil {
					log.Error("gateway: interception CA rotation failed (old CA still serving)", slog.String("err", err.Error()))
					continue
				}
				log.Warn("gateway: interception CA ROTATED (SIGHUP) — leaf cache flushed (D79)")
			}
		}()
	}

	// OPTIONAL telemetry projection to the control plane (D77): when NATS + an
	// enrollment endpoint are configured, enroll a signed identity and project a
	// boundary-safe view of decisions. Off by default; the local ledger is always
	// the system of record.
	if natsURL, enrollURL := os.Getenv("OPENSHIELD_NATS_URL"), os.Getenv("OPENSHIELD_ENROLL_URL"); natsURL != "" && enrollURL != "" {
		agentID := env("OPENSHIELD_AGENT_ID", "gateway")
		id, err := identity.Generate(agentID)
		if err != nil {
			fatal(log, "identity", err)
		}
		if err := enrollpkg.Enroll(ctx, http.DefaultClient, enrollURL, agentID, os.Getenv("OPENSHIELD_ENROLL_TOKEN"), id); err != nil {
			fatal(log, "enroll", err)
		}
		conn, err := nats.Connect(natsURL)
		if err != nil {
			fatal(log, "nats", err)
		}
		defer conn.Close()
		var pub *natsx.SignedPublisher
		if seqFile := os.Getenv("OPENSHIELD_SEQ_FILE"); seqFile != "" {
			pub, err = natsx.NewSignedPublisherWithSeq(agentID, id, conn, natsx.NewFileSeqStore(seqFile))
			if err != nil {
				fatal(log, "sequence store", err)
			}
		} else {
			pub = natsx.NewSignedPublisher(agentID, id, conn)
		}
		gw.SetTelemetry(pub)
		log.Info("gateway: telemetry projection ENABLED (boundary-safe: no user IP, no URL path)",
			slog.String("agent_id", agentID))
	}

	srv := &http.Server{Addr: listen, Handler: proxy, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	log.Info("gateway proxying",
		slog.String("listen", listen),
		slog.String("worker", workerBin),
		slog.Bool("enforce", enforce),
		slog.Bool("intercept", proxy.Intercepting()))
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatal(log, "serving", err)
	}
	log.Info("gateway shut down")
}

// runAccessMode serves the Zero-Trust access proxy (D90): the AccessProxy over
// client-certificate-required TLS, with a file-loaded default-deny access policy, an
// env service catalog, and a RiskStore. Config is fail-fast and LOUD — a ZT gate must
// never boot misconfigured and permissive; the failure mode is "does not start",
// never "starts and admits everyone".
func runAccessMode(ctx context.Context, log *slog.Logger, cls *privileged.Pool, ledger core.Ledger) {
	listen := env("OPENSHIELD_ACCESS_LISTEN", "127.0.0.1:8443")
	clientCA := os.Getenv("OPENSHIELD_ACCESS_CLIENT_CA")
	serverCert := os.Getenv("OPENSHIELD_ACCESS_SERVER_CERT")
	serverKey := os.Getenv("OPENSHIELD_ACCESS_SERVER_KEY")
	policyPath := os.Getenv("OPENSHIELD_ACCESS_POLICY")

	if clientCA == "" || serverCert == "" || serverKey == "" || policyPath == "" {
		fatal(log, "access mode", errNoAccessConfig)
	}

	// The access policy is identity-aware and DEFAULT-DENY (D87) — only the operator
	// can author it. Load it, or abort: never fall back to the observe-first default
	// (which is default-ALLOW and would admit everyone).
	mod, err := os.ReadFile(policyPath)
	if err != nil {
		fatal(log, "reading access policy", err)
	}
	accessPol, err := policy.New(ctx, "access", "1", string(mod))
	if err != nil {
		fatal(log, "access policy", err)
	}

	catalog, err := gateway.ParseCatalog(os.Getenv("OPENSHIELD_ACCESS_CATALOG"))
	if err != nil {
		fatal(log, "access catalog", err)
	}
	if catalog.Len() == 0 {
		fatal(log, "access catalog", errEmptyCatalog)
	}

	caPEM, err := os.ReadFile(clientCA)
	if err != nil {
		fatal(log, "reading client CA", err)
	}
	clientPool := x509.NewCertPool()
	if !clientPool.AppendCertsFromPEM(caPEM) {
		fatal(log, "client CA", errNoCerts)
	}
	kp, err := tls.LoadX509KeyPair(serverCert, serverKey)
	if err != nil {
		fatal(log, "access server certificate", err)
	}

	gw := gateway.New(cls, accessPol, ledger, log, 30*time.Second)
	applyThreatFeed(ctx, gw, log)
	applyCasbCatalog(ctx, log)
	ap := gateway.NewAccessProxy(gw, catalog, gateway.DefaultMaxBody, log)
	riskStore := gateway.NewRiskStore()
	ap.SetRiskStore(riskStore)
	postureStore := gateway.NewPostureStore()
	ap.SetPostureStore(postureStore)
	// XDR-1-WIRE: populate the device⋈user edge of the entity graph from the real dual-credential
	// path, reusing the ledger's DB pool (same database). Best-effort/async — never affects a request.
	// The Postgres ledger exposes its pool; a non-Postgres ledger simply gets no graph (capability check).
	if pg, ok := ledger.(interface{ Pool() *pgxpool.Pool }); ok {
		ap.SetEntityGraph(xdr.NewStore(pg.Pool()))
	}

	// OIDC SSO identity (ZT-2): when OPENSHIELD_OIDC_ISSUER is set, the access proxy resolves the
	// USER identity from a verified bearer token (subject+role from the token), layered on the mTLS
	// DEVICE cert. Keys are loaded from a directory of <kid>.pem public keys (static-key wiring; live
	// JWKS discovery is a follow-up). A misconfigured OIDC block aborts startup — a ZT gate must not
	// come up with a broken identity source.
	if issuer := os.Getenv("OPENSHIELD_OIDC_ISSUER"); issuer != "" {
		audience := os.Getenv("OPENSHIELD_OIDC_AUDIENCE")
		roleClaim := env("OPENSHIELD_OIDC_ROLE_CLAIM", "groups")
		var v *identitypkg.OIDCVerifier
		// ZT-2b/ADR-7: when a JWKS URL is set, source the signing keys from a live JWKS refresher so an
		// IdP key rotation is picked up without a restart — background refresh, serve-stale on failure,
		// rate-limited on a kid miss, never fetching on the request path. Else the static PEM keys.
		if jwksURL := os.Getenv("OPENSHIELD_OIDC_JWKS_URL"); jwksURL != "" {
			interval := envDuration("OPENSHIELD_OIDC_JWKS_INTERVAL", 5*time.Minute)
			ref, jerr := identitypkg.NewJWKSRefresher(jwksURL, interval)
			if jerr != nil {
				fatal(log, "JWKS refresher", jerr) // https-only (R34-3); a ZT gate never boots on a plaintext key source
			}
			go ref.Start(ctx)
			v, err = identitypkg.NewOIDCVerifierWithSource(issuer, audience, roleClaim, ref.KeyFor)
			if err != nil {
				fatal(log, "OIDC verifier", err)
			}
			log.Info("gateway: OIDC SSO identity enabled — keys from a live JWKS endpoint (ZT-2b)",
				slog.String("issuer", issuer), slog.String("jwks", jwksURL))
		} else {
			keys, kerr := identitypkg.LoadOIDCKeys(os.Getenv("OPENSHIELD_OIDC_KEYS_DIR"))
			if kerr != nil {
				fatal(log, "loading OIDC keys", kerr)
			}
			v, err = identitypkg.NewOIDCVerifier(issuer, audience, roleClaim, keys)
			if err != nil {
				fatal(log, "OIDC verifier", err)
			}
			log.Info("gateway: OIDC SSO identity enabled — user identity from a verified bearer token (ZT-2)",
				slog.String("issuer", issuer), slog.Int("keys", len(keys)))
		}
		// R34-10: apply a clock-skew leeway (default 60s) and, when turned on, sender-constrained
		// (DPoP) validation so a stolen bearer token cannot be replayed from a device that lacks the
		// bound key. DPoP is opt-in because it requires clients to present a proof; a token without a
		// cnf.jkt is unaffected either way.
		v.WithLeeway(envDuration("OPENSHIELD_OIDC_LEEWAY", 60*time.Second))
		if os.Getenv("OPENSHIELD_OIDC_DPOP") != "" {
			v.EnableDPoP(envInt("OPENSHIELD_OIDC_DPOP_CACHE", 8192))
			log.Info("gateway: DPoP sender-constrained tokens ENABLED (a cnf.jkt token requires a matching proof)")
		}
		ap.SetOIDCVerifier(v)
	}

	// Subscribe to published risk (D91) and device posture (D92) — SIGNED and VERIFIED
	// (SEC-1). Risk is verified against the control-plane key (OPENSHIELD_RISK_PUBKEY);
	// posture against the posture-publisher key (OPENSHIELD_POSTURE_PUBKEY). A channel with
	// NO trusted key configured is NOT subscribed — the gateway never applies an UNSIGNED
	// update, so a publisher past broker mTLS cannot forge risk=0 / Compliant=true for any
	// subject. Without NATS both stores stay empty: a risk-gating policy allows on absent
	// risk (D89), a posture-requiring policy DENIES on absent posture (D85 tamper-lockout).
	if natsURL := os.Getenv("OPENSHIELD_NATS_URL"); natsURL != "" {
		conn, err := nats.Connect(natsURL)
		if err != nil {
			fatal(log, "risk nats", err)
		}
		defer conn.Close()
		if pk := os.Getenv("OPENSHIELD_RISK_PUBKEY"); pk != "" {
			pub, err := loadEd25519Pub(pk)
			if err != nil {
				fatal(log, "risk pubkey", err)
			}
			if _, err := gateway.NewRiskSubscriber(riskStore, pub).Subscribe(conn); err != nil {
				fatal(log, "risk subscribe", err)
			}
			log.Info("gateway: SIGNED risk subscription active (SEC-1/D91)")
		} else {
			log.Warn("gateway: OPENSHIELD_RISK_PUBKEY unset — risk continuous-verification inert (unsigned risk is never applied, SEC-1)")
		}
		// SEC-12: posture is verified PER AGENT against its OWN enrolled key, from a roster the
		// gateway loads (OPENSHIELD_POSTURE_ROSTER: "<agent-identity> <base64-pubkey>" per line; the
		// loader keys it by the canonical pseudonym so it matches the published subject, IDENT-1). A
		// single shared posture key let any agent forge another's Compliant=true; the roster +
		// subject↔key binding closes that. No roster → the channel is inert (posture never applied; a
		// posture-requiring policy denies on absent posture, D85).
		if rp := os.Getenv("OPENSHIELD_POSTURE_ROSTER"); rp != "" {
			resolver, err := gateway.LoadPostureRoster(rp)
			if err != nil {
				fatal(log, "posture roster", err)
			}
			if _, err := gateway.NewPostureSubscriber(postureStore, resolver).Subscribe(conn); err != nil {
				fatal(log, "posture subscribe", err)
			}
			log.Info("gateway: SIGNED device-posture subscription active — per-agent keys (SEC-12/D92)")
		} else {
			log.Warn("gateway: OPENSHIELD_POSTURE_ROSTER unset — posture channel inert (unsigned/unenrolled posture is never applied, SEC-12)")
		}
		// ZT-1 hardware attestation transport: the gateway answers attestation
		// challenges (issuing a fresh nonce) and verifies published reports into an
		// AttestationVerifier, setting DevicePosture.Attested from its OWN quote
		// verification — never a self-reported value. Enrollment distribution
		// (populating the verifier with each device's AK public key + golden PCR
		// baseline, the output of credential activation, D184) is the remaining
		// operational piece; until it lands the verifier is empty and every device is
		// unattested — a policy requiring attestation fails closed (D85/D186).
		if os.Getenv("OPENSHIELD_ATTEST") != "" {
			av := gateway.NewAttestationVerifier()
			// R34-1: a verdict expires after the TTL, so a device that stops attesting
			// loses attestation (continuous re-attestation D190 keeps a healthy device fresh).
			av.SetTTL(envDuration("OPENSHIELD_ATTEST_TTL", gateway.DefaultAttestationTTL))
			// Load device enrollments (each device's AK public key + golden PCR
			// baseline) so the verifier can attest real devices. Without a file the
			// verifier is empty and every device is unattested — a policy requiring
			// attestation fails closed (D85/D186). A malformed file aborts startup.
			if ef := os.Getenv("OPENSHIELD_ATTEST_ENROLLMENTS"); ef != "" {
				n, err := gateway.LoadAttestationEnrollments(av, ef)
				if err != nil {
					fatal(log, "attestation enrollments", err)
				}
				log.Info("gateway: ZT-1 attestation enrollments loaded", slog.Int("devices", n))
			} else {
				log.Warn("gateway: OPENSHIELD_ATTEST_ENROLLMENTS unset — attestation verifier empty, every device unattested (fail closed)")
			}
			ap.SetAttestationVerifier(av)
			responder := gateway.NewAttestationResponder(av)
			if _, err := responder.ServeChallenge(conn); err != nil {
				fatal(log, "attestation challenge serve", err)
			}
			if _, err := responder.SubscribeReports(conn); err != nil {
				fatal(log, "attestation report subscribe", err)
			}
			// Automated network enrollment: a device proves its AK genuine-TPM-resident
			// by credential activation and self-enrolls over the wire (no operator file).
			enroller := gateway.NewEnrollmentResponder(av)
			// R34-2: pre-authorization. OPENSHIELD_ENROLL_PREAUTH_TOKENS is a comma-separated set of
			// operator-provisioned single-use tokens; when set, only a device presenting one may
			// enroll. Without it the transport keeps the legacy (open) behavior — log which mode.
			if raw := os.Getenv("OPENSHIELD_ENROLL_PREAUTH_TOKENS"); raw != "" {
				toks := strings.Split(raw, ",")
				for i := range toks {
					toks[i] = strings.TrimSpace(toks[i])
				}
				enroller.RequireEnrollTokens(toks...)
				log.Info("gateway: enrollment pre-authorization ENABLED (single-use tokens required)")
			} else {
				log.Warn("gateway: enrollment pre-authorization DISABLED — any device with a co-resident TPM can self-enroll; set OPENSHIELD_ENROLL_PREAUTH_TOKENS to require a token (R34-2)")
			}
			// R34-2 part 2: EK-certificate anchor. OPENSHIELD_EK_ROOTS is a PEM bundle of TPM
			// manufacturer root CAs; when set, an enrolling device must present an EK cert that chains
			// to a root and is bound to its EK public key. Without it, a fabricated EK (incl. swtpm)
			// still passes credential activation — log which mode.
			if rootsPath := os.Getenv("OPENSHIELD_EK_ROOTS"); rootsPath != "" {
				pem, err := os.ReadFile(rootsPath)
				if err != nil {
					fatal(log, "reading OPENSHIELD_EK_ROOTS", err)
				}
				roots, err := attest.LoadEKRoots(pem)
				if err != nil {
					fatal(log, "loading EK manufacturer roots", err)
				}
				enroller.RequireEKCertChain(roots)
				log.Info("gateway: EK-certificate anchoring ENABLED (EK must chain to a manufacturer root)")
			} else {
				log.Warn("gateway: EK-certificate anchoring DISABLED — a fabricated EK (incl. swtpm) passes enrollment; set OPENSHIELD_EK_ROOTS to require a manufacturer-certified EK (R34-2)")
			}
			if _, err := enroller.ServeEnroll(conn); err != nil {
				fatal(log, "attestation enroll serve", err)
			}
			if _, err := enroller.ServeActivate(conn); err != nil {
				fatal(log, "attestation activate serve", err)
			}
			log.Info("gateway: ZT-1 attestation transport + network enrollment active")
		}
	}

	srv := &http.Server{
		Addr: listen, Handler: ap, ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{kp},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientPool,
			MinVersion:   tls.VersionTLS12,
		},
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Warn("gateway: ZERO-TRUST ACCESS MODE — a valid client certificate is REQUIRED (D86/D90)",
		slog.String("listen", listen), slog.Int("services", catalog.Len()))
	if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		fatal(log, "access serving", err)
	}
	log.Info("gateway access mode shut down")
}

var (
	errNoAccessConfig = errors.New("access mode requires OPENSHIELD_ACCESS_CLIENT_CA, _SERVER_CERT, _SERVER_KEY, and _POLICY")
	errEmptyCatalog   = errors.New("OPENSHIELD_ACCESS_CATALOG is empty — an access gateway must front at least one service")
	errNoCerts        = errors.New("no certificates in OPENSHIELD_ACCESS_CLIENT_CA")
)

func loadOrCreateSigner(path string, log *slog.Logger) (*core.Signer, error) {
	if s, err := core.LoadSignerFile(path); err == nil {
		log.Info("resumed signer", slog.String("file", path))
		return s, nil
	}
	s, err := core.NewSigner()
	if err != nil {
		return nil, err
	}
	if mkErr := os.MkdirAll(filepath.Dir(path), 0o700); mkErr == nil {
		_ = core.SaveSignerFile(path, s)
	}
	return s, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// envInt reads an integer env var, falling back to def on absence or a parse error.
func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// splitList parses a comma-separated env value, trimming blanks.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// applyThreatFeed loads the NIPS-2 IOC feed (OPENSHIELD_IOC_FEED) and enables the
// threat-intel engine on the gateway. A configured-but-malformed feed aborts
// startup; no feed leaves the engine inert (the gateway inspects DLP only).
func applyThreatFeed(ctx context.Context, gw *gateway.Gateway, log *slog.Logger) {
	// NIPS-2 remote source: pull the feed from an operator URL (a served TI list) instead of a local
	// file. Initial fetch is fail-fast (a misconfigured URL must not start a silently-empty IPS); later
	// refreshes serve-stale so a feed-server outage never disarms the running engine.
	if feedURL := os.Getenv("OPENSHIELD_IOC_FEED_URL"); feedURL != "" {
		feed, etag, _, err := nips.FetchFeed(ctx, nil, feedURL, "")
		if err != nil {
			fatal(log, "fetching IOC feed URL", err)
		}
		gw.SetThreatFeed(feed)
		log.Info("gateway: NIPS-2 threat-intel engine active (remote feed)", slog.Int("indicators", feed.Size()))
		if iv := envDuration("OPENSHIELD_IOC_FEED_URL_RELOAD", 0); iv > 0 {
			w := nips.NewURLFeedWatcher(feedURL, nil, etag)
			go w.Watch(ctx, iv,
				func(f *nips.Feed) {
					gw.SetThreatFeed(f)
					log.Info("gateway: NIPS-2 IOC feed reloaded (remote)", slog.Int("indicators", f.Size()))
				},
				func(err error) {
					log.Error("gateway: NIPS-2 remote IOC feed refresh failed — keeping the current feed", slog.String("err", err.Error()))
				})
			log.Info("gateway: NIPS-2 remote IOC feed pull enabled", slog.Duration("interval", iv))
		}
		return
	}

	path := os.Getenv("OPENSHIELD_IOC_FEED")
	if path == "" {
		log.Warn("gateway: OPENSHIELD_IOC_FEED[_URL] unset — NIPS-2 threat-intel engine inert (DLP inspection only)")
		return
	}
	feed, err := nips.LoadFeed(path)
	if err != nil {
		fatal(log, "loading IOC feed", err) // fail-fast on a broken INITIAL feed
	}
	gw.SetThreatFeed(feed)
	log.Info("gateway: NIPS-2 threat-intel engine active", slog.Int("indicators", feed.Size()))

	// NIPS-2 hot reload: re-read the feed on a timer so a new IOC takes effect without a restart. A
	// later malformed edit is served-stale (the current feed is kept) — a feed typo must not disarm the
	// running IPS. OPENSHIELD_IOC_FEED_RELOAD sets the interval; unset/0 disables reloading.
	if iv := envDuration("OPENSHIELD_IOC_FEED_RELOAD", 0); iv > 0 {
		w := nips.NewFeedWatcher(path) // baseline the mtime now (before the first tick)
		go w.Watch(ctx, iv,
			func(f *nips.Feed) {
				gw.SetThreatFeed(f)
				log.Info("gateway: NIPS-2 IOC feed reloaded", slog.Int("indicators", f.Size()))
			},
			func(err error) {
				log.Error("gateway: NIPS-2 IOC feed reload failed — keeping the current feed", slog.String("err", err.Error()))
			})
		log.Info("gateway: NIPS-2 IOC feed hot-reload enabled", slog.Duration("interval", iv))
	}
}

// applyCasbCatalog loads the DLP-2 cloud-service catalog (OPENSHIELD_CASB_CATALOG) and
// installs it as the process-wide CASB catalog the policy input consults. A configured-
// but-malformed catalog aborts startup (fail-closed on config, like the EDM index); no
// catalog leaves the CASB engine inert (the gateway still does DLP + IOC). It hot-reloads
// so a change to a service's sanctioned status takes effect without a restart; a later
// malformed edit is served-stale (the current catalog is kept).
func applyCasbCatalog(ctx context.Context, log *slog.Logger) {
	path := os.Getenv("OPENSHIELD_CASB_CATALOG")
	if path == "" {
		log.Warn("gateway: OPENSHIELD_CASB_CATALOG unset — DLP-2 content-aware CASB inert (no cloud-upload awareness)")
		return
	}
	cat, err := casb.LoadCatalog(path)
	if err != nil {
		fatal(log, "loading CASB catalog", err) // fail-fast on a broken INITIAL catalog
	}
	casb.SetCatalog(cat)
	log.Info("gateway: DLP-2 content-aware CASB active", slog.Int("services", cat.Size()))

	if iv := envDuration("OPENSHIELD_CASB_CATALOG_RELOAD", 0); iv > 0 {
		w := casb.NewCatalogWatcher(path) // baseline the mtime now (before the first tick)
		go w.Watch(ctx, iv,
			func(c *casb.Catalog) {
				casb.SetCatalog(c)
				log.Info("gateway: DLP-2 CASB catalog reloaded", slog.Int("services", c.Size()))
			},
			func(err error) {
				log.Error("gateway: DLP-2 CASB catalog reload failed — keeping the current catalog", slog.String("err", err.Error()))
			})
		log.Info("gateway: DLP-2 CASB catalog hot-reload enabled", slog.Duration("interval", iv))
	}
}

// applyTProxy starts the NIPS-1 transparent inline data-plane when OPENSHIELD_TPROXY_LISTEN is
// set: a TPROXY-redirected TCP flow is decided through the pipeline and DROPPED (blocked) or
// SPLICED (allowed) at L4. Fail-to-wire, never fail-closed: if the IP_TRANSPARENT listener cannot
// be created (no CAP_NET_ADMIN), the gateway logs loudly and runs WITHOUT the inline plane — the
// network is never taken down because inline could not arm (ADR-8/D73). The operator installs the
// iptables/nft TPROXY + routing rules out of band.
func applyTProxy(ctx context.Context, gw *gateway.Gateway, log *slog.Logger) {
	addr := strings.TrimSpace(os.Getenv("OPENSHIELD_TPROXY_LISTEN"))
	if addr == "" {
		return
	}
	log.Info("gateway: NIPS-1 transparent inline plane ACTIVE (drops a blocked flow at L4)", slog.String("addr", addr))

	// Self-install path (NIPS-1 inc-4a): OpenShield owns the TPROXY rules, bound to the server lifecycle
	// (inc-4b) and SUPERVISED (inc-4c) — SuperviseTProxy re-arms the listener + reinstalls the rules after a
	// transient stop, so a blip does not leave inline prevention silently disabled.
	if os.Getenv("OPENSHIELD_TPROXY_INSTALL_RULES") == "1" {
		dports := envPorts("OPENSHIELD_TPROXY_DPORTS", []int{80, 443})
		mark := envMark("OPENSHIELD_TPROXY_MARK", 1)
		table := envMark("OPENSHIELD_TPROXY_TABLE", 100)
		retry := envDuration("OPENSHIELD_TPROXY_RETRY", 5*time.Second)
		newServer := func() *gateway.TProxyServer { return gateway.NewTProxyServer(gw, log) }
		go gateway.SuperviseTProxy(ctx, addr, dports, mark, table, retry, newServer, log)
		return
	}

	// Operator owns the redirect rules out of band — just serve; OpenShield manages only rules it installed.
	ln, err := gateway.ListenTransparent(addr)
	if err != nil {
		log.Error("gateway: TPROXY inline plane could NOT arm — continuing WITHOUT it (fail-to-wire, "+
			"network not taken down); needs CAP_NET_ADMIN + an IP_TRANSPARENT-capable kernel + out-of-band "+
			"iptables/nft TPROXY redirect rules", slog.String("addr", addr), slog.String("err", err.Error()))
		return
	}
	go serveTProxy(ctx, gateway.NewTProxyServer(gw, log), ln, log)
}

// serveTProxy runs the transparent server and logs an unexpected stop.
func serveTProxy(ctx context.Context, srv *gateway.TProxyServer, ln net.Listener, log *slog.Logger) {
	if err := srv.Serve(ctx, ln); err != nil && ctx.Err() == nil {
		log.Error("gateway: TPROXY server stopped", slog.String("err", err.Error()))
	}
}

// envPorts parses a comma-separated port list; def on unset/empty. A bad token is skipped.
func envPorts(k string, def []int) []int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	var out []int
	for _, tok := range strings.Split(v, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(tok)); err == nil && n > 0 {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return def
	}
	return out
}

// applyDNSSink starts the NIPS-8 preventive DNS resolver when OPENSHIELD_DNS_SINK_LISTEN +
// OPENSHIELD_DNS_UPSTREAM are set: it forwards normal queries to the upstream and sinkholes (NXDOMAIN) a
// query whose domain is on the CURRENT IOC feed. Fail-open (an unparseable/unmatched query is forwarded)
// and fail-to-wire (a bind failure logs and the gateway keeps running) — a DNS resolver must never
// blackhole the fleet's name resolution. Binding :53 needs privilege (CAP_NET_BIND_SERVICE).
func applyDNSSink(ctx context.Context, gw *gateway.Gateway, log *slog.Logger) {
	addr := strings.TrimSpace(os.Getenv("OPENSHIELD_DNS_SINK_LISTEN"))
	upstream := strings.TrimSpace(os.Getenv("OPENSHIELD_DNS_UPSTREAM"))
	if addr == "" || upstream == "" {
		return
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Error("gateway: DNS sinkhole could NOT bind — continuing WITHOUT it (fail-to-wire; :53 needs "+
			"CAP_NET_BIND_SERVICE)", slog.String("addr", addr), slog.String("err", err.Error()))
		return
	}
	// Transparent :53 redirect (NIPS-8 increment 2): when OPENSHIELD_DNS_REDIRECT=1, redirect the host's
	// UDP :53 traffic to this resolver so UNCONFIGURED clients are also sinkholed. The resolver carries a
	// firewall mark on its upstream socket so its OWN forwards escape the redirect (the loop-break); the
	// redirect rule exempts that mark. Root-only (CAP_NET_ADMIN); a failure logs and the resolver still
	// serves explicitly-configured clients.
	mark := 0
	if os.Getenv("OPENSHIELD_DNS_REDIRECT") == "1" {
		mark = envMark("OPENSHIELD_DNS_REDIRECT_MARK", 0x1d5)
	}
	r := dnssink.Resolver{Upstream: upstream, Blocked: gw.BlockedDomain, Mark: mark, Log: log}
	go func() {
		if err := r.Serve(ctx, pc); err != nil && ctx.Err() == nil {
			log.Error("gateway: DNS sinkhole stopped", slog.String("err", err.Error()))
		}
	}()
	log.Info("gateway: NIPS-8 preventive DNS resolver ACTIVE (sinkhole blocked domains, forward the rest)",
		slog.String("listen", addr), slog.String("upstream", upstream))

	if mark != 0 {
		port := listenPort(pc.LocalAddr(), addr)
		if port == 0 {
			log.Error("gateway: transparent DNS redirect NOT installed — could not determine resolver port",
				slog.String("addr", addr))
		} else {
			// The watchdog owns install/remove: it removes the redirect (falls back to direct DNS) if the
			// resolver wedges, so a dead resolver never wedges host name resolution, and restores it on
			// recovery (NIPS-8 inc-3, the D234 availability follow-up).
			wd := &dnsredirect.Watchdog{Port: port, Mark: mark, Log: log}
			go wd.Run(ctx)
		}
	}
}

// listenPort resolves a listener's actual port: prefer the bound socket address (handles a ":0" ephemeral
// listen for either UDP or TCP), fall back to parsing the configured address string.
func listenPort(bound net.Addr, addr string) int {
	switch a := bound.(type) {
	case *net.UDPAddr:
		if a.Port != 0 {
			return a.Port
		}
	case *net.TCPAddr:
		if a.Port != 0 {
			return a.Port
		}
	}
	if _, portStr, err := net.SplitHostPort(addr); err == nil {
		if p, err := strconv.Atoi(portStr); err == nil {
			return p
		}
	}
	return 0
}

// envMark reads a firewall mark (accepts hex "0x1d5" or decimal); def on unset/parse error.
func envMark(k string, def int) int {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if n, err := strconv.ParseInt(v, 0, 32); err == nil {
			return int(n)
		}
	}
	return def
}

func fatal(log *slog.Logger, msg string, err error) {
	log.Error(msg, slog.String("err", err.Error()))
	os.Exit(1)
}

// loadEd25519Pub reads a raw 32-byte Ed25519 public key from a file — the trusted
// risk/posture publisher key the gateway verifies signed updates against (SEC-1). Same
// format as the witness key (openshieldctl), so provisioning can emit it the same way.
func loadEd25519Pub(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading public key %s: %w", path, err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key %s is %d bytes, want %d", path, len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

func envDuration(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
