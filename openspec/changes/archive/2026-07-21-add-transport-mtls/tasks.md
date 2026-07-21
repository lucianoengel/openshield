# Tasks — add mTLS to the agent-facing transport

## 1. TLS config loader

- [x] 1.1 `internal/transport/tlsconf`: `Load(caPath, certPath, keyPath)` → parses the CA bundle + cert/key pair; `ServerConfig()` (`RequireAndVerifyClientCert`, `ClientCAs`, TLS 1.3) and `ClientConfig()` (`RootCAs`, client cert, TLS 1.3).
- [x] 1.2 `LoadFromEnv()` reads `OPENSHIELD_TLS_CA/CERT/KEY`; returns (nil, nil) when unset (disabled), a hard error when partially set or unreadable (fail loud, never silent plaintext).

## 2. Wire the three call sites

- [x] 2.1 Enroll HTTP server: when a server TLS config is present, serve with `ServeTLS`/`http.Server{TLSConfig}`; otherwise plaintext as today.
- [x] 2.2 `internal/transport/nats` agent side: accept and apply a `*tls.Config` (via `nats.Secure` + client cert) in `Connect`.
- [x] 2.3 Control-plane NATS subscribe side: apply the same client config when connecting.
- [x] 2.4 `cmd/openshield-server` + `cmd/openshield-fleet-agent`: load TLS from env and pass it through; log "TLS enabled" when on.

## 3. Tests (guards, each mutation-tested)

- [x] 3.1 **Test**: `tlsconf.Load` produces configs where the server requires+verifies a client cert and rejects an unknown-CA cert; a wrong-CA client fails the handshake.
- [x] 3.2 **Test**: enrollment over mTLS succeeds with a valid client cert and is REFUSED (handshake failure, no enrollment) without one — not downgraded to plaintext.
- [x] 3.3 **Test**: `LoadFromEnv` disabled-by-default (unset → nil, plaintext) and fails loudly when partially configured.
- [x] 3.4 **Test**: a mutual-TLS-authenticated peer whose telemetry fails signature check is STILL rejected (D50) — the two layers are independent.

## 4. Live fleet e2e

- [x] 4.1 `deploy/mtls-e2e.sh` (focused companion to fleet-e2e.sh, to avoid destabilizing its plaintext assertions): generate a throwaway CA + server/agent certs, run the fleet over mTLS, assert enrollment + verified telemetry succeed; assert a no-cert client is refused.

## 5. Docs, ship

- [x] 5.1 `docs/decisions.md` new D-number: mTLS is a channel-security layer beneath Ed25519 signing (defence in depth, both enforced); opt-in, fail-closed; host root still wins (D16); server still only observes (D14).
- [x] 5.2 `openspec validate add-transport-mtls --strict`; `make all`; archive via the skill; fix TBD Purpose; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| server uses VerifyClientCertIfGiven (not Require+Verify) | `TestMutualTLSEnforced`, `TestEnrollOverMutualTLS` |
| LoadFromEnv silently disables on a partial config | `TestLoadFromEnvDefaultAndPartial` |
| client sets InsecureSkipVerify (skips server-CA check) | `TestMutualTLSEnforced` (rogue CA accepted) |
| TLS auth bypasses signing (independence) | `TestTLSDoesNotBypassSigning` (bad-sig over mTLS still rejected; good-sig accepted) |

Mutual TLS now protects both agent-facing channels: a valid client cert enrolls
and publishes, a wrong-CA or no-cert peer is refused at the handshake (no
plaintext downgrade), it is off by default and fails loud on a partial config,
and a cert-authenticated peer's badly-signed telemetry is STILL rejected (D50) —
the two layers are independent and both enforced.
