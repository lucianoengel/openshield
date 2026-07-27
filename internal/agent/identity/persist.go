package identity

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
)

// PERSISTING THE AGENT'S IDENTITY ACROSS RESTARTS (D318).
//
// Without this, `openshield-fleet-agent` COULD NOT SURVIVE A REBOOT. It generated a fresh keypair on
// every start and re-enrolled; enrollment tokens are single-use; and SEC-2 deliberately REFUSES to
// overwrite an enrolled agent's public key, because a fresh token must not be able to replace an agent's
// key or un-revoke a revoked one. Each of those three is right on its own, and together they meant an
// agent that restarted got `enroll status 401` and exited — permanently, until an operator revoked the
// identity and minted a new token. A reboot, an upgrade or a crash therefore took an endpoint out of the
// fleet, silently from the console's point of view: it simply stopped reporting.
//
// The fix is not to weaken SEC-2. It is for the agent to KEEP the key it enrolled, exactly as it already
// keeps its telemetry sequence (D66) — the same shape, for the same reason: state that identifies this
// agent to the control plane must outlive the process.
//
// HONEST LIMIT, unchanged from the package's own (D16): root on the host can read this file and sign
// anything the agent could. Persisting the key does not widen that — the key was already in the agent's
// memory, and a host-root attacker had it either way. What changes is that the key is now at rest, so
// FILE PERMISSIONS carry weight they did not before: it is written 0600, and a key file that is readable
// by anyone else is refused rather than used.

// LoadOrCreate returns the agent's identity from path, creating and saving one if the file is absent.
//
// The second return value reports whether the identity is NEW, which is what tells the caller whether it
// must enrol: a loaded identity is by definition one the control plane already knows, so re-enrolling it
// would consume a token to assert something already true — and would be refused by SEC-2 anyway.
func LoadOrCreate(path, agentID string) (id *Identity, created bool, err error) {
	if path == "" {
		// No file configured: the pre-D318 behaviour, an ephemeral identity that must enrol every boot.
		// Kept because it is right for a container that is replaced rather than restarted, and because
		// changing what an unset setting does would alter existing deployments silently.
		id, err = Generate(agentID)
		return id, true, err
	}
	blob, rerr := os.ReadFile(path)
	switch {
	case rerr == nil:
		if len(blob) != ed25519.PrivateKeySize {
			return nil, false, fmt.Errorf("identity: %s is %d bytes, want %d — refusing to use a "+
				"truncated key, which would fail as unattributable telemetry rather than as a bad file",
				path, len(blob), ed25519.PrivateKeySize)
		}
		if err := refusePermissive(path); err != nil {
			return nil, false, err
		}
		priv := ed25519.PrivateKey(blob)
		return &Identity{AgentID: agentID, priv: priv, pub: priv.Public().(ed25519.PublicKey)}, false, nil
	case !os.IsNotExist(rerr):
		return nil, false, fmt.Errorf("identity: reading %s: %w", path, rerr)
	}

	id, err = Generate(agentID)
	if err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("identity: creating the directory for %s: %w", path, err)
	}
	// WRITTEN BEFORE ENROLLMENT IS ATTEMPTED, by the caller's ordering, so a crash between generating and
	// enrolling leaves a key the next boot will reuse rather than a second key needing a second token.
	if err := os.WriteFile(path, id.priv, 0o600); err != nil {
		return nil, false, fmt.Errorf("identity: writing %s: %w", path, err)
	}
	return id, true, nil
}

// refusePermissive rejects a key file others can read.
//
// A REFUSAL, not a warning. The whole value of a per-agent key is that compromising one agent yields one
// agent's key; a world-readable key file on a shared host quietly turns it back into a shared secret,
// which is the fleet-wide risk (A6) this package exists to avoid.
func refusePermissive(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("identity: %s is mode %04o — readable beyond its owner. A per-agent key that "+
			"others can read is a shared fleet secret with extra steps; fix it with chmod 600", path, perm)
	}
	return nil
}
