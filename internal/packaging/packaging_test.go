package packaging

import (
	"os"
	"strings"
	"testing"
)

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The engine — holder of the ledger signer key + OPA — MUST be isolated under a
// dedicated user, never root and never the monitored/other accounts, with the
// signer state confined to its own directory (D68). A regression that drops this
// fails the build.
func TestEngineUnitIsolatesTheSignerHolder(t *testing.T) {
	unit := read(t, "../../deploy/systemd/openshield-engine.service")

	if !strings.Contains(unit, "User=openshield-engine") {
		t.Error("engine unit does not run as the dedicated openshield-engine user")
	}
	// Not root, not the server user, not the worker/monitored account.
	for _, bad := range []string{"User=root", "User=openshield\n", "User=openshield-worker"} {
		if strings.Contains(unit, bad) {
			t.Errorf("engine runs as %q — not isolated", strings.TrimSpace(bad))
		}
	}
	if !strings.Contains(unit, "NoNewPrivileges=true") {
		t.Error("engine unit missing NoNewPrivileges=true")
	}
	if !strings.Contains(unit, "CapabilityBoundingSet=\n") {
		t.Error("engine unit missing an empty CapabilityBoundingSet")
	}
	if strings.Contains(unit, "CAP_SYS_ADMIN") {
		t.Error("engine unit grants CAP_SYS_ADMIN")
	}
	if !strings.Contains(unit, "StateDirectory=") {
		t.Error("engine unit missing a StateDirectory for the signer state")
	}
	if !strings.Contains(unit, "OPENSHIELD_SIGNER_FILE=/var/lib/openshield-engine/") {
		t.Error("signer state is not confined to the engine's own StateDirectory")
	}
}

// The installer MUST create the engine user and install the engine + anchor units.
func TestInstallerInstallsEngineAndAnchor(t *testing.T) {
	sh := read(t, "../../deploy/install.sh")
	for _, want := range []string{
		"ensure_user openshield-engine",
		"openshield-engine.service",
		"openshield-anchor.service",
		"openshield-anchor.timer",
	} {
		if !strings.Contains(sh, want) {
			t.Errorf("install.sh does not install %q", want)
		}
	}
	if !strings.Contains(sh, "systemctl enable") || !strings.Contains(sh, "openshield-engine.service") {
		t.Error("engine service is not enabled by the installer")
	}
}

// The gateway — holder of the ledger signer AND (when interception is on) the
// interception-CA skeleton key (D75) — MUST be isolated exactly like the engine
// (D68/D84), never root and never the monitored account.
func TestGatewayUnitIsolatesTheSecretHolder(t *testing.T) {
	unit := read(t, "../../deploy/systemd/openshield-gateway.service")

	if !strings.Contains(unit, "User=openshield-gateway") {
		t.Error("gateway unit does not run as the dedicated openshield-gateway user")
	}
	for _, bad := range []string{"User=root", "User=openshield\n", "User=openshield-worker"} {
		if strings.Contains(unit, bad) {
			t.Errorf("gateway runs as %q — not isolated", strings.TrimSpace(bad))
		}
	}
	if !strings.Contains(unit, "NoNewPrivileges=true") {
		t.Error("gateway unit missing NoNewPrivileges=true")
	}
	if !strings.Contains(unit, "CapabilityBoundingSet=\n") {
		t.Error("gateway unit missing an empty CapabilityBoundingSet")
	}
	if !strings.Contains(unit, "ProtectSystem=strict") {
		t.Error("gateway unit missing ProtectSystem=strict")
	}
	if !strings.Contains(unit, "StateDirectory=openshield-gateway") {
		t.Error("gateway unit missing its own StateDirectory for the signer + interception CA")
	}
}

// The installer MUST create the gateway user, install + enable the gateway, and MUST
// NOT enable the openshield-agent stub (it exits non-zero, D49/D62/D84).
func TestInstallerHardensGatewayAndDoesNotEnableStubAgent(t *testing.T) {
	sh := read(t, "../../deploy/install.sh")
	for _, want := range []string{
		"ensure_user openshield-gateway",
		"openshield-gateway.service",
	} {
		if !strings.Contains(sh, want) {
			t.Errorf("install.sh does not install/create %q", want)
		}
	}
	// The single enable line must include the gateway and NOT the stub agent.
	var enableLine string
	for _, line := range strings.Split(sh, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "systemctl enable ") {
			enableLine = line
		}
	}
	if enableLine == "" {
		t.Fatal("install.sh has no `systemctl enable` line")
	}
	if !strings.Contains(enableLine, "openshield-gateway.service") {
		t.Error("the installer does not enable the gateway unit")
	}
	if strings.Contains(enableLine, "openshield-agent.service") {
		t.Error("the installer ENABLES the openshield-agent stub — it exits non-zero (D49/D62); it must stay disabled")
	}
}
