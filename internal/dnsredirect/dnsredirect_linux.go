//go:build linux

package dnsredirect

import (
	"fmt"
	"log/slog"
	"os/exec"
)

// Install transparently redirects locally-originated UDP :53 to the local resolver on resolverPort, exempt
// from the resolver's own mark (the loop-break). It prefers iptables and falls back to nft; if neither is
// present it returns an error. It is remove-then-add (the TPROXY idempotency discipline): any stale
// openshield rules are torn down first so a re-run after an unclean shutdown never fails on "exists".
func Install(resolverPort, mark int, log *slog.Logger) error {
	return installBackend(resolverPort, mark, true, log)
}

// installBackend selects a backend and installs the redirect. exempt controls the loop-break mark
// exemption; production always passes true. The gated kernel test also drives it with false to PROVE that
// without the exemption the resolver's own upstream forward loops back and normal resolution breaks.
func installBackend(resolverPort, mark int, exempt bool, log *slog.Logger) error {
	if path, err := exec.LookPath("iptables"); err == nil {
		return install(path, log, iptablesRemoveArgs(), iptablesScaffoldArgs(), iptablesInstallArgs(resolverPort, mark, exempt))
	}
	if path, err := exec.LookPath("nft"); err == nil {
		return install(path, log, nftRemoveArgs(), nftScaffoldArgs(), nftInstallArgs(resolverPort, mark, exempt))
	}
	return fmt.Errorf("dnsredirect: neither iptables nor nft found: %w", errUnsupported)
}

// Remove tears down the redirect. It is idempotent (a missing rule/table is not an error).
func Remove(log *slog.Logger) error {
	if path, err := exec.LookPath("iptables"); err == nil {
		best(path, log, iptablesRemoveArgs())
		return nil
	}
	if path, err := exec.LookPath("nft"); err == nil {
		best(path, log, nftRemoveArgs())
		return nil
	}
	return nil
}

// InstallForwarded redirects FORWARDED UDP :53 (client DNS passing through this host as a gateway) to the
// local resolver on resolverPort (nat PREROUTING, iptables). Remove-then-add idempotent. No mark loop-break
// is needed for the forwarded path. nft-forwarded is a deferred backend.
func InstallForwarded(resolverPort int, log *slog.Logger) error {
	path, err := exec.LookPath("iptables")
	if err != nil {
		return fmt.Errorf("dnsredirect: iptables not found for the forwarded redirect: %w", errUnsupported)
	}
	return install(path, log, iptablesForwardedRemoveArgs(), iptablesForwardedScaffoldArgs(), iptablesForwardedInstallArgs(resolverPort))
}

// RemoveForwarded tears down the forwarded redirect. Idempotent.
func RemoveForwarded(log *slog.Logger) error {
	if path, err := exec.LookPath("iptables"); err == nil {
		best(path, log, iptablesForwardedRemoveArgs())
	}
	return nil
}

// install is remove-then-add: idempotent teardown, best-effort scaffold (chain/table create — a benign
// "exists" is fine after the flush), then the FATAL rule adds (a half-installed redirect must not report
// success).
func install(bin string, log *slog.Logger, teardown, scaffold, rules [][]string) error {
	best(bin, log, teardown)
	best(bin, log, scaffold)
	for _, args := range rules {
		if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
			return fmt.Errorf("dnsredirect: %s %v: %v (%s)", bin, args, err, string(out))
		}
	}
	if log != nil {
		log.Info("dnsredirect: transparent :53 redirect installed", slog.String("backend", bin))
	}
	return nil
}

// best runs each command ignoring failures (idempotent cleanup / benign "exists").
func best(bin string, log *slog.Logger, seq [][]string) {
	for _, args := range seq {
		if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil && log != nil {
			log.Debug("dnsredirect: best-effort step (ignored)", slog.String("bin", bin), slog.Any("args", args), slog.String("out", string(out)))
		}
	}
}
