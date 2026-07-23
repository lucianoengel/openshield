//go:build linux

package gateway

import (
	"fmt"
	"log/slog"
	"os/exec"
)

// InstallTProxyRules installs the mark-based routing + mangle TPROXY rules that redirect forwarded TCP
// flows on the given destination ports into the transparent listener on listenPort. Remove-then-add
// idempotent; the divert route lives in a dedicated table and the iptables rule in a dedicated chain, so a
// re-run never errors and teardown never touches operator rules. Needs iptables + ip and CAP_NET_ADMIN.
func InstallTProxyRules(listenPort int, dports []int, mark, table int, log *slog.Logger) error {
	iptBin, err := exec.LookPath("iptables")
	if err != nil {
		return fmt.Errorf("gateway: iptables not found: %w", errTProxyUnsupported)
	}
	ipBin, err := exec.LookPath("ip")
	if err != nil {
		return fmt.Errorf("gateway: ip (iproute2) not found: %w", errTProxyUnsupported)
	}
	ipDel, iptDel := tproxyRemoveArgs(listenPort, dports, mark, table)
	ipAdd, iptAdd := tproxyInstallArgs(listenPort, dports, mark, table)

	// Idempotent teardown of any stale state (ignore errors).
	bestEffort(iptBin, log, iptDel)
	bestEffort(ipBin, log, ipDel)
	// Fatal rule adds: a half-installed redirect must not report success.
	if err := runAll(ipBin, ipAdd); err != nil {
		return err
	}
	if err := runAll(iptBin, iptAdd); err != nil {
		return err
	}
	if log != nil {
		log.Info("gateway: TPROXY redirect rules installed", slog.Int("listen_port", listenPort),
			slog.Any("dports", dports), slog.Int("mark", mark), slog.Int("table", table))
	}
	return nil
}

// RemoveTProxyRules tears down the TPROXY rules. Idempotent (a missing rule/route is not an error). It
// needs the same listenPort/dports/mark/table used to install, so it deletes the exact rules it added.
func RemoveTProxyRules(listenPort int, dports []int, mark, table int, log *slog.Logger) error {
	ipDel, iptDel := tproxyRemoveArgs(listenPort, dports, mark, table)
	if iptBin, err := exec.LookPath("iptables"); err == nil {
		bestEffort(iptBin, log, iptDel)
	}
	if ipBin, err := exec.LookPath("ip"); err == nil {
		bestEffort(ipBin, log, ipDel)
	}
	return nil
}

func runAll(bin string, seq [][]string) error {
	for _, args := range seq {
		if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
			return fmt.Errorf("gateway: %s %v: %v (%s)", bin, args, err, string(out))
		}
	}
	return nil
}

func bestEffort(bin string, log *slog.Logger, seq [][]string) {
	for _, args := range seq {
		if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil && log != nil {
			log.Debug("gateway: TPROXY best-effort step (ignored)", slog.String("bin", bin),
				slog.Any("args", args), slog.String("out", string(out)))
		}
	}
}
