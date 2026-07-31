//go:build linux

package gateway

import (
	"fmt"
	"log/slog"
	"os/exec"
)

// InstallQUICRedirect diverts forwarded UDP/443 into the plane on listenPort via mangle PREROUTING TPROXY,
// with the mark-based routing that makes the divert deliverable. Remove-then-add, so a re-run after an
// unclean shutdown never fails on "exists". Needs CAP_NET_ADMIN.
func InstallQUICRedirect(listenPort, mark, table int, log *slog.Logger) error {
	RemoveQUICRedirect(listenPort, mark, table, nil) // idempotent teardown first
	ipArgs, iptArgs := quicInstallArgs(listenPort, mark, table)
	for _, a := range ipArgs {
		if out, err := exec.Command("ip", a...).CombinedOutput(); err != nil {
			return fmt.Errorf("gateway: ip %v: %v (%s)", a, err, string(out))
		}
	}
	for _, a := range iptArgs {
		if out, err := exec.Command("iptables", a...).CombinedOutput(); err != nil {
			return fmt.Errorf("gateway: iptables %v: %v (%s)", a, err, string(out))
		}
	}
	if log != nil {
		log.Info("quic: UDP/443 TPROXY divert installed", slog.Int("plane_port", listenPort))
	}
	return nil
}

// RemoveQUICRedirect tears the divert down. Idempotent — a missing rule is not an error.
func RemoveQUICRedirect(listenPort, mark, table int, log *slog.Logger) error {
	ipArgs, iptArgs := quicRemoveArgs(listenPort, mark, table)
	for _, a := range iptArgs {
		if out, err := exec.Command("iptables", a...).CombinedOutput(); err != nil && log != nil {
			log.Debug("quic: teardown step (ignored)", slog.Any("args", a), slog.String("out", string(out)))
		}
	}
	for _, a := range ipArgs {
		if out, err := exec.Command("ip", a...).CombinedOutput(); err != nil && log != nil {
			log.Debug("quic: teardown step (ignored)", slog.Any("args", a), slog.String("out", string(out)))
		}
	}
	return nil
}
