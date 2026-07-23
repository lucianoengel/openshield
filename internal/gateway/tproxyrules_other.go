//go:build !linux

package gateway

import "log/slog"

// InstallTProxyRules is linux-only (TPROXY + iproute2 mark routing).
func InstallTProxyRules(listenPort int, dports []int, mark, table int, log *slog.Logger) error {
	return errTProxyUnsupported
}

// RemoveTProxyRules is a no-op off linux (nothing was installed).
func RemoveTProxyRules(listenPort int, dports []int, mark, table int, log *slog.Logger) error { return nil }
