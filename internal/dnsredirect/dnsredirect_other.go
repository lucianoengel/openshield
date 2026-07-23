//go:build !linux

package dnsredirect

import "log/slog"

// Install is unsupported off linux (the redirect needs the linux nat stack + CAP_NET_ADMIN).
func Install(resolverPort, mark int, log *slog.Logger) error { return errUnsupported }

// Remove is a no-op off linux (nothing was installed).
func Remove(log *slog.Logger) error { return nil }

// InstallForwarded is unsupported off linux.
func InstallForwarded(resolverPort int, log *slog.Logger) error { return errUnsupported }

// RemoveForwarded is a no-op off linux.
func RemoveForwarded(log *slog.Logger) error { return nil }
