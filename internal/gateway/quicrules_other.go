//go:build !linux

package gateway

import "log/slog"

// InstallQUICRedirect is unsupported off Linux, and says so rather than returning nil — a caller that
// believed the divert was installed would report an inline QUIC plane that never sees a packet.
func InstallQUICRedirect(int, int, int, *slog.Logger) error { return errQUICUnsupported }

// RemoveQUICRedirect has nothing to remove off Linux.
func RemoveQUICRedirect(int, int, int, *slog.Logger) error { return nil }
