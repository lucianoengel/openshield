//go:build !linux

package execmon

import (
	"context"
	"fmt"

	"github.com/lucianoengel/openshield/internal/agent/watchdog"
)

// Monitor is unavailable off Linux (fanotify is Linux-only). The stub exists so the tree
// cross-compiles (D9); enforcement ships on Linux.
type Monitor struct{}

// Open returns an unsupported error off Linux.
func Open(paths []string) (*Monitor, error) {
	return nil, fmt.Errorf("execmon: fanotify exec-permission monitoring is Linux-only")
}

// OpenWithMode is the mode-selecting form, equally unavailable off Linux. It FAILS rather than
// silently ignoring the mode: a caller that asked for a narrow mark and got a broad one (or none)
// would believe it had a property it does not.
func OpenWithMode(paths []string, mode MarkMode) (*Monitor, error) {
	return nil, fmt.Errorf("execmon: fanotify exec-permission monitoring is Linux-only (mode %s)", mode)
}

// MarkFile is unavailable off Linux.
func (m *Monitor) MarkFile(path string) error {
	return fmt.Errorf("execmon: unsupported off Linux")
}

// WatchForNewExecutables is unavailable off Linux.
func (m *Monitor) WatchForNewExecutables(ctx context.Context, onErr func(error)) error {
	return fmt.Errorf("execmon: unsupported off Linux")
}

// Marked reports zero off Linux; Watched reports nothing.
func (m *Monitor) Marked() int       { return 0 }
func (m *Monitor) Watched() []string { return nil }

func (m *Monitor) NotifyFD() int { return -1 }
func (m *Monitor) Close() error  { return nil }
func (m *Monitor) Run(ctx context.Context, wd *watchdog.Watchdog) error {
	return fmt.Errorf("execmon: unsupported off Linux")
}
