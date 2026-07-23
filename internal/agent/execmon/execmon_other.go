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

func (m *Monitor) NotifyFD() int { return -1 }
func (m *Monitor) Close() error  { return nil }
func (m *Monitor) Run(ctx context.Context, wd *watchdog.Watchdog) error {
	return fmt.Errorf("execmon: unsupported off Linux")
}
