//go:build !linux

package openmon

import (
	"context"
	"fmt"

	"github.com/lucianoengel/openshield/internal/agent/watchdog"
)

// Monitor is the portable stub. The gate is a Linux kernel interface; the tree must still compile for
// Windows and macOS (ADR-11/PLAT-7), and a stub that pretended to work would be worse than one that
// says it cannot.
type Monitor struct{}

// Open always fails off Linux.
func Open(paths []string) (*Monitor, error) {
	return nil, fmt.Errorf("openmon: FAN_OPEN_PERM is a Linux interface; this platform has no inline file-open gate")
}

func (m *Monitor) Close() error { return nil }

func (m *Monitor) NotifyFD() int { return -1 }

func (m *Monitor) Run(ctx context.Context, wd *watchdog.Watchdog) error {
	return fmt.Errorf("openmon: unsupported on this platform")
}

func (m *Monitor) Watched() []string { return nil }
