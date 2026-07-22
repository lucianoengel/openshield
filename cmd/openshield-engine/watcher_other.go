//go:build !linux

package main

import "github.com/lucianoengel/openshield/internal/connectors/filewatch"

// openFileWatcher opens the portable poll-based connector on operating systems
// without fanotify (windows, darwin), so the SAME engine runs and observes there
// unprivileged — self-signable, no kernel driver — instead of exiting where
// fanotify is unsupported (ADR-11/PLAT-7). Enforcement on those platforms stays
// externally gated; this is the observe half only.
func openFileWatcher(dir string) (fileWatcher, error) { return filewatch.Open(dir) }
