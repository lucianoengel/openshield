//go:build linux

package main

import "github.com/lucianoengel/openshield/internal/connectors/fanotify"

// openFileWatcher opens the Linux fanotify connector in unprivileged NOTIFY mode
// (D52) — the endpoint's observe path on Linux, unchanged by cross-platform work.
func openFileWatcher(dir string) (fileWatcher, error) { return fanotify.Open(dir) }
