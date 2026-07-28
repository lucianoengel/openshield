//go:build !linux

package config

// MaxSocketPath is the longest unix socket address this platform accepts.
//
// 104 is macOS's `sockaddr_un.sun_path` and the safe answer for anything unlisted. Windows has no unix
// socket of this shape at all; the constant exists there only so the package compiles, which the
// cross-compilation gate requires.
const MaxSocketPath = 104
