//go:build linux

package config

// MaxSocketPath is the longest unix socket address this platform accepts.
//
// Linux's `sockaddr_un.sun_path` is 108 bytes. The RUNNING platform's limit is used rather than the
// smallest across platforms, because a 106-byte path binds correctly here and refusing it would be
// rejecting valid configuration — a worse fault than a message that differs by platform, since the
// operator would have a correct value the product will not accept.
const MaxSocketPath = 108
