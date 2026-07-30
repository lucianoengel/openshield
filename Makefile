GO ?= go
PROTOC ?= protoc

.PHONY: all quick build test integration vet check cross-compile proto proto-check tidy release verify-release

all: vet test check build cross-compile integration

# THE FAST FEEDBACK LOOP, for while you are iterating. Run `all` before pushing; run this in between.
#
# It is not a judgement call about what to skip — it is the set of checks that ACTUALLY CAUGHT things a
# targeted `go test ./some/package/` would have missed. Over one long session, that was exactly two
# classes:
#
#   - CROSS-COMPILATION. A new file behind a `linux` build tag with no portable stub breaks the Windows
#     and macOS builds and NOTHING else notices; the package tests pass on the machine you are sitting at.
#   - THE DECLARATION AND FITNESS GUARDS. A setting read by a command but never declared, a test entry
#     point in a non-_test.go file, an invariant named in a doc with no test behind it. These are static
#     checks over the whole tree, so no targeted run reaches them.
#
# Everything else the full gate caught was infrastructure — a full disk, a suite outgrowing its timeout —
# which a faster loop finds just as well, sooner.
#
# It deliberately does NOT run the integration suite or the race detector. Those are the slow, valuable
# parts, and skipping them is the whole point: they belong to `all`, before a push.
quick: vet
	$(GO) build ./...
	GOOS=windows GOARCH=amd64 $(GO) build ./...
	GOOS=darwin  GOARCH=amd64 $(GO) build ./...
	$(GO) test -count=1 ./internal/config/ ./internal/fitness/ ./internal/doccheck/
	./scripts/check-core-deps.sh
	./scripts/check-agent-deps.sh
	./scripts/check-no-binaries.sh
	./scripts/check-ci-pins.sh
	./scripts/check-cmd-closure.sh

build:
	$(GO) build ./...

# The endpoint agent is cross-platform (ADR-11/PLAT-7): the same code compiles for
# Windows and macOS, where the engine uses the portable file watcher instead of
# fanotify. A portability regression must fail locally, not on a user's Mac.
cross-compile:
	GOOS=windows GOARCH=amd64 $(GO) build ./...
	GOOS=darwin  GOARCH=amd64 $(GO) build ./...

vet:
	$(GO) vet ./...

test:
	$(GO) test -race ./...

# The integration suite runs the REAL binaries against containerised infrastructure.
#
# It is a separate TARGET but part of `all`, and the distinction matters: it must not run CONCURRENTLY
# with the unit suite — every scenario starts two containers, and under `go test ./...` the control plane
# was still not listening after sixty seconds (contention, not a product failure; inflating timeouts would
# only have made the failures slower to arrive). Sequencing it after `test` in `all` gives it the machine
# to itself while keeping it in the gate.
#
# It IS the gate for the cmd/ wiring, which nothing else reaches: D285, D287, D292, D294 and D296 were all
# found by it and none by a package test. It skips cleanly without podman.
# THE TIMEOUT IS EXPLICIT, because Go's default is 10 MINUTES for the whole binary and the suite grew
# past it (D317) — the failure is a panic with a stack trace from whichever scenario happened to be
# running, which reads like that scenario hanging rather than like the suite outgrowing its budget. It
# cost a gate run to diagnose. A generous explicit value fails honestly when something really does hang.
integration:
	$(GO) test -tags integration -count=1 -timeout 40m ./test/integration/...

# Architectural boundaries that the compiler cannot express on its own.
check:
	./scripts/check-core-deps.sh
	./scripts/check-agent-deps.sh
	./scripts/check-cmd-closure.sh

# Regenerate Go types from the proto sources. Generated output is committed so
# a plain `go build` works without a protoc toolchain; `proto-check` guards
# against the tree drifting from its sources.
proto:
	$(PROTOC) --proto_path=proto \
		--go_out=. --go_opt=module=github.com/lucianoengel/openshield \
		proto/openshield/v1/*.proto

proto-check: proto
	@git diff --exit-code -- internal/core/corev1 \
		|| (echo "generated code is stale — run 'make proto' and commit"; exit 1)

tidy:
	$(GO) mod tidy
	@git diff --exit-code -- go.mod go.sum

# PLAT-6: a REPRODUCIBLE, SIGNED artifact set. Verification is a command an operator runs, not a
# paragraph in a README — `make verify-release` re-checks every digest against the signed manifest, and
# reports a file present that the manifest does NOT name (a verifier that only walks the manifest happily
# accepts an extra binary).
release:
	./scripts/release.sh

verify-release:
	$(GO) run ./cmd/openshieldctl verify-release --dir $${DIST:-dist}
