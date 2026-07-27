GO ?= go
PROTOC ?= protoc

.PHONY: all build test integration vet check cross-compile proto proto-check tidy release verify-release

all: vet test check build cross-compile integration

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
integration:
	$(GO) test -tags integration -count=1 ./test/integration/...

# Architectural boundaries that the compiler cannot express on its own.
check:
	./scripts/check-core-deps.sh
	./scripts/check-agent-deps.sh

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
