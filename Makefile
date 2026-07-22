GO ?= go
PROTOC ?= protoc

.PHONY: all build test vet check cross-compile proto proto-check tidy

all: vet test check build cross-compile

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
