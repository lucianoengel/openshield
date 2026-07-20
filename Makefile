GO ?= go
PROTOC ?= protoc

.PHONY: all build test vet proto proto-check tidy

all: vet test build

build:
	$(GO) build ./...

vet:
	$(GO) vet ./...

test:
	$(GO) test -race ./...

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
