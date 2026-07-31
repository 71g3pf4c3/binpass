# binpass build automation.

GO        ?= go
BIN_DIR   ?= bin
VERSION   ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILDDATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.buildDate=$(BUILDDATE)

export CGO_ENABLED := 0

.PHONY: all build test cover vet lint tidy clean snapshot release

all: build

build: ## Build the binpass client.
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/binpass ./cmd/binpass

snapshot: ## Build a local release snapshot with goreleaser (no publish).
	goreleaser release --snapshot --clean

release: ## Cut a release with goreleaser (requires a tag + GITHUB_TOKEN).
	goreleaser release --clean

test: ## Run unit tests.
	$(GO) test ./...

test-race: ## Run unit tests with the race detector (requires cgo).
	CGO_ENABLED=1 $(GO) test -race ./...

cover: ## Run tests and report business-logic coverage (excludes mocks/gen).
	$(GO) test -coverpkg=./pkg/...,./internal/... -coverprofile=coverage.out ./...
	@grep -v -E '/mocks/|_mock\.go|/gen/' coverage.out > coverage.filtered
	@$(GO) tool cover -func=coverage.filtered | awk '/^total:/ {print "total: "$$3}'

vet: ## Run go vet.
	$(GO) vet ./...

tidy: ## Tidy the module.
	$(GO) mod tidy

clean: ## Remove build artefacts.
	rm -rf $(BIN_DIR) coverage.out
