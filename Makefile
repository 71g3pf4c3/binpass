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

.PHONY: all build test cover vet lint tidy clean

all: build

build: ## Build the binpass client.
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/binpass ./cmd/binpass

test: ## Run unit tests.
	$(GO) test ./...

test-race: ## Run unit tests with the race detector (requires cgo).
	CGO_ENABLED=1 $(GO) test -race ./...

cover: ## Run tests and report coverage.
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

vet: ## Run go vet.
	$(GO) vet ./...

tidy: ## Tidy the module.
	$(GO) mod tidy

clean: ## Remove build artefacts.
	rm -rf $(BIN_DIR) coverage.out
