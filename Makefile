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

.PHONY: all build test cover vet lint tidy clean snapshot release containers ci-parity man

all: build

build: ## Build the binpass client.
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/binpass ./cmd/binpass

snapshot: ## Build a local release snapshot with goreleaser (no publish).
	# Keyless signing needs the CI's OIDC identity, which a local run does
	# not have; skipping it is what makes a local snapshot possible at all.
	goreleaser release --snapshot --clean --skip=sign

man: build ## Regenerate man pages into man/ for local preview (not committed).
	# The pages are generated at build time by every packager (nix,
	# goreleaser); this target is the same generation, run by hand, so
	# `man ./man/binpass.1` shows exactly what a package would install.
	# man/ is gitignored on purpose: a committed page can drift from the
	# flags the binary actually accepts.
	rm -rf man
	./bin/binpass man man

release: ## Cut a release with goreleaser (requires a tag + GITHUB_TOKEN).
	goreleaser release --clean

test: ## Run unit tests (warns loudly when suites skip for missing tools).
	@GO=$(GO) ./scripts/run-tests.sh

containers: ## Build and run every container test suite (needs Docker).
	./scripts/containers.sh

test-race: ## Run unit tests with the race detector (requires cgo).
	CGO_ENABLED=1 $(GO) test -race ./...

cover: ## Run tests and report business-logic coverage (excludes mocks/gen).
	$(GO) test -coverpkg=./pkg/...,./internal/... -coverprofile=coverage.out ./...
	@grep -v -E '/mocks/|_mock\.go|/gen/' coverage.out > coverage.filtered
	@$(GO) tool cover -func=coverage.filtered | awk '/^total:/ {print "total: "$$3}'

vet: ## Run go vet.
	$(GO) vet ./...

ci-parity: ## Verify .github/workflows/ci.yml and .gitlab-ci.yml stay in sync.
	./scripts/ci-parity.sh

tidy: ## Tidy the module.
	$(GO) mod tidy

clean: ## Remove build artefacts.
	rm -rf $(BIN_DIR) coverage.out
