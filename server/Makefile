# binpassd build automation.

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

.PHONY: all build gen test cover vet tidy docker snapshot release clean

all: build

gen: ## Regenerate the shared wire contract and refresh the bundled swagger.
	$(MAKE) -C ../api gen
	cp ../api/gen/openapiv2/binpass.swagger.json internal/controller/http/v1/swagger/binpass.swagger.json

build: ## Build the binpassd binary.
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/binpassd ./cmd/binpassd

test: ## Run unit tests.
	$(GO) test ./...

cover: ## Report business-logic coverage (excludes generated code).
	$(GO) test -short -coverpkg=./internal/...,./pkg/... -coverprofile=coverage.out ./...
	@grep -v -E '/gen/|_mock\.go' coverage.out > coverage.filtered || cp coverage.out coverage.filtered
	@$(GO) tool cover -func=coverage.filtered | awk '/^total:/ {print "total: "$$3}'

vet: ## Run go vet.
	$(GO) vet ./...

tidy: ## Tidy the module.
	$(GO) mod tidy

docker: ## Build the Docker image.
	docker build -t binpassd:$(VERSION) .

snapshot: ## Build a local release snapshot with goreleaser (no publish).
	goreleaser release --snapshot --clean

release: ## Cut a release with goreleaser (requires a tag + tokens).
	goreleaser release --clean

clean: ## Remove build artefacts.
	rm -rf $(BIN_DIR) dist coverage.out coverage.filtered
