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

.PHONY: all build gen test cover vet tidy docker clean

all: build

gen: ## Regenerate protobuf, gRPC, gateway, and swagger code (buf).
	buf generate --path api/proto/v1
	cp gen/openapiv2/binpass.swagger.json internal/controller/http/v1/swagger/binpass.swagger.json

build: ## Build the binpassd binary.
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/binpassd ./cmd/binpassd

test: ## Run unit tests.
	$(GO) test ./...

cover: ## Report business-logic coverage.
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

vet: ## Run go vet.
	$(GO) vet ./...

tidy: ## Tidy the module.
	$(GO) mod tidy

docker: ## Build the Docker image.
	docker build -t binpassd:$(VERSION) .

clean: ## Remove build artefacts.
	rm -rf $(BIN_DIR) coverage.out
