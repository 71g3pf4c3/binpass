# binpass shared wire contract (protobuf/gRPC) automation.

.PHONY: gen tidy build

gen: ## Regenerate protobuf, gRPC, gateway, and swagger code (buf).
	buf generate --path proto/v1

tidy: ## Tidy the module.
	go mod tidy

build: ## Compile the generated code.
	CGO_ENABLED=0 go build ./...
