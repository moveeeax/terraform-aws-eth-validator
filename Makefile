.PHONY: help build test test-go test-tf fmt lint install clean demo

BINARY := slashguard
VERSION ?= dev

help:
	@grep -E '^[a-zA-Z-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

build: ## Build the slashguard binary
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY) ./cmd/slashguard

test: test-go test-tf ## Run every test

test-go: ## Go unit tests
	go test -race ./...

test-tf: ## Terraform module tests against a mocked provider (no AWS credentials)
	terraform init -backend=false -input=false
	terraform validate
	terraform test

fmt: ## Format Go and Terraform
	gofmt -w .
	terraform fmt -recursive

lint: ## Vet Go, check Terraform formatting, run tflint
	test -z "$$(gofmt -l .)"
	go vet ./...
	terraform fmt -check -recursive
	tflint --recursive

install: ## Install slashguard into GOBIN
	go install -ldflags "-X main.version=$(VERSION)" ./cmd/slashguard

demo: build ## Run slashguard against the bundled fixtures
	./$(BINARY) \
	  --interchange testdata/interchange/clean.json \
	  --keystores testdata/keystores/extra \
	  --genesis-validators-root 0x415f7d28a5d66b012547d7991089127689f11afa0b6792a080a000a15bbd0352 \
	  --current-epoch 120004 || true

clean: ## Remove build artefacts
	rm -f $(BINARY)
	rm -rf .terraform
