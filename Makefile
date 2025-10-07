# Heavily inspired by Lighthouse: https://github.com/sigp/lighthouse/blob/stable/Makefile
# and Reth: https://github.com/paradigmxyz/reth/blob/main/Makefile
.DEFAULT_GOAL := help

VERSION ?= $(shell git describe --tags --always --dirty="-dev")

##@ Help

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: v
v: ## Show the version
	@echo "Version: ${VERSION}"

##@ Build

.PHONY: clean
clean: ## Clean the build directory
	rm -rf build/

.PHONY: build
build: clean build-proxy-client build-proxy-server ## Build the proxy client and server

.PHONY: build-proxy-client
build-proxy-client: ## Build the proxy client
	@mkdir -p ./build
	go build -trimpath -ldflags "-s -w -buildid= -X github.com/flashbots/cvm-reverse-proxy/common.Version=${VERSION}" -v -o ./build/proxy-client cmd/proxy-client/main.go

.PHONY: build-proxy-server
build-proxy-server: ## Build the proxy server
	@mkdir -p ./build
	go build -trimpath -ldflags "-s -w -buildid= -X github.com/flashbots/cvm-reverse-proxy/common.Version=${VERSION}" -v -o ./build/proxy-server cmd/proxy-server/main.go

##@ Test & Development

.PHONY: test
test: ## Run tests
	go test ./cmd/... ./common/... ./proxy/...

.PHONY: test-race
test-race: ## Run tests with race detector
	go test -race ./cmd/... ./common/... ./proxy/...

.PHONY: lint
lint: ## Run linters
	gofmt -d -s cmd common proxy
	gofumpt -d -extra cmd common proxy
	go vet ./cmd/... ./common/... ./proxy/...
	staticcheck ./cmd/... ./common/... ./proxy/...
	# golangci-lint run --exclude-dirs internal --exclude-dirs-use-default=false

.PHONY: fmt
fmt: ## Format the code
	gofmt -s -w cmd common proxy
	gci write cmd common proxy
	gofumpt -w -extra cmd common proxy
	go mod tidy

.PHONY: gofumpt
gofumpt: ## Run gofumpt
	gofumpt -l -w -extra cmd common proxy

.PHONY: lt ## Alias for lint and test
lt: lint test

.PHONY: cover
cover: ## Run tests with coverage
	go test -coverprofile=/tmp/go-sim-lb.cover.tmp ./...
	go tool cover -func /tmp/go-sim-lb.cover.tmp
	unlink /tmp/go-sim-lb.cover.tmp

.PHONY: cover-html
cover-html: ## Run tests with coverage and open the HTML report
	go test -coverprofile=/tmp/go-sim-lb.cover.tmp ./...
	go tool cover -html=/tmp/go-sim-lb.cover.tmp
	unlink /tmp/go-sim-lb.cover.tmp

.PHONY: docker-images
docker-images: ## Build the Docker images
	DOCKER_BUILDKIT=1 docker build \
		--platform linux/amd64 \
		--build-arg VERSION=${VERSION} \
		--file proxy-server.dockerfile \
		--tag cvm-proxy-server \
	.
