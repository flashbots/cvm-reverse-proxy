VERSION := $(shell git describe --tags --always --dirty="-dev")

.PHONY: all
all: clean build-proxy-client build-proxy-server

.PHONY: v
v:
	@echo "Version: ${VERSION}"

.PHONY: clean
clean:
	rm -rf build/

.PHONY: build-proxy-client
build-proxy-client:
	@mkdir -p ./build
	go build -trimpath -ldflags "-X cvm-reverse-proxy/common.Version=${VERSION}" -v -o ./build/proxy-client cmd/proxy-client/main.go

.PHONY: build-proxy-server
build-proxy-server:
	@mkdir -p ./build
	go build -trimpath -ldflags "-X cvm-reverse-proxy/common.Version=${VERSION}" -v -o ./build/proxy-server cmd/proxy-server/main.go

.PHONY: test
test:
	go test ./...

.PHONY: test-race
test-race:
	go test -race ./...

.PHONY: lint
lint:
	gofmt -d -s cmd common proxy tdx
	gofumpt -d -extra cmd common proxy tdx
	go vet ./cmd/... ./common/... ./proxy/... ./tdx/...
	staticcheck cmd common proxy tdx
	golangci-lint run
	nilaway cmd common proxy tdx

.PHONY: fmt
fmt:
	gofmt -s -w cmd common proxy tdx
	gci write cmd common proxy tdx
	gofumpt -w -extra cmd common proxy tdx
	go mod tidy

.PHONY: gofumpt
gofumpt:
	gofumpt -l -w -extra cmd common proxy tdx

.PHONY: lt
lt: lint test

.PHONY: cover
cover:
	go test -coverprofile=/tmp/go-sim-lb.cover.tmp ./...
	go tool cover -func /tmp/go-sim-lb.cover.tmp
	unlink /tmp/go-sim-lb.cover.tmp

.PHONY: cover-html
cover-html:
	go test -coverprofile=/tmp/go-sim-lb.cover.tmp ./...
	go tool cover -html=/tmp/go-sim-lb.cover.tmp
	unlink /tmp/go-sim-lb.cover.tmp
