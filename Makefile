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

.PHONY: build-server
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
	gofmt -d -s .
	gofumpt -d -extra .
	go vet ./...
	staticcheck ./...
	golangci-lint run
	nilaway ./...

.PHONY: fmt
fmt:
	gofmt -s -w .
	gci write .
	gofumpt -w -extra .
	go mod tidy

.PHONY: gofumpt
gofumpt:
	gofumpt -l -w -extra .

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
