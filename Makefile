# Proxy — 构建与开发入口。
#
# 常用目标：
#   make build   构建全部二进制到 bin/
#   make test    运行全部单元测试
#   make cover   运行测试并打印总覆盖率
#   make lint    运行 golangci-lint（首次自动下载到 .bin/，带校验）
#   make run     构建并前台启动 proxy-server
#   make dev-cert 生成本地演示用自签证书（var/）
# 完整目标列表见 make help。
#
# 提示：网络受限时可用镜像覆盖下载源，例如：
#   make lint GOLANGCI_LINT_BASE=https://<mirror>/golangci-lint/releases/download/$(GOLANGCI_LINT_VERSION)

GO         ?= go
BIN_DIR    := bin
TOOL_DIR   := .bin
MODULE     := github.com/OopsOo0ps/proxy

DOCKER           ?= docker
DOCKER_PLATFORM  ?= linux/amd64
DOCKER_TAG       ?= dev

VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
  -X '$(MODULE)/pkg/version.Version=$(VERSION)' \
  -X '$(MODULE)/pkg/version.Commit=$(COMMIT)' \
  -X '$(MODULE)/pkg/version.BuildDate=$(BUILD_DATE)'

GOLANGCI_LINT_VERSION ?= v2.14.0
GOLANGCI_LINT_BASE    ?= https://github.com/golangci/golangci-lint/releases/download/$(GOLANGCI_LINT_VERSION)
GOLANGCI_LINT := $(TOOL_DIR)/golangci-lint

.PHONY: all build test cover lint fmt vet run run-server run-client run-controller dev-cert \
	docker-build docker-build-debug clean help

all: build

build:
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/proxy-server ./cmd/server
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/proxy-client ./cmd/client
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/proxy-controller ./cmd/controller

test:
	$(GO) test ./...

cover:
	$(GO) test -coverprofile=coverage.out ./...
	@$(GO) tool cover -func=coverage.out | tail -1

lint: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run

$(GOLANGCI_LINT):
	@mkdir -p $(TOOL_DIR)
	@set -e; \
	os=$$(uname -s | tr 'A-Z' 'a-z'); \
	arch=$$(uname -m); \
	case "$$arch" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; esac; \
	ver=$$(printf '%s' '$(GOLANGCI_LINT_VERSION)' | sed 's/^v//'); \
	file="golangci-lint-$$ver-$$os-$$arch.tar.gz"; \
	tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT; \
	echo "downloading $$file"; \
	curl -sSfL "$(GOLANGCI_LINT_BASE)/$$file" -o "$$tmp/$$file"; \
	curl -sSfL "$(GOLANGCI_LINT_BASE)/golangci-lint-$$ver-checksums.txt" -o "$$tmp/checksums.txt"; \
	if command -v sha256sum >/dev/null 2>&1; then sum='sha256sum'; else sum='shasum -a 256'; fi; \
	expected=$$(grep "[[:space:]]$$file$$" "$$tmp/checksums.txt" | awk '{print $$1}'); \
	actual=$$($$sum "$$tmp/$$file" | awk '{print $$1}'); \
	if [ -z "$$expected" ] || [ "$$expected" != "$$actual" ]; then \
		echo "error: checksum verification failed for $$file" >&2; \
		exit 1; \
	fi; \
	tar -xzf "$$tmp/$$file" -C "$$tmp"; \
	mv "$$tmp/golangci-lint-$$ver-$$os-$$arch/golangci-lint" $(GOLANGCI_LINT)

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

run: run-server

run-server: build
	$(BIN_DIR)/proxy-server

run-client: build
	$(BIN_DIR)/proxy-client

run-controller: build
	$(BIN_DIR)/proxy-controller

dev-cert:
	@mkdir -p var
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
		-keyout var/dev-key.pem -out var/dev-cert.pem \
		-days 365 -nodes -subj "/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
	@echo "已生成 var/dev-cert.pem 与 var/dev-key.pem"

# 构建最小运行镜像（distroless，非 root，linux/amd64）。
docker-build:
	$(DOCKER) build --platform $(DOCKER_PLATFORM) --target client -t proxy-client:$(DOCKER_TAG) \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg BUILD_DATE=$(BUILD_DATE) .
	$(DOCKER) build --platform $(DOCKER_PLATFORM) --target server -t proxy-server:$(DOCKER_TAG) \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg BUILD_DATE=$(BUILD_DATE) .
	@echo "最小镜像（目标 <30MB）："
	@$(DOCKER) images --filter reference='proxy-client' --filter reference='proxy-server' \
		--format '{{.Repository}}:{{.Tag}} {{.Size}}'

# 构建排错镜像（alpine + curl/dig/tcpdump/ss/nc/openssl/bash/jq，root）。
docker-build-debug:
	$(DOCKER) build --platform $(DOCKER_PLATFORM) --target client-debug -t proxy-client-debug:$(DOCKER_TAG) \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg BUILD_DATE=$(BUILD_DATE) .
	$(DOCKER) build --platform $(DOCKER_PLATFORM) --target server-debug -t proxy-server-debug:$(DOCKER_TAG) \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg BUILD_DATE=$(BUILD_DATE) .
	@$(DOCKER) images --filter reference='proxy-client-debug' --filter reference='proxy-server-debug' \
		--format '{{.Repository}}:{{.Tag}} {{.Size}}'

clean:
	rm -rf $(BIN_DIR) $(TOOL_DIR)

help:
	@printf '%s\n' \
		'可用目标：' \
		'  build           构建全部二进制到 bin/' \
		'  test            运行全部单元测试' \
		'  cover           运行测试并打印总覆盖率' \
		'  lint            运行 golangci-lint' \
		'  fmt             格式化代码（go fmt）' \
		'  vet             运行 go vet' \
		'  run             构建并前台启动 proxy-server' \
		'  run-client      构建并前台启动 proxy-client' \
		'  run-controller  运行 proxy-controller' \
		'  dev-cert        生成本地演示用自签证书到 var/' \
		'  docker-build    构建最小运行镜像（linux/amd64，distroless）' \
		'  docker-build-debug 构建排错镜像（alpine + 网络排查工具）' \
		'  clean           清理 bin/ 与 .bin/'
