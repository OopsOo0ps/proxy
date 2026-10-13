# Proxy — 构建与开发入口。
#
# 常用目标：
#   make build      构建全部二进制到 bin/
#   make test       运行全部单元测试
#   make cover      运行测试并打印总覆盖率
#   make lint       运行 golangci-lint（首次自动下载到 .bin/，带校验）
#   make demo       一条命令跑通本地三节点演示（构建 → 启动 → 验证）
#   make demo-up    本地三节点演示：后台启动 3 节点 + 客户端（日志在 var/demo/）
#   make demo-check 演示链路验证（HTTP / SOCKS5 / DNS 网关 / 指标）
#   make demo-down  停止本地演示进程
#   make run-server 前台运行 proxy-server（默认 configs/local/server-1.yaml）
#   make run-client 前台运行 proxy-client（默认 configs/local/client.yaml）
# 完整目标列表见 make help。
#
# 提示：运行与演示目标可通过变量覆盖，例如：
#   make run-server SERVER_CONFIG=configs/example-server.yaml
# 网络受限时可用镜像覆盖下载源，例如：
#   make lint GOLANGCI_LINT_BASE=https://<mirror>/golangci-lint/releases/download/$(GOLANGCI_LINT_VERSION)

GO         ?= go
BIN_DIR    := bin
TOOL_DIR   := .bin
MODULE     := github.com/OopsOo0ps/proxy

DOCKER           ?= docker
DOCKER_PLATFORM  ?= linux/amd64
DOCKER_TAG       ?= dev

# 本地三节点演示（与 configs/local/ 保持一致；调整演示配置时请同步这里）。
DEMO_DIR      := var/demo
DEMO_HTTP     ?= 127.0.0.1:18080
DEMO_SOCKS5   ?= 127.0.0.1:11080
DEMO_DNS      ?= 127.0.0.1:1053
DEMO_METRICS  ?= 127.0.0.1:19100
DEMO_USER     ?= alice:change-me
DEMO_TARGET   ?= https://example.com

# 前台运行目标使用的配置（可用 SERVER_CONFIG= / CLIENT_CONFIG= 覆盖）。
SERVER_CONFIG ?= configs/local/server-1.yaml
CLIENT_CONFIG ?= configs/local/client.yaml

VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
  -X '$(MODULE)/internal/version.Version=$(VERSION)' \
  -X '$(MODULE)/internal/version.Commit=$(COMMIT)' \
  -X '$(MODULE)/internal/version.BuildDate=$(BUILD_DATE)'

GOLANGCI_LINT_VERSION ?= v2.14.0
GOLANGCI_LINT_BASE    ?= https://github.com/golangci/golangci-lint/releases/download/$(GOLANGCI_LINT_VERSION)
GOLANGCI_LINT := $(TOOL_DIR)/golangci-lint

.PHONY: all build test cover lint fmt vet run run-server run-client dev-cert \
	version demo demo-up demo-check demo-down \
	docker-build docker-build-debug clean help

all: build

build:
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/proxy-server ./cmd/server
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/proxy-client ./cmd/client

version: build
	@$(BIN_DIR)/proxy-server -version
	@$(BIN_DIR)/proxy-client -version

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
	$(BIN_DIR)/proxy-server -config $(SERVER_CONFIG)

run-client: build
	$(BIN_DIR)/proxy-client -config $(CLIENT_CONFIG)

dev-cert:
	@mkdir -p var
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
		-keyout var/dev-key.pem -out var/dev-cert.pem \
		-days 365 -nodes -subj "/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
	@echo "已生成 var/dev-cert.pem 与 var/dev-key.pem"

# ---- 本地三节点演示 ----------------------------------------------------------
# demo       一条命令跑通：构建 → 启动 3 节点 + 客户端 → 四项验证（进程保持运行）。
# demo-up    生成证书并后台启动 3 个出口节点 + 1 个客户端（PID 与日志在 var/demo/）。
# demo-check 验证四条链路：HTTP 入站 / SOCKS5 入站 / DNS 网关 / Prometheus 指标。
# demo-down  停止全部演示进程（SIGTERM 优雅关停，等待排空后退出）。

demo:
	@$(MAKE) --no-print-directory demo-up
	@$(MAKE) --no-print-directory demo-check
	@echo "演示完成：make demo-down 停止演示进程。"

demo-up: build dev-cert
	@command -v curl >/dev/null 2>&1 || { echo "需要 curl 用于就绪检查（Ubuntu 可 apt install curl）"; exit 1; }
	@mkdir -p $(DEMO_DIR)
	@start() { name=$$1; shift; \
		if [ -f $(DEMO_DIR)/$$name.pid ] && kill -0 $$(cat $(DEMO_DIR)/$$name.pid) 2>/dev/null; then \
			echo "  $$name 已在运行（pid $$(cat $(DEMO_DIR)/$$name.pid)）"; return 0; \
		fi; \
		nohup "$$@" >$(DEMO_DIR)/$$name.log 2>&1 </dev/null & echo $$! > $(DEMO_DIR)/$$name.pid; \
		echo "  $$name 已启动（pid $$(cat $(DEMO_DIR)/$$name.pid)）"; \
	}; \
	start server-1 $(BIN_DIR)/proxy-server -config configs/local/server-1.yaml; \
	start server-2 $(BIN_DIR)/proxy-server -config configs/local/server-2.yaml; \
	start server-3 $(BIN_DIR)/proxy-server -config configs/local/server-3.yaml; \
	start client $(BIN_DIR)/proxy-client -config configs/local/client.yaml; \
	wait_http() { i=0; while [ $$i -lt 30 ]; do curl -fsS "$$1" >/dev/null 2>&1 && return 0; i=$$((i+1)); sleep 0.5; done; return 1; }; \
	for probe in http://127.0.0.1:19201/health http://127.0.0.1:19202/health http://127.0.0.1:19203/health http://$(DEMO_METRICS)/health; do \
		wait_http $$probe || { echo "等待 $$probe 超时，请查看 $(DEMO_DIR)/*.log"; exit 1; }; \
	done; \
	ok=1; \
	for name in server-1 server-2 server-3 client; do \
		kill -0 $$(cat $(DEMO_DIR)/$$name.pid) 2>/dev/null || { ok=0; echo "  !! $$name 未存活，日志末尾："; tail -n 5 $(DEMO_DIR)/$$name.log; }; \
	done; \
	if [ $$ok -eq 1 ]; then \
		echo "  HTTP 入站 http://$(DEMO_HTTP) ｜ SOCKS5 $(DEMO_SOCKS5) ｜ DNS 网关 $(DEMO_DNS) ｜ 指标 http://$(DEMO_METRICS)/metrics"; \
		echo "演示已就绪：make demo-check 验证 / make demo-down 停止。"; \
	else \
		echo "演示启动异常（见上方日志）"; exit 1; \
	fi

demo-check:
	@command -v curl >/dev/null 2>&1 || { echo "需要 curl（Ubuntu 可 apt install curl）"; exit 1; }
	@curl -fsS http://$(DEMO_METRICS)/health >/dev/null 2>&1 || { echo "演示未在运行：先执行 make demo-up（或 make demo）"; exit 1; }
	@printf 'HTTP/HTTPS 入站（CONNECT 隧道）：'; \
	curl -fsS -x http://$(DEMO_HTTP) -U $(DEMO_USER) $(DEMO_TARGET) -o /dev/null -w 'HTTP %{http_code}，耗时 %{time_total}s\n'
	@printf 'SOCKS5 入站：'; \
	curl -fsS --socks5-hostname $(DEMO_SOCKS5) -U $(DEMO_USER) $(DEMO_TARGET) -o /dev/null -w 'HTTP %{http_code}，耗时 %{time_total}s\n'
	@dns=$(DEMO_DNS); \
	if command -v dig >/dev/null 2>&1; then \
		printf 'DNS 网关（经出口节点远程解析 example.com）：'; \
		dig @$${dns%:*} -p $${dns##*:} +short example.com | tr '\n' ' '; echo; \
	else \
		echo 'DNS 网关：未找到 dig（Ubuntu 可 apt install dnsutils），跳过该验证'; \
	fi
	@echo 'Prometheus 指标（客户端，非零项节选）：'; \
	curl -fsS http://$(DEMO_METRICS)/metrics | grep -E '^(requests_total|active_connections)' | awk '$$NF != 0' | head -6 | sed 's/^/  /'

demo-down:
	@pids=''; \
	for name in server-1 server-2 server-3 client; do \
		pidfile=$(DEMO_DIR)/$$name.pid; \
		[ -f $$pidfile ] || continue; \
		pid=$$(cat $$pidfile); rm -f $$pidfile; \
		if kill -0 $$pid 2>/dev/null; then \
			kill $$pid && echo "  已通知停止：$${name}（pid $${pid}）"; pids="$$pids $$pid"; \
		else \
			echo "  $$name 未在运行"; \
		fi; \
	done; \
	[ -z "$$pids" ] && { echo "  没有需要停止的演示进程。"; exit 0; }; \
	i=0; while [ $$i -lt 20 ]; do \
		alive=''; \
		for p in $$pids; do kill -0 $$p 2>/dev/null && alive="$$alive $$p"; done; \
		[ -z "$$alive" ] && { echo "  演示已全部停止。"; exit 0; }; \
		i=$$((i+1)); sleep 1; \
	done; \
	echo "  以下进程仍在退出中（最长排空 15s）：$$alive"

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
		'  version         构建并打印两个二进制的版本信息' \
		'  test            运行全部单元测试' \
		'  cover           运行测试并打印总覆盖率' \
		'  lint            运行 golangci-lint' \
		'  fmt             格式化代码（go fmt）' \
		'  vet             运行 go vet' \
		'  demo            一条命令跑通本地演示（demo-up + demo-check）' \
		'  demo-up         本地三节点演示：后台启动 3 节点 + 客户端' \
		'  demo-check      演示链路验证（HTTP / SOCKS5 / DNS / 指标）' \
		'  demo-down       停止本地演示进程' \
		'  run             构建并前台启动 proxy-server（run-server 别名）' \
		'  run-server      前台运行 proxy-server（SERVER_CONFIG= 覆盖配置）' \
		'  run-client      前台运行 proxy-client（CLIENT_CONFIG= 覆盖配置）' \
		'  dev-cert        生成本地演示用自签证书到 var/' \
		'  docker-build    构建最小运行镜像（linux/amd64，distroless）' \
		'  docker-build-debug 构建排错镜像（alpine + 网络排查工具）' \
		'  clean           清理 bin/ 与 .bin/'
