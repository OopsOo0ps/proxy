# proxy 的容器镜像（多阶段构建，linux/amd64）。
#
# 目标阶段（每条二进制独立镜像）：
#   client / server                 —— 最小运行镜像：distroless/static，非 root，无 shell
#   client-debug / server-debug     —— 排错镜像：alpine + 常用网络排查工具（root）
#
# 构建入口见 Makefile（make docker-build / docker-build-debug），等价命令：
#   docker build --platform linux/amd64 --target client -t proxy-client:dev .
#
# 构建阶段跑在原生架构（BUILDPLATFORM）上并交叉编译到 linux/amd64，
# 在 Apple Silicon 上无需仿真编译。
#
# 基础镜像固定 digest：构建可复现，也避免个别网络环境下标签解析失败。
# 升级方式：docker buildx imagetools inspect <image>:<tag>，取新的 sha256 更新此处。

FROM --platform=$BUILDPLATFORM golang:1.25@sha256:699337d620559a59b4a2bb298ad59611e535d2ee755a34cf2d2a98f37578dc80 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# TARGETARCH 由 buildx 注入；plain docker build 下缺省 linux/amd64（本仓库目标平台）。
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
        -ldflags "-s -w \
          -X github.com/OopsOo0ps/proxy/pkg/version.Version=$VERSION \
          -X github.com/OopsOo0ps/proxy/pkg/version.Commit=$COMMIT \
          -X github.com/OopsOo0ps/proxy/pkg/version.BuildDate=$BUILD_DATE" \
        -o /out/proxy-client ./cmd/client \
 && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
        -ldflags "-s -w \
          -X github.com/OopsOo0ps/proxy/pkg/version.Version=$VERSION \
          -X github.com/OopsOo0ps/proxy/pkg/version.Commit=$COMMIT \
          -X github.com/OopsOo0ps/proxy/pkg/version.BuildDate=$BUILD_DATE" \
        -o /out/proxy-server ./cmd/server

# ---- 最小运行镜像：proxy-client ----
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS client
COPY --from=build /out/proxy-client /usr/local/bin/proxy-client
COPY --from=build /src/configs/example-client.yaml /etc/proxy/client.yaml
EXPOSE 8080 1080
ENTRYPOINT ["/usr/local/bin/proxy-client"]
CMD ["-config", "/etc/proxy/client.yaml"]

# ---- 最小运行镜像：proxy-server ----
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS server
COPY --from=build /out/proxy-server /usr/local/bin/proxy-server
COPY --from=build /src/configs/example-server.yaml /etc/proxy/server.yaml
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/proxy-server"]
CMD ["-config", "/etc/proxy/server.yaml"]

# ---- 排错镜像：proxy-client-debug（alpine + 排查工具，root）----
FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 AS client-debug
RUN apk add --no-cache ca-certificates curl bind-tools tcpdump iproute2 netcat-openbsd openssl bash jq
COPY --from=build /out/proxy-client /usr/local/bin/proxy-client
COPY --from=build /src/configs/example-client.yaml /etc/proxy/client.yaml
EXPOSE 8080 1080
ENTRYPOINT ["/usr/local/bin/proxy-client"]
CMD ["-config", "/etc/proxy/client.yaml"]

# ---- 排错镜像：proxy-server-debug ----
FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 AS server-debug
RUN apk add --no-cache ca-certificates curl bind-tools tcpdump iproute2 netcat-openbsd openssl bash jq
COPY --from=build /out/proxy-server /usr/local/bin/proxy-server
COPY --from=build /src/configs/example-server.yaml /etc/proxy/server.yaml
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/proxy-server"]
CMD ["-config", "/etc/proxy/server.yaml"]
