# 更新日志

本文件记录 Proxy 的显著变更。格式参考
[Keep a Changelog](https://keepachangelog.com/)，版本号遵循
[语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 文档（Documentation）

- README 重组为「定位 / 快速开始 / 关键信号」，配置、运维与验证的深度内容
  迁入 [Wiki](https://github.com/OopsOo0ps/proxy/wiki)（配置参考、分流与规则、
  DNS 策略、运行时语义、可观测性、部署指南、性能与容量、测试与验收等）。

## [0.1.0] - 2026-10-11

首个公开发布：可用的代理核心与生产部署能力。

### 新增（Added）

- HTTP/HTTPS 正向代理入站（CONNECT 隧道与绝对地址转发）。
- SOCKS5 入站（TCP CONNECT，可选用户名/密码认证）。
- 客户端 ↔ 服务端隧道（Trojan over TLS）：多节点轮询、上游连接池预热复用、
  主动健康检查摘除与自动加回、失败冷却转移。
- 域名分流：本地规则文件与远程 URL 动态加载（定时刷新、失败保持旧规则）。
- 可选 DNS 网关（remote DNS；防污染、TC 截断回退 TCP、非法查询拒绝）。
- 配置热加载（SIGHUP 校验失败保持旧配置，成功原子生效）。
- 认证：HTTP `Proxy-Authorization` / SOCKS5 RFC 1929；监听非环回地址时强制认证。
- 结构化 JSON 日志与运行时动态日志级别（`/log/level`）。
- Prometheus 指标（`/metrics`）与健康/运行时状态端点（`/health`、`/stats`）。
- 优雅关闭（SIGTERM drain）与过载保护（连接上限 + 背压）。
- 多阶段 Docker 镜像：distroless 最小版（<30MB）与排错版，linux/amd64。
- systemd 单元（Ubuntu 22.04 原生部署，含沙箱加固）。

### 文档（Documentation）

- README：架构、快速开始、生产部署、配置参考、观测、限制说明、路线图。
- [CONTRIBUTING.md](CONTRIBUTING.md)：开发环境、提交规范、测试与 lint 要求。
- [SECURITY.md](SECURITY.md)：漏洞报告流程与响应时限。

### 测试（Tests）

- 单元测试与黑盒集成测试（构建并启动真实二进制；分流、指标、半关闭传播校验）。
- 混沌测试（SIGKILL 上游 → 自动摘除 / 流量转移 / 自动加回；含 3 台 VPS 真机演练）。
- 热路径基准测试与单机压力测试报告（1k/5k/10k 并发曲线）。

### 已知限制（Known Limitations）

- 暂不支持 UDP（SOCKS5 UDP ASSOCIATE / Trojan UDP 转发）与 TUN/透明代理，
  详见 README「限制说明」。
