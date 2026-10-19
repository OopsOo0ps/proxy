# 更新日志

本文件记录 Proxy 的显著变更。格式参考
[Keep a Changelog](https://keepachangelog.com/)，版本号遵循
[语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 新增（Added）

- 出口节点故障转移总超时预算 `timeouts.failover`（缺省 30s，可配置）：
  单次请求在全部候选节点上的等待收敛为预算上限，不再随节点数量线性放大；
  预算或调用方取消导致的尝试中断不计入节点被动失败，健康节点不会被误冷却。
- 客户端 TLS 会话复用：出口节点 TLS 配置启用 `ClientSessionCache`（每节点
  LRU 1024 条会话），新建隧道可恢复会话，省去一次完整 TLS 握手，显著抬高
  冷路径（每请求新建隧道）吞吐。
- 入站 HTTP 请求头大小上限收敛为 64KiB（stdlib 缺省 1MiB）：高并发下的
  头部缓冲内存风险面相应收敛，任何正常 CONNECT / 绝对地址请求（含
  `Proxy-Authorization`）不受影响。
- systemd 单元（`deploy/systemd/`）内置运行时资源约束：`GOMEMLIMIT`、
  `MemoryHigh`、`MemoryMax` 与 `TasksMax=infinity`，取值面向 2 vCPU / 4GB
  目标环境（`GOMEMLIMIT` 低于 `MemoryMax`，让 GC 先行软限回收）。

### 变更（Changed）

- `limits.max-connections` 默认值 1024 → 8192。**升级影响**：进程并发上限
  提高 8 倍，超限拒绝（HTTP 503 / SOCKS5 `0x05 0xFF` / 隧道关闭）随之更晚
  触发，内存占用随并发上升；按实测口径每条隧道（双进程合计）≈200KB，小内存
  机器应显式调低该值。
- 核心模型抽象重构（内部结构演进，PR #32–#35）：新增 `core` / `outbound` /
  `session` 契约与生命周期包、依赖方向守护测试（`internal/arch`）、遥测改为
  组件 Observer 窄接口、Trojan 协议知识收进协议包且出口节点池协议无关。
  **对用户可见的行为、配置格式、日志与指标完全不变**（全部既有测试一行未改
  通过；覆盖率与基线持平）。

### 安全（Security）

- 运维端点（`metrics.listen`）默认拒绝绑定非环回地址：一次绑定疏忽不再直接
  对外暴露拓扑与运行时状态；确需远程只读访问时显式设置 `metrics.allow_remote: true`
  （启动会打 warning 提醒暴露面；该开关属启动时绑定语义，热加载翻动会被拒绝并要求重启）。
- `PUT /log/level` 日志级别变更永远只接受环回来源的请求（远程一律 403），
  不受 `metrics.allow_remote` 影响。
- 节点 params 的 `insecure-skip-verify` 仅环回节点可用（本地自签演示），
  非环回节点一律拒绝组装；远程自签节点请改用 `ca-file` 信任自定义 CA。
- 分流规则源强制 https-only（环回地址豁免，便于本地试验），远程规则源支持
  可选的 sha256 内容钉扎，防止规则源被中间人篡改后劫持分流。
- 入站认证失败按来源 IP 指数退避（100ms 起步、2s 封顶，进程内共享计数；
  认证成功即重置），抬高针对入站代理的密码爆破成本。
- 未配置服务端 `decoy-file` 时使用内置伪装页：仅适用于本地试验，启动会记录
  warning 提醒；生产建议显式配置自定义页面避免被指纹识别（README 已同步建议）。

### 构建（Build）

- Makefile 新增本地演示工作流：`make demo` 一条命令完成构建 → 启动 → 验证，
  `demo-up` / `demo-check` / `demo-down` 可分步起停并验证 3 节点演示
  （HTTP / SOCKS5 / DNS / 指标）；新增 `version` 目标；`run-server` / `run-client`
  支持 `SERVER_CONFIG` / `CLIENT_CONFIG` 覆盖配置。

### 文档（Documentation）

- README 重组为「定位 / 快速开始 / 关键信号」，配置、运维与验证的深度内容
  迁入 [Wiki](https://github.com/OopsOo0ps/proxy/wiki)（配置参考、分流与规则、
  DNS 策略、运行时语义、可观测性、部署指南、性能与容量、测试与验收等）；
  文档命令统一为 Makefile 目标，不再出现直接调用 `bin/` 二进制的示例。

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
