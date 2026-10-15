# proxy 设计文档

> **本文档为仓库内权威设计文档（design doc v3 重建版）**。全仓代码注释中的 `§X` 引用指向本文档的章节号；每节给出关键代码坐标（`file:line`），可离线核对。文档依据当前代码事实（main @ 6b3fcca）重构：先有代码，后有此稿；章节号沿用注释中既有引用，不随重构改动。

| 章节 | 主题 |
| --- | --- |
| §1–§3 | 引言、目标与非目标、总体架构 |
| §4 | 契约：core（§4.1）、outbound（§4.2）、session（§4.3）、消费方锚点表（§4.4） |
| §5 | 分层 L0–L5（§5.1）、横切原语（§5.2）、出站组合树（§5.3） |
| §6 | 分层治理：分层是数据（§6.1）、守护测试与 G4（§6.2）、第三方属主（§6.3） |
| §7 | 配置：严格 YAML（§7）、schema（§7.1）、缺省单点（§7.2）、Params 解码（§7.3）、两个分派点（§7.4） |
| §8 | 组装根（§8、§8.1）、热加载（§8.2）、测试纪律（§8.4） |
| §9 | 测试分层（§9.1）、入站一致性 C1–C10（§9.2） |
| §10–§12 | 可观测性、工程量化、术语与协议接入 |
| 附录 | 不变量 3/6（A）、C1–C10 对照（B）、G4 说明（C） |

---

## §1 引言

proxy 是生产级正向代理工具（Go 1.25+，面向 Ubuntu 22.04），产出三个二进制（`cmd/`）：

- `proxy-client`（`cmd/client`）——本机入口：HTTP / SOCKS5 / DNS 网关三种入站，按分流规则直连或经出口节点转发（§3、§5.3）。
- `proxy-server`（`cmd/server`）——远端出口：Trojan over TLS 隧道接受器 + 直连出站（§8）。
- `proxy-controller`（`cmd/controller`）——控制端骨架，未实现（README 路线图「控制端动态配置」未勾选）。

工程基调：依赖方向严格单向且由守护测试强制（§6）；契约锚在消费方（§4）；配置是严格 YAML（§7）；热加载走不可变快照 + 原子切换（§8.2）。

## §2 目标与非目标

目标：

- 入站协议（HTTP/SOCKS5/DNS）与出口传输（Trojan，可扩展）解耦——入站只见 `core.TargetDialer` 契约，出口节点彻底协议无关（§4.1、§4.2、§5.3）。
- 分流可组合：内联规则 + 本地/远程规则源定时刷新，DNS 与流量同路（§5.3、§9.1）。
- 运行期可运维：SIGHUP 热加载、优雅关停排空、过载背压、`/metrics` `/health` `/stats` `/log/level`（§8.2、§10）。
- 每个质量属性都有机械守护：依赖分层（§6.2）、示例可构造（§6.2 G4）、入站/出站一致性套件（§9.2、§4.2）、导出接口清点（§11.2）。

非目标（当前明确不做）：UDP（SOCKS5 UDP ASSOCIATE）与 TUN 模式；多路复用出口协议接入预热模型（`outbound.Prewarmer` 注明其将来以自己的方式接入，`internal/outbound/outbound.go:8`）；控制端动态配置。

## §3 总体架构

请求流（client）：

```
入站 httpproxy / socks5 / dnsgw（§4.3 session 承载 accept/drain 机械）
  → auth 常量时间校验（internal/auth/auth.go:1）
  → core.TargetDialer（dialer.Dialer：routing/rule 规则判定 → direct 剪枝 或 nodes.Pool）
  → nodes.Pool（SWRR + 冷却 + 主动健康检查）→ connpool 预热池领取 或 Transport.DialTunnel
  → trojan over TLS 隧道 → relay 双向转发（半关闭/空闲超时，internal/relay/relay.go:1）
```

请求流（server）：`trojan` 服务端接受隧道（凭据只存 SHA-224 摘要，§7.3）→ 还原 Target → `dialer.Direct` 直连（服务端即出口，§5.3）→ relay 转发。

横切（两端相同）：`connlimit` 并发背压在 accept 阶段拒绝（§10）；`shutdown` 两阶段排空在关停时生效（§5.2）；SIGHUP 热加载走 §8.2 流水线。

目录与分层对应关系见 §5.1；两个组装根 `clientapp` / `serverapp` 见 §8。

## §4 契约

### §4.1 核心契约（L1：internal/core）

`internal/core/core.go:1`。core 只依赖标准库，不得依赖任何其它 internal 包（core.go:7）。

- **`core.Target`**（core.go:22）：`{Host, Port}` 结构体 + `String()`（core.go:35），全仓统一替代 `(host, port)` 双参签名，参数转置在编译期即不可能。Host 保存原始域名或 IP 字面量，解析是路由/出口的事（core.go:24）。
- **`core.Route` / `RouteAction`**（core.go:42、core.go:67）：`RouteDirect/RouteProxy/RouteReject`（core.go:44）；`Route{Action, Label}` 是一次连接实际走过的**权威路径**（不变量 6，见附录 A）。`Label` 词汇：Direct 时空串；Proxy 时为出口标签，池选择未定时为 `"pool"`（core.go:68，`clientapp/app.go:682` 的回退）。
- **`core.TargetDialer`**（core.go:82）：入站消费出站的唯一接口，天然可组合——路由分派器、直连拨号器、节点池都满足它（组合树见 §5.3，core.go:79）。`DialTarget` 返回的 `Route` 是权威路径，入站拿它填日志与遥测，不得自行推断上游（core.go:81）。
- **`core.Authenticator`**（core.go:90）：消费方锚点接口，`*auth.Store` 以结构化类型满足，无需 import core。
- **`core.Telemetry`**（core.go:152）：三类事件 `ConnOpened / ConnRejected / ConnDone` 恰好覆盖三类基础指标（requests_total / active_connections / connections_rejected_total，core.go:144）；缺省 `NopTelemetry`（core.go:164），组件测试零构造。事件发射时机全部由入站协议代码负责（core.go:149）。事件词汇常量唯一来源：`Proto*`（core.go:97）与 `Result*`（core.go:109）。

消费方锚点示例：`dnsgw.RouteDecider`（`internal/dnsgw/dnsgw.go:62`）消费同一分流判定（§5.3）。

### §4.2 出口传输契约（L1：internal/outbound）

`internal/outbound/outbound.go:1`。按能力拆分，不假设所有出口协议同形：

- **`Transport`**（必备，outbound.go:26）：`DialTunnel` 建立绑定到 target 的就绪隧道；失败必须返回非 nil error（不允许 `(nil, nil)` 假成功，outbound.go:30）。
- **`Prepared`**（outbound.go:34）：两阶段预热的中间句柄，对池不透明；`Discard` 是为首个非 Close 等价释放预留的扩展点。
- **`Prewarmer`**（可选，outbound.go:43）：「协议握手」与「绑定目标」两阶段分离的传输（如 Trojan）才有——`ConnectIdle` 入池 + `Bind` 补发绑定；多路复用协议不走此接口。
- **`Prober`**（可选，outbound.go:55）：主动健康探测；不实现则该节点只做被动健康判定。

每节点一个 Transport 实例，协议参数在协议构造器内封闭；节点池与组装根只见能力面，线格式细节不出协议包（outbound.go:12）。`nodes.Node = {Addr, Transport, Weight}` 彻底协议无关（`internal/nodes/pool.go:68`）。

**验收闸门**：`outbound.RunConformance`（`internal/outbound/conformance.go:33`）——新出口协议在回环夹具上调用一次即获得 dial / prewarm / probe 全量正负例检查（含并发拨号互不串扰、已取消 ctx 必须失败等假成功识别）。

### §4.3 入站生命周期契约（L1：internal/session）

`internal/session/session.go:1`。session 只承载 accept/drain 的机械部分：ctx 取消 → 停止接受 → 存量连接在排空期限内自然结束 → 超时强制断开。协议逻辑收敛在 `ConnHandler`（session.go:31）——握手、认证、拒绝路径与遥测事件发射都在协议侧，新入站实现 `ConnHandler` 即免费获得背压闸、双 ctx 语义与优雅排空。双 ctx 显式分离：`serveCtx` 供 accept 循环感知关停，`connCtx` 承载强制期限（session.go:10）。基于 net/http 的 httpproxy 排空路径保持独立，仅复用完成日志辅助（session.go:9）。

### §4.4 消费方锚点契约表

契约锚在消费方：各组件定义自己的窄接口，实现方以结构化类型满足。全仓导出接口清点（`internal/arch/arch_test.go:119`）按「契约表 + 消费方锚点」构成：

| 接口 | 归属 | 消费方 |
| --- | --- | --- |
| `core.TargetDialer` / `core.Authenticator` / `core.Telemetry` | §4.1 核心契约 | 入站组件 / metrics |
| `outbound.Transport` / `Prewarmer` / `Prober` / `Prepared` | §4.2 出口契约 | nodes.Pool |
| `session.ConnHandler` | §4.3 | socks5 / trojan 服务端 |
| `dialer.Router` | §5.3 | dialer.Dialer |
| `dnsgw.RouteDecider` / `DNSObserver` / `LivePolicy` | §4.1 锚点 / §10 / §8.2 | dnsgw |
| `httpproxy.LivePolicy` / `socks5.LivePolicy` | §8.2 热加载视图 | 入站 |
| `trojan.LivePolicy` / `trojan.Verifier` | §8.2 / §4.1 锚点 | trojan |
| `nodes.Observer` / `connpool.Observer` / `ruleset.Observer` | §10 事件归属 | metrics 适配 |
| `testutil.Inbound` | §9.2 套件夹具锚点 | 一致性套件 |

## §5 架构分层与组合树

### §5.1 分层（L0–L5）

分层的权威数据在 `internal/arch/layering.go:21`（层号值越小越底层；「cmd/ → internal/ → pkg/」中 pkg/ 当前为空）：

```text
L5 入口       cmd/client · cmd/server · test/integration
L4 组装/面/守护 config · clientapp · serverapp · metrics · status · testutil · arch
L3 协议端点    httpproxy · socks5 · dnsgw · trojan
L2 领域引擎    routing · ruleset · nodes · connpool · dialer
L1 契约/机械   core · outbound · session · lifecycle
L0 纯原语      relay · sockswire · netutil · logging · shutdown · connlimit
              auth · version · defaults · throttle
```

允许的 import = 层号严格更小的包 + 受控同层边（§6.1）。CLAUDE.md 中的「L4 组装根唯一可 import config / metrics」即 SameLayerEdges 中 clientapp/serverapp → {config, metrics, status} 三条边（layering.go:54）。同一分层内 serverapp 是 clientapp 的特化（§8.1）：没有 routing / ruleset / nodes，出站只有直连剪枝（§5.3）。

### §5.2 横切原语（L0）

- `relay`：双向转发，半关闭 + 空闲超时（relay.go:1、relay.go:109）。
- `connlimit`：进程级并发背压，`SetMax` 运行期可调（connlimit.go:1）。
- `shutdown`：两阶段排空原语（shutdown.go:1）。
- `logging`：slog JSON，含 request_id；`auth`：常量时间校验，只存 SHA-224 摘要（auth.go:1）。
- `defaults`：全部文档化数值缺省的唯一来源，config 与领域包引用同一常量（`internal/defaults/defaults.go:1`）。

### §5.3 组合树

出站侧是 `core.TargetDialer` 的组合树（core.go:79），根为 `dialer.Dialer`（`internal/dialer/dialer.go:1`）：

```
dialer.Dialer（路由感知分派器，实现 core.TargetDialer）
├─ direct 剪枝：dialer.Direct（net.Dial + Route{Direct}；client 与 server
│   两个组装根共用同一实现，dialer.go:35）
└─ proxy 分支：nodes.Pool（实现 core.TargetDialer，pool.go:376）
    └─ 每节点 PrewarmPool（connpool 实例；预热池是节点池的内部机制，
        nodes/pool.go:18）→ 领取未命中回退 Transport.DialTunnel
```

- 分派输入：`dialer.Router` 的实现是组装根的分流判定组合表 `routeTable`（`internal/clientapp/routing.go:1`）——私网直连是前置硬规则（规则不可覆盖），其后按声明顺序匹配内联规则与各规则源 Provider 的规则表（匹配顺序 = 声明顺序，`internal/routing/routing.go:113`），最后落缺省动作。单一判定入口保证「DNS 走哪条路 = 流量走哪条路」（routing.go:11）。
- 节点池：SWRR 加权轮询 + 指数退避冷却 + 主动健康检查摘除/加回 + failover 总预算（`nodes/pool.go:1`）；预热参数 `PrewarmOptions`（pool.go:105）。冷却状态只由真实拨号更新，摘除状态只由探测更新，二者独立但共同决定节点是否可接流量；全部节点都在冷却中时降级为全量尝试，避免「有节点但永远不试」的黑洞；节点被主动摘除时同步释放其空闲预热连接（pool.go:18）。
- 预热池（`internal/connpool/connpool.go:1`）：connect-then-bind 模型——池只认 connect（建立已完成握手、未绑定目标的空闲连接）与 bind（领取时补发绑定）两个函数，协议无关，由组装根从节点传输的 `Prewarmer` 能力映射而来；不具备该能力的传输不进预热池，每次直接 `DialTunnel`。领取时做非阻塞存活探测，失效连接不会流入业务；空闲连接受 IdleTTL 约束，按需补充、无流量时零周期开销。
- 服务端特化：serverapp 没有另一套模型——「入站 + 直连出站」，出站组合树就是共享的直连拨号器 `dialer.NewDirect`（`internal/serverapp/app.go:8`、app.go:189）。

## §6 分层治理

### §6 分层是数据，完备性即强制

`internal/arch/arch.go:1`：arch 以测试强制仓库的依赖治理。规则全部声明为 `layering.go` 的数据，守护测试只从数据推导，不存在第二份例外清单。

### §6.1 依赖规则的四张表（layering.go:1）

1. `Layers`（layering.go:21）——每包层号；允许的 import = 层号严格更小 + 同层边。
2. `SameLayerEdges`（layering.go:50）——受控同层边，每条一句话理由；相对早期「5 源包 / 10 条边」的计数有一条勘误：`outbound(L1) → core(L1)` 因 §4.2 契约签名直接引用 `core.Target` 不可避免（layering.go:46），登记后实为 6 源包 / 11 条边。
3. `ExternalDeps`（layering.go:62）——第三方依赖属主（§6.3）。
4. `ProtocolPkgs`（layering.go:71）——协议词汇触达 allowlist（当前仅 `trojan`），防协议泄漏。

「把新包加进仓库」这个动作本身就让 `TestDependencyDirection` 失败——归类决策无法被遗忘（layering.go:19）。

### §6.2 守护测试

`internal/arch/arch_test.go:16` 四条守护：`TestDependencyDirection`（方向 + 完备性 + 属主）、`TestProtocolLeak`（协议词汇泄漏，含测试文件 import）、`TestGoModAllowlist`（go.mod 直接依赖按属主收口）、`TestExportedInterfaceInventory`（导出接口清点，§11.2）。测试从 `go list ./...` 枚举真实包集合，而不是遍历手工矩阵。

**G4（示例配置可构造守护）**：`internal/clientapp/example_configs_test.go:13` 与 `internal/serverapp/example_configs_test.go:14`——遍历 `configs/` 与 `configs/local/` 的示例 YAML（命名约定 `*server*` 归 serverapp），`config.Parse(data, KnownProtocols) + Build` 必须全部成功，防「示例配置与代码漂移」（协议 params 严格解码、信封校验、缺省值文档任何一侧漂移即失败）。

### §6.3 第三方依赖属主

`arch_test.go:98`：go.mod 直接 require ⊆ `ExternalDeps` 键集。当前属主：`gopkg.in/yaml.v3 → config`、`github.com/prometheus/client_golang → metrics`（layering.go:62）。新增第三方依赖必须先登记属主 = 一次显式决策（防依赖蔓延）。

## §7 配置

### §7 严格 YAML（L4：internal/config）

`internal/config/config.go:1`。`Parse` 用 `dec.KnownFields(true)`——未知字段直接导致启动失败（config.go:538），避免拼写错误被静默忽略；改配置结构必须同步更新全部示例（G4 守护）与 Wiki 配置参考。

schema 形状镜像运行时名词：入站与出口节点都是**带判别字段的列表**，config 只认识「信封」（类型、监听、认证、名字、权重），协议专属参数与校验归协议所有（config.go:4）。已知协议集由组装根传入 `ProtocolSet`（config.go:494：Inbounds / Outbound 两个 allowlist，空 = 该组装根没有出站侧，配置中出现对应段即报错）。数值缺省全部引用 `internal/defaults`（§5.2），「两份默认值 + 防漂移测试」的变体不再需要。

### §7.1 配置 schema：信封与判别字段

顶层段（config.go:480 起）：`api`（运维端点）、`inbounds`（入站端点列表，判别字段 `type`）、`outbound`（出口侧，client 专属）、`routing`（分流配置，client 专属）、`limits`（进程级过载保护）、`timeouts`（各类超时）。server schema 无 outbound / routing 段——组装根传入的 `ProtocolSet` 在解析期拒绝它们（§7.3）。

`Duration` 是支持 YAML 时长写法的 `time.Duration`：Go 时长语法（"10s"、"1m30s"），纯数字按秒解释（config.go:28）。各段缺省值经 `Effective*` getter 解析并钳制（如 `poolCfg.EffectiveFailoverBudget()`），组装根不做二次钳制（`session/session.go:53` 的 Options 语义同理）。

### §7.2 缺省值单点（internal/defaults）

`internal/defaults/defaults.go:1`：收录规则是「config 文档化或跨层共享」的数值才进本包（超时、健康阈值、池上限与 TTL、排空期限、故障转移预算、并发上限、规则源刷新周期、日志与 DNS 缺省）；包内机械细节留在各自包内。config 的文档化缺省与领域包实现缺省引用同一常量——同一语义在任何入口下取值相同。

### §7.3 协议判别集与 Params 解码

组装根能分派的协议全集以 `config.ProtocolSet`（config.go:494）在解析期声明校验依据：Inbounds 列出允许的入站 type、Outbound 列出允许的出口 protocol（空 = 该组装根没有出站侧，配置中出现对应段即报错）。

协议 Params 结构体只有 struct tag，协议包零 yaml 依赖——严格解码由 `config.DecodeParams`（config.go:556）完成，协议专属校验在传输/服务端构造器（`internal/trojan/params.go:1`）。当前 Params 形状：客户端 `trojan.Params`（addr / password / sni / ca-file / insecure-skip-verify，params.go:8）与服务端 `trojan.ServerParams`（cert-file / key-file / decoy-file / users，params.go:28）；服务端凭据只保留 SHA-224 摘要（params.go:26，auth.Store 构造时派生）。`insecure-skip-verify` 仅允许环回地址，远程节点 fail-closed（`clientapp/app.go:229`）。

### §7.4 两个分派点（全仓唯一）

协议分派只有两个位置，switch 就是注册表——静态、可 grep、类型安全、fail-fast（`clientapp/app.go:4`）：

1. **出口协议分派** `buildTransport`（clientapp/app.go:192）：按 `n.Protocol` 分派（trojan → `DecodeParams` → `trojan.NewTransport`，协议校验在构造器）。
2. **入站协议分派** `buildInbound`：client 按 type 分派 http / socks5 / dns；server 只有入站一个分派位置（trojan → `DecodeParams`，证书/凭据/伪装页在组装根封闭，`serverapp/app.go:6`）。

## §8 组装根与工程纪律

### §8 组装根

组装根是唯一知道「全部零件」的地方：解析配置 → 构建不可变运行时快照（含监听绑定）→ 原子切换 → 旧快照排空（`clientapp/app.go:1`、`serverapp/app.go:1`）。L4 组装根是唯一可 import config / metrics / status 的包（§5.1）。

### §8.1 组装根清单

- **clientapp**（`internal/clientapp/app.go:1`）：`KnownProtocols = {Inbounds: http/socks5/dns, Outbound: trojan}`（app.go:52）。构建依赖经 `BuildOptions`（app.go:59，G4 与直接构造场景使用），出站构建 `buildOutbound`（app.go:517）。
- **serverapp**（`internal/serverapp/app.go:1`）：`KnownProtocols = {Inbounds: trojan}`，无出站侧；「入站（trojan 隧道接受器）+ 直连出站」是 client 模型的特化（app.go:5）。
- 两者共用 L1 的 `internal/lifecycle`（泛型生命周期核心，§8.2）与 `internal/status`（运维端点宿主）；差异只在快照形状与分派表（§7.4）。

### §8.2 热加载：不可变快照 + 原子切换

- **快照形状**：`clientapp.Runtime`（`internal/clientapp/runtime.go:25`）是一次配置构建的全部产物，构造后不可变；导出字段 `Inbounds / Outbound / Telemetry / Admin`，未导出字段是快照携带的组装产物（pool、providers、DNS 参数等，runtime.go:38）。监听绑定属于构建步骤（不变量 3，附录 A）。serverapp 采用同样模式（`serverapp/app.go:1`）。
- **重载流水线**（`internal/lifecycle/lifecycle.go:1`，组装根共有 L1 核心，泛型不感知应用类型）：构建快照 → 绑定监听 → 原子切换 → 旧快照排空。`switchTo` 三阶段：停旧（取消旧代际 ctx → 关旧监听）→ 绑新（失败回滚：关新监听 → CloseOwned → restore）→ 提交（live.Store → 上线新代际 → 最后释放被替换资源）。restore 走 `Clone` 浅拷贝上线恢复代际；restore 也失败则 fail-closed。
- **重载语义表**（clientapp/app.go:9）：快照重建是默认路径——任何字段改动都在新快照中生效（「需重启字段」分类不存在）；规则表与日志级别走运行期热更；**上游栈指纹未变时复用节点池/预热池实例**（预热连接与冷却/摘除状态保留），指纹变化时重建即状态重置（clientapp/app.go:517）。关停期拒绝重载；重载失败旧配置仍在原端口继续服务；每次尝试恰好记账一次 `config_reloads_total`（app.go:1028）。
- **生效边界 = 新拨号**：`live` 是组装根持有的全局 `atomic.Pointer[Runtime]`，切换对新拨号立即生效，包括被替换世代在途请求的后续拨号（app.go:1032）。
- **热加载视图**：单个 `liveView` 适配器（app.go:687）同时满足 httpproxy / socks5 / dnsgw 三者的 `LivePolicy` 接口（方法集为并集，返回类型锚定 core 契约），auth 锚定构建该入站时的凭据（生效边界 = 新连接）；新增可热加载字段只需改这一处，消费方接口漂移由文件底部编译期断言拦截。serverapp 用 `trojan.LivePolicy` 同理。
- **SIGHUP**：`cmd/client/main.go:73` 与 `cmd/server/main.go:67` 监听 SIGHUP 触发 `ReloadFile`；URL 规则源在 SIGHUP 时立即重检（`clientapp/rules_remote_test.go:201`）。
- **运维端点宿主**：`Runtime.Admin` 是 `status.Server`（`internal/status/status.go:219`）——`/metrics /health /stats /log/level` 共用 api.listen 监听，metrics 与 log/level 处理器由组装根注入（本包不 import metrics）。

### §8.4 测试纪律

- **事件归属组件领域**：各组件测试直接断言事件序列，不靠 e2e `/metrics` 文本兜底（`internal/nodes/observability_test.go:46`、`internal/dnsgw/dnsgw_test.go:466`）。做法是记录器假件（`Nop*` 的对应物，如 `testutil/conformance.go:595` 的 `telemetryRecorder`）+ 事件序列断言，组件层可见（dnsgw_test.go:493）。
- **测试分层**：`internal/clientapp/e2e_test.go` 回环端到端；`test/integration/` 黑盒集成与混沌（构建并启动真实二进制）；`internal/arch` 依赖守护（§6.2）；套件级一致性见 §9.2 / §4.2。

## §9 测试与验收

### §9.1 测试分层

单元（组件 + 记录器假件）→ 一致性套件（§9.2 入站 / §4.2 出站）→ 回环 e2e（clientapp）→ 黑盒集成与混沌（test/integration，真实二进制）→ 依赖守护（arch）。全部离线（回环，不依赖外部网络）。

### §9.2 入站一致性不变量 C1–C10

`internal/testutil/conformance.go:1`：入站的协议方言无法统一（HTTP 407 与 SOCKS5 拒绝码天然不同），但契约断言可以统一——套件接收各协议外部测试提供的 `InboundFixture`（套件注入面：Tel 记录器假件、Dial 假出站、ConnLimit 闸，conformance.go:43），在回环夹具上对被测入站逐条断言（conformance.go:91，检查函数即 `check*`）：

| # | 不变量 | 语义 |
| --- | --- | --- |
| C1 | 双向转发 | 会话能双向转发字节（半关闭、收尾正确） |
| C2 | 认证失败 | 协议合法拒绝响应 + 零拨号 + 遥测 `ConnRejected(denied)` |
| C3 | 拨号失败 | 明确失败响应 + 遥测 `ConnDone(result=dial_fail)` |
| C4 | 权威路径 | 成功会话遥测 `result=ok` 且 Route 与 `DialTarget` 返回的权威路径一致（不变量 6） |
| C5 | 优雅排空 | 关停时存量会话在排空期内正常完成（不被打断） |
| C6 | 强制断开 | 排空期限到点后阻塞连接被强制断开，且仍发 `ConnDone` |
| C7 | 关停拒绝 | 关停后不再接受新连接 |
| C8 | 过载拒绝 | 超过并发上限按协议回过载拒绝，遥测 `ConnRejected(overloaded)` |
| C9 | 空闲回收 | 空闲超过期限的会话被回收 |
| C10 | 预读转发 | 握手期预读的字节被原样前置转交 |

套件自身的负例测试（`testutil/conformance_test.go:3`）故意写坏入站实现，必须被拦截——套件才可信（与 §4.2 `RunConformance` 同一模式）。各协议接线见 §12。

## §10 可观测性

- **遥测事件归属组件领域**：`core.Telemetry`（§4.1）覆盖入站连接终态——`ConnDone` 产 requests_total / request_duration_seconds，`ConnOpened` 与（`ConnDone`|`ConnRejected`）之差产 active_connections，`ConnRejected` 产 connections_rejected_total（core.go:144）；组件自有窄接口 `dnsgw.DNSObserver`（dnsgw.go:89，查询结果）、`nodes.Observer`（pool.go:30，探测结果与健康变化）、`connpool.Observer`、`ruleset.Observer`，缺省 `Nop*` 实现，测试零构造。
- **metrics（L4 单点）**：`internal/metrics/metrics.go:57` 统一适配为 Prometheus；组件只发事件，Prometheus 编码归 metrics。L4 以下禁止 import metrics（§5.1 arch 守护强制）。
- **运维端点**：`status.Server`（§8.2）承载 `/metrics /health /stats /log/level`，共用 api.listen 监听（不单独配端口）；`/health` 依赖检查任一失败返回 503（status.go:20）；`/log/level` 运行时切级且保持环回专属；api 监听非环回时组装根告警（`clientapp/app.go:186`）。
- **日志**：slog JSON（L0 `logging`），request_id 关联一条连接；`-log-level` 启动参数显式覆盖文件值（app.go:963）。

## §11 工程量化与演进

### §11.1 覆盖率与门槛

`make cover` 输出总覆盖率；`make lint`（golangci-lint v2）与 `make test`（含 arch 守护）是提交门槛（CONTRIBUTING.md）。

### §11.2 导出接口面量化

`arch_test.go:113`：量化承诺为「全仓导出接口 ≤ 15 个」，现状 20 个（§4.4 契约表 + 各组件 Observer/LivePolicy 消费方锚点 + 入站一致性套件的 `testutil.Inbound` 夹具锚点，逐个有存在理由）。`TestExportedInterfaceInventory`（arch_test.go:145）钉住精确集合：新增或删除接口都必须显式修改清单——接口面在收敛回 ≤15 之前不允许静默生长。

## §12 术语与协议接入参考

**术语**：组装根（§8）、快照（§8.2）、直连剪枝（§5.3 `dialer.Direct`）、预热（§4.2 Prewarmer / §5.3 connpool）、冷却/摘除（§5.3 nodes.Pool）、权威路径（§4.1 Route / 不变量 6）、信封与 Params（§7 / §7.3）。

**新增协议接入清单**（与 §12 的「某入站走 C1–C10」引用对应）：

- 入站协议：实现 `session.ConnHandler`（§4.3）→ 在外部测试包提供 `InboundFixture`（协议客户端驱动，接线与组装根一致：connlimit 过载闸 + 拒绝遥测）→ 调 `testutil.RunInboundConformance` 跑 C1–C10。现有点位：SOCKS5（`internal/socks5/conformance_test.go:3`）、HTTP/HTTPS（`internal/httpproxy/conformance_test.go:3`）。
- 出口协议：实现 `outbound.Transport`（必备）与可选 `Prewarmer` / `Prober`（§4.2）→ 调 `outbound.RunConformance` → 在 §7.4 两个分派点各加一个 case、在 `config.ProtocolSet`（§7）登记判别值、在 `ProtocolPkgs`（§6.1）登记 allowlist。
- 协议词汇常量（`core.Proto*`）随新协议扩充，metrics 预初始化、套件断言、日志口径读同一常量（core.go:94）。

---

## 附录 A：编号不变量（代码注释实际引用者）

| # | 不变量 | 锚点 |
| --- | --- | --- |
| 不变量 3 | 构建失败零残留：监听绑定失败（或任何构建/绑定失败）必须关闭本次已打开的一切并返回错误，旧运行时零影响 | `clientapp/runtime.go:4`、`runtime.go:137`（closeOwned）、`status/status.go:240` |
| 不变量 6 | 权威路径：`Route` 是一次连接实际走过的路径的权威值，入站拿 `DialTarget` 返回值填日志与遥测，不得自行推断上游 | `core/core.go:67`、`dialer/dialer.go:5`、C4（§9.2） |

## 附录 B：C1–C10 对照表

见 §9.2 表格；实现为 `internal/testutil/conformance.go` 的 `checks` 表（conformance.go:117）驱动的 `checkRelay` … `checkPreloadedForwarding` 十个检查函数，每条一个子测试、入站按子测试重新构造。

## 附录 C：G4（示例配置可构造）

G4 是 §6.2 守护族中的示例守护：`configs/example-client.yaml`、`configs/example-server.yaml`、`configs/local/` 全部示例必须能被对应组装根 `Parse + Build` 成功（client 侧 `clientapp/example_configs_test.go:13`，server 侧 `serverapp/example_configs_test.go:14`；`example-rules.yaml` 是规则文档而非应用配置）。它同时钉住：严格 YAML 字段名、`ProtocolSet` 判别值、`DecodeParams` 协议参数、`defaults` 缺省值文档四者与代码不漂移。

## 文档维护约定

- 本文档与代码同向演化：改变 §X 所述语义的代码变更应同步更新对应小节及其坐标；守护测试（§6.2）与一致性套件（§9.2、§4.2）是文档断言的机械形态。
- 章节号是代码注释的公共锚点，**不得重编号**——废弃小节保留标题并标注去向，新增小节用未占用的号段。
- 行为语义的运维视角（配置字段、指标全表、部署）在 Wiki 深度文档；本文档只锚定设计事实与代码坐标。
