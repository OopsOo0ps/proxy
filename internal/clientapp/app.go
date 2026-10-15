// Package clientapp 组装 proxy-client（设计文档 §8 组装根）：解析配置 →
// 构建不可变运行时快照（含监听绑定）→ 原子切换 → 旧快照排空。
//
// 协议分派只有两个位置（全仓唯一，§7.4）：buildTransport 按出口协议
// protocol 分派（trojan → DecodeParams → trojan.NewTransport，协议校验在
// 构造器），buildInbound 按入站 type 分派（http / socks5 / dns）。switch
// 就是注册表：静态、可 grep、类型安全、fail-fast。
//
// 热加载语义（§8.2 重载语义表）：快照重建是默认路径——任何字段改动都会在
// 新快照中生效（"需重启字段"分类不存在）；规则表与日志级别走运行期热更；
// 上游栈（节点 + params + 池 + 超时）指纹未变时复用节点池 / 预热池实例。
// 关停期拒绝重载；重载失败时旧配置仍在原端口继续服务（同端口重绑冲突的
// 处置见 internal/lifecycle 的 switchTo）。
//
// 代码按职责拆分为同包多文件（assemble / dispatch / inbounds / outbound /
// dns / liveview / observers 等）；本文件保留包文档、构建依赖与 App 生命周期。
package clientapp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/connlimit"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/defaults"
	"github.com/OopsOo0ps/proxy/internal/dialer"
	"github.com/OopsOo0ps/proxy/internal/dnsgw"
	"github.com/OopsOo0ps/proxy/internal/httpproxy"
	"github.com/OopsOo0ps/proxy/internal/lifecycle"
	"github.com/OopsOo0ps/proxy/internal/logging"
	"github.com/OopsOo0ps/proxy/internal/metrics"
	"github.com/OopsOo0ps/proxy/internal/nodes"
	"github.com/OopsOo0ps/proxy/internal/outbound"
	"github.com/OopsOo0ps/proxy/internal/routing"
	"github.com/OopsOo0ps/proxy/internal/ruleset"
	"github.com/OopsOo0ps/proxy/internal/socks5"
	"github.com/OopsOo0ps/proxy/internal/status"
	"github.com/OopsOo0ps/proxy/internal/version"
)

// KnownProtocols 是本组装根能分派的协议全集（config 解析期校验依据）：
// 入站 http / socks5 / dns，出口 trojan。
var KnownProtocols = config.ProtocolSet{
	Inbounds: []string{config.TypeHTTP, config.TypeSOCKS5, config.TypeDNS},
	Outbound: []string{config.ProtocolTrojan},
}

// —— 构建依赖 ——

// BuildOptions 是包级 Build 的组装依赖（G4 示例配置守护测试与直接构造
// 场景使用；常驻服务经 New 构造）。
type BuildOptions struct {
	// Logger 记录构建期告警与请求日志；nil 时静默。
	Logger *slog.Logger
	// Metrics 是遥测与观察者出口；nil 时使用禁用集合的空指标。
	Metrics *metrics.Metrics
	// Limiter 是进程级并发闸；nil 时不限流。
	Limiter *connlimit.Limiter
	// Version 出现在 /stats。
	Version string
	// LogCtrl 是运行时可调日志控制器；nil 时 /log/level 端点不可用。
	LogCtrl *logging.Control
	// OnRulesChange 在规则表变化后被调用（丢弃转发路径空闲连接）；可 nil。
	OnRulesChange func()
}

// builder 承载一次组装的全部依赖；App 持有同一 builder 覆盖完整生命周期。
type builder struct {
	logger        *slog.Logger
	metrics       *metrics.Metrics
	limiter       *connlimit.Limiter
	dnsLimiter    *connlimit.Limiter
	version       string
	start         time.Time
	logCtrl       *logging.Control
	onRulesChange func()
	live          *atomic.Pointer[Runtime]
}

func newBuilder(opts BuildOptions, live *atomic.Pointer[Runtime]) builder {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	m := opts.Metrics
	if m == nil {
		m = metrics.New(nil)
	}
	return builder{
		logger:  logger,
		metrics: m,
		limiter: opts.Limiter,
		// DNS 用独立于进程全局闸的专用查询闸（上限与全局闸同源复用
		// limits.max-connections，不新增配置字段）：UDP 在途查询不是连接，
		// 不适合计入全局连接闸；且 DNS 洪水不应级联拒掉 HTTP/SOCKS5 的
		// 新连接。UDP 与 TCP 双栈共用这一份预算。
		dnsLimiter:    connlimit.New(opts.Limiter.Max()),
		version:       opts.Version,
		start:         time.Now(),
		logCtrl:       opts.LogCtrl,
		onRulesChange: opts.OnRulesChange,
		live:          live,
	}
}

// —— 分流与出站 ——

// buildRouting 构建分流判定组合表：内联静态规则 + 规则源 Provider（至多
// 一个，schema 层已校验）按声明顺序匹配；私网直连是前置硬规则；缺省动作 =
// 规则源文档 default > 内联 default > proxy（与既有语义一致：规则文档的
// default 覆盖配置缺省）。reuse 非 nil 时按规则源 Spec 复用 Provider 并立即
// 重检（本地文件严格重读、远程 URL 容错重拉）。
func (b *builder) buildRouting(cfg *config.Config, reuse *Runtime) (*routeTable, []*ruleset.Provider, error) {
	privateDirect := cfg.Routing.EffectivePrivateDirect()

	var static *routing.Engine
	if cfg.Routing != nil && len(cfg.Routing.Rules) > 0 {
		engineRules := &routing.Rules{}
		for _, r := range cfg.Routing.Rules {
			if r.Default != nil {
				engineRules.Default = r.Default
				continue
			}
			rr, err := r.RoutingRule()
			if err != nil {
				return nil, nil, err
			}
			engineRules.Rules = append(engineRules.Rules, rr)
		}
		engine, err := routing.NewEngine(engineRules, routing.Options{PrivateDirect: false})
		if err != nil {
			return nil, nil, fmt.Errorf("routing.rules: %w", err)
		}
		static = engine
	}

	var providers []*ruleset.Provider
	if cfg.Routing != nil && len(cfg.Routing.Rulesets) == 1 {
		rs := cfg.Routing.Rulesets[0]
		spec := rulesetSpecOf(&rs)
		var (
			prov *ruleset.Provider
			err  error
		)
		if reuse != nil && len(reuse.providers) == 1 && reuse.providers[0].Spec() == spec {
			prov = reuse.providers[0]
			if err := prov.Recheck(context.Background()); err != nil {
				return nil, nil, err
			}
		} else {
			file, url, sha256, interval := rulesetSourceOf(&rs)
			prov, err = ruleset.New(ruleset.Options{
				FilePath:        file,
				URL:             url,
				ExpectedSHA256:  sha256,
				RefreshInterval: interval,
				Parse:           config.ParseRules,
				Default:         inlineDefault(cfg.Routing),
				PrivateDirect:   privateDirect,
				Logger:          b.logger,
				Observer:        b.metrics,
				OnChange:        b.onRulesChange,
			})
			if err != nil {
				return nil, nil, err
			}
		}
		providers = append(providers, prov)
	}

	// 缺省动作：规则源文档 default > 内联 default > proxy。
	def := inlineDefault(cfg.Routing)
	for _, p := range providers {
		if d, ok := p.DocDefault(); ok {
			def = d
			break
		}
	}
	return &routeTable{privateDirect: privateDirect, static: static, providers: providers, def: def}, providers, nil
}

// inlineDefault 返回内联规则指定的缺省动作；未指定时 proxy（缺省动作与
// 未配置 routing 段的运行语义同源）。
func inlineDefault(r *config.Routing) core.RouteAction {
	if r != nil {
		for i := range r.Rules {
			if d := r.Rules[i].Default; d != nil {
				return *d
			}
		}
	}
	return core.RouteProxy
}

// rulesetSpecOf 把规则源配置映射为 ruleset 的 Spec（复用判定依据）。
func rulesetSpecOf(rs *config.Ruleset) ruleset.Spec {
	file, url, sha256, interval := rulesetSourceOf(rs)
	return ruleset.SpecOf(file, url, sha256, interval)
}

// rulesetSourceOf 把规则源配置映射为 ruleset 的来源参数。
func rulesetSourceOf(rs *config.Ruleset) (file, url, sha256 string, interval time.Duration) {
	if rs.Type == "file" {
		return rs.Path, "", "", 0
	}
	return "", rs.URL, rs.SHA256, rs.EffectiveInterval()
}

// buildOutbound 构建出口链路（节点池 + 预热池）；未配置节点时保持 nil
// （仅直连）。reuse 非 nil 且上游栈指纹未变时复用现有实例（预热连接与
// 冷却 / 摘除状态保留）；指纹变化时重建（状态重置语义，§8.2 显式成文）。
func (b *builder) buildOutbound(cfg *config.Config, reuse *Runtime, rt *Runtime) error {
	if cfg.Outbound == nil || len(cfg.Outbound.Nodes) == 0 {
		return nil
	}
	if reuse != nil && reuse.pool != nil {
		changed, err := upstreamStackChanged(reuse.cfg, cfg)
		if err != nil {
			b.logger.Warn("upstream fingerprint failed; rebuilding pools", "error", err)
		} else if !changed {
			rt.pool = reuse.pool
			return nil
		}
	}

	// 配置模型 → 节点运行时模型（nodes 包不反向依赖 config）。
	// 每节点一个传输实例：协议参数（地址、口令、TLS/SNI、超时）经
	// buildTransport 在协议构造器封闭，SHA-224 口令派生等线格式细节不出
	// 协议包；节点池只携带地址、调度权重与传输能力（nodes 彻底协议无关）。
	nodeCfgs := make([]nodes.Node, 0, len(cfg.Outbound.Nodes))
	for i := range cfg.Outbound.Nodes {
		n := cfg.Outbound.Nodes[i]
		tr, addr, err := buildTransport(n, cfg.Timeouts.EffectiveDial(), cfg.Timeouts.EffectiveHandshake())
		if err != nil {
			return fmt.Errorf("outbound.nodes[%d]: %w", i, err)
		}
		nodeCfgs = append(nodeCfgs, nodes.Node{Addr: addr, Transport: tr, Weight: n.Weight})
	}

	// 节点池拨号回退路径：预热领取未命中时走节点自身传输（预热池由
	// nodes.Pool 自持，§5.3 组合树：NodePool → 每节点 PrewarmPool）。
	poolCfg := cfg.Outbound.Pool
	health := poolCfg.Health
	opts := nodes.Options{
		Logger:   b.logger,
		Observer: b.metrics,
		// 故障转移总预算：整条候选节点的等待上限（缺省 defaults.FailoverBudget）。
		FailoverBudget: poolCfg.EffectiveFailoverBudget(),
		// 预热池参数与观测出口：连接池实例由节点池按 Prewarmer 能力自建，
		// 组装根只注入配置（config 是预热参数的唯一入口）。
		Prewarm:         nodes.PrewarmOptions{Size: poolCfg.Prewarm.EffectiveSize(), TTL: poolCfg.Prewarm.EffectiveTTL()},
		PrewarmObserver: b.metrics,
		Health: nodes.HealthOptions{
			Interval:  health.EffectiveInterval(),
			Timeout:   health.EffectiveTimeout(),
			Failures:  health.EffectiveFailures(),
			Successes: health.EffectiveSuccesses(),
		},
	}
	if opts.Health.Interval > 0 {
		// 主动探测经 Prober 能力（传输构造时已含超时参数，期限由探测循环
		// 按 Health.Timeout 收敛）；未声明探测能力的传输不做主动探测判定
		//（恒成功），健康性交由被动冷却评估。
		opts.Probe = func(ctx context.Context, node nodes.Node) error {
			prober, ok := node.Transport.(outbound.Prober)
			if !ok {
				return nil
			}
			return prober.Probe(ctx)
		}
	}
	pool, err := nodes.New(nodeCfgs, nil, opts)
	if err != nil {
		return err
	}
	rt.pool = pool
	return nil
}

// upstreamStackChanged 判断两份配置的出口链路栈是否相同：相同 ⇒ 复用现有
// 节点池与预热池；不同 ⇒ 重建。比较依据是 config.UpstreamFingerprint
// （整份子结构的哈希），不做逐字段手工列举——新增上游相关字段时指纹自动变化。
func upstreamStackChanged(oldCfg, newCfg *config.Config) (bool, error) {
	oldFP, err := config.UpstreamFingerprint(oldCfg)
	if err != nil {
		return false, err
	}
	newFP, err := config.UpstreamFingerprint(newCfg)
	if err != nil {
		return false, err
	}
	return oldFP != newFP, nil
}

// —— DNS 网关的动态参数与剪枝 ——

func dnsGatewayListen(cfg *config.Config) string {
	for i := range cfg.Inbounds {
		if cfg.Inbounds[i].Type == config.TypeDNS {
			return cfg.Inbounds[i].Listen
		}
	}
	return ""
}

func effectiveDNSRemote(r *config.Routing) string {
	if r == nil || r.DNS == nil {
		return defaults.DNSRemote
	}
	return r.DNS.EffectiveRemote()
}

func effectiveDNSTimeout(r *config.Routing) time.Duration {
	if r == nil || r.DNS == nil {
		return defaults.DNSTimeout
	}
	return r.DNS.EffectiveTimeout()
}

// resolveDNSLocal 返回生效的直连解析器列表；未显式配置时读取系统
// resolv.conf（读取失败或无可用条目时告警并保持为空，与既有启动行为一致）。
func (b *builder) resolveDNSLocal(r *config.Routing, dnsListen string) []string {
	if r != nil && r.DNS != nil && len(r.DNS.Local) > 0 {
		return append([]string(nil), r.DNS.Local...)
	}
	path := dnsgw.DefaultResolvConfPath
	resolved, err := dnsgw.LocalResolversFromResolvConf(path, dnsListen)
	switch {
	case err != nil:
		b.logger.Warn("dns gateway: cannot read system resolvers, direct-routed names will fail",
			"path", path, "error", err)
		return nil
	case len(resolved) == 0:
		b.logger.Warn("dns gateway: no usable system resolvers found, direct-routed names will fail",
			"path", path, "hint", "set routing.dns.local explicitly")
		return nil
	default:
		b.logger.Info("dns gateway: using system resolvers for direct-routed names",
			"path", path, "resolvers", resolved)
		return resolved
	}
}

// dnsRouter 把当前快照的分流表适配为 dnsgw 的查询判定（DNS 走哪条路 =
// 流量走哪条路）：core.Target 承载查询名（Port 无语义）。
type dnsRouter struct{ live *atomic.Pointer[Runtime] }

func (r dnsRouter) Decide(t core.Target) core.Route {
	rt := r.live.Load()
	if rt == nil || rt.table == nil {
		return core.Route{Action: core.RouteProxy}
	}
	return core.Route{Action: rt.table.Decide(t.Host)}
}

// dnsDirectDialer 是 DNS 网关的直连剪枝（本地解析路径）：对本地解析器的
// UDP 拨号，超时跟随当前快照。
type dnsDirectDialer struct{ live *atomic.Pointer[Runtime] }

func (d dnsDirectDialer) DialTarget(ctx context.Context, t core.Target) (net.Conn, core.Route, error) {
	timeout := defaults.DNSTimeout
	if rt := d.live.Load(); rt != nil && rt.dnsTimeout > 0 {
		timeout = rt.dnsTimeout
	}
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "udp", t.String())
	return conn, core.Route{Action: core.RouteDirect}, err
}

// dnsTunnelDialer 是 DNS 网关的代理剪枝（远端解析路径）：不经分流，一律经
// 当前快照的出口节点池（同一棵组合树的池子树，返回权威路径 Route{Proxy}）。
type dnsTunnelDialer struct{ live *atomic.Pointer[Runtime] }

func (d dnsTunnelDialer) DialTarget(ctx context.Context, t core.Target) (net.Conn, core.Route, error) {
	rt := d.live.Load()
	if rt == nil || rt.pool == nil {
		return nil, core.Route{Action: core.RouteProxy, Label: "pool"}, dialer.ErrNoNodes
	}
	return rt.pool.DialTarget(ctx, t)
}

// —— 热加载视图（运行期热更路径，§8.2）——

// liveView 是入站的热加载视图：dialer、超时与 DNS 参数读当前快照；
// auth 锚定构建该入站时的凭据（生效边界 = 新连接）。单个适配器同时满足
// httpproxy / socks5 / dnsgw 三份消费方接口（方法集是三者的并集；返回类型
// 锚定 core 契约），新增热加载项只需维护这一处；任意消费方接口增删方法
// 都会让文件底部编译期断言失败，不会静默失配。
type liveView struct {
	live *atomic.Pointer[Runtime]
	auth *auth.Store // nil = 不校验
}

func (l liveView) current() *Runtime { return l.live.Load() }

// Auth 返回当前凭据校验能力；未配置认证时必须返回真正的 nil 接口——
// 消费方以接口 == nil 判定“不校验”，nil *Store 装进接口会被误判为启用。
func (l liveView) Auth() core.Authenticator {
	if l.auth == nil {
		return nil
	}
	return l.auth
}

func (l liveView) Dialer() core.TargetDialer {
	if rt := l.current(); rt != nil {
		return rt.Outbound
	}
	return nil
}

func (l liveView) IdleTimeout() time.Duration {
	if rt := l.current(); rt != nil {
		return rt.cfg.Timeouts.EffectiveIdle()
	}
	return defaults.IdleTimeout
}

func (l liveView) ReadHeaderTimeout() time.Duration {
	if rt := l.current(); rt != nil {
		return rt.cfg.Timeouts.EffectiveHandshake()
	}
	return defaults.HandshakeTimeout
}

func (l liveView) HandshakeTimeout() time.Duration {
	if rt := l.current(); rt != nil {
		return rt.cfg.Timeouts.EffectiveHandshake()
	}
	return defaults.HandshakeTimeout
}

func (l liveView) ShutdownTimeout() time.Duration {
	if rt := l.current(); rt != nil {
		return rt.cfg.Timeouts.EffectiveShutdown()
	}
	return defaults.DrainTimeout
}

// Router 把当前快照的分流表适配为 dnsgw 的查询判定。
func (l liveView) Router() dnsgw.RouteDecider { return dnsRouter{live: l.live} }

func (l liveView) Remote() string {
	if rt := l.current(); rt != nil {
		return rt.dnsRemote
	}
	return defaults.DNSRemote
}

func (l liveView) Local() []string {
	if rt := l.current(); rt != nil {
		return rt.dnsLocal
	}
	return nil
}

func (l liveView) Timeout() time.Duration {
	if rt := l.current(); rt != nil {
		return rt.dnsTimeout
	}
	return defaults.DNSTimeout
}

// 编译期断言：消费方接口与适配器失配（增删方法）会直接编译失败。
var (
	_ httpproxy.LivePolicy = liveView{}
	_ socks5.LivePolicy    = liveView{}
	_ dnsgw.LivePolicy     = liveView{}
)

// —— 可观测性接缝（/stats 与依赖健康）——

func (b *builder) logLevelHandler() http.Handler {
	if b.logCtrl == nil {
		return nil
	}
	return logging.LevelHandler(b.logger, b.logCtrl.LevelVar())
}

// healthChecks 返回依赖健康检查：配置了出口节点时，池中无健康节点视为
// 依赖不可用。
func (b *builder) healthChecks() []func() error {
	return []func() error{func() error {
		rt := b.live.Load()
		if rt == nil || rt.pool == nil {
			return nil
		}
		if rt.pool.AnyHealthy() {
			return nil
		}
		return errors.New("no healthy exit nodes available")
	}}
}

// runtimeStats 组装 /stats 快照：活跃连接数与出口节点状态。
func (b *builder) runtimeStats() status.Runtime {
	rt := b.live.Load()
	var out status.Runtime
	if rt == nil {
		return out
	}
	active := b.metrics.ActiveByProto()
	httpConns := active[core.ProtoHTTP]
	socksConns := active[core.ProtoSOCKS5]
	out = status.Runtime{
		Connections: status.Connections{
			HTTP:   httpConns,
			SOCKS5: socksConns,
			Total:  httpConns + socksConns,
		},
	}
	if rt.pool != nil {
		idle := rt.pool.IdleCounts()
		for _, n := range rt.pool.Snapshot() {
			out.Upstreams = append(out.Upstreams, status.Upstream{
				Addr:              n.Addr,
				Healthy:           n.Healthy,
				Fails:             n.Fails,
				CooldownRemaining: status.Seconds(n.CooldownRemaining),
				Removed:           n.Removed,
				ProbeFails:        n.ProbeFails,
				Idle:              idle[n.Addr],
			})
		}
	}
	if len(rt.providers) > 0 {
		if snap := rt.providers[0].Snapshot(); snap.Source != ruleset.SourceNone {
			out.Ruleset = &status.Ruleset{
				Source:    snap.Source.String(),
				Target:    snap.Target,
				Refresh:   status.Seconds(snap.Interval),
				Loaded:    snap.Loaded,
				Rules:     snap.Rules,
				LastError: snap.LastError,
			}
			if !snap.LastSuccess.IsZero() {
				out.Ruleset.LastSuccess = snap.LastSuccess.UTC().Format(time.RFC3339)
			}
		}
	}
	// 0 = 不限制时不输出 limit 字段（与 README 描述一致）。
	if b.limiter != nil && b.limiter.Max() > 0 {
		out.Limit = &status.Limit{
			MaxConnections: b.limiter.Max(),
			Current:        b.limiter.Active(),
			Rejected:       b.limiter.Rejected(),
		}
	}
	return out
}

// —— App：薄包装（生命周期核心见 internal/lifecycle）——

// App 是组装完成的 proxy-client 实例。
// 生命周期：New（构建快照并绑定监听）→ Serve（阻塞服务直到 ctx 取消）。
// 配置热加载见 Reload：先完整构建新快照，全部成功后原子切换并排空旧快照；
// 任何失败都保持旧配置在原端口继续服务。顺序与关停语义（代际切换、失败
// 回滚、fail-closed、按代际计数防 Add-after-Wait）全部由 internal/lifecycle
// 核心承载；本组装根只注入应用语义（组装、绑定、服务端点、运行期热更）。
type App struct {
	core *lifecycle.App[Runtime, *config.Config]
	b    builder
	live atomic.Pointer[Runtime] // 借给核心的组装根 live 指针（生效边界 = 新拨号）
}

// New 校验并组装应用：构建完整运行时快照并绑定全部监听（不变量 3：
// 任何失败关闭已打开的一切并返回错误）。logCtrl 是运行时可调日志控制器
// （可为 nil，此时 /log/level 端点不可用）。
func New(cfg *config.Config, logger *slog.Logger, logCtrl *logging.Control) (*App, error) {
	app := &App{}
	app.b = newBuilder(BuildOptions{
		Logger:        logger,
		Metrics:       metrics.New(enabledProtos(cfg)),
		Limiter:       connlimit.New(cfg.Limits.EffectiveMaxConnections()),
		Version:       version.Get().Version,
		LogCtrl:       logCtrl,
		OnRulesChange: app.dropForwardIdleConns,
	}, &app.live)
	core, _, err := lifecycle.New(lifecycleOptions(&app.b), cfg, &app.live)
	if err != nil {
		return nil, err
	}
	app.core = core
	return app, nil
}

// lifecycleOptions 把 clientapp 的应用语义注入生命周期核心：闭包一律经
// builder 指针运行期读取（测试会在 New 后替换 logger / logCtrl，钩子不得
// 捕获构造期值）。Name 前缀 "clientapp" 逐字复现既有错误与日志文案。
func lifecycleOptions(b *builder) lifecycle.Options[Runtime, *config.Config] {
	return lifecycle.Options[Runtime, *config.Config]{
		Name:     "clientapp",
		Assemble: b.assemble,
		Load:     loadConfigFile,
		Port: lifecycle.Port[Runtime]{
			// Clone 返回浅拷贝（c := *rt; return &c）：restore 回滚路径以
			// 克隆上线，旧代际（及其服务协程闭包）仍持原指针。
			Clone: func(rt *Runtime) *Runtime {
				c := *rt
				return &c
			},
			Services:       runtimeServices,
			Bind:           b.bindRuntime,
			CloseListeners: func(rt *Runtime) { rt.closeListeners() },
			CloseOwned:     func(cur, next *Runtime) { next.closeOwned(cur) },
			ReleaseReplaced: func(cur, next *Runtime) {
				cur.releaseReplaced(next)
			},
			StartResources: func(rt *Runtime, parent context.Context) {
				rt.startResources(parent)
			},
			CloseResources: func(rt *Runtime) { rt.closeResources() },
		},
		OnReloaded: func(next *config.Config) {
			b.limiter.SetMax(next.Limits.EffectiveMaxConnections())
			// DNS 专用查询闸与全局闸同源：热加载时同步调整上限。
			b.dnsLimiter.SetMax(next.Limits.EffectiveMaxConnections())
			if b.logCtrl != nil {
				b.logCtrl.SetLevel(next.Log.Level)
				b.logCtrl.SetFormat(next.Log.Format)
			}
			b.logger.Info("configuration reloaded",
				"inbounds", len(next.Inbounds),
				"nodes", len(nodesOf(next)),
				"max_connections", next.Limits.EffectiveMaxConnections(),
				"dns_gateway", dnsGatewayListen(next) != "",
			)
		},
		OnReloadResult: func(success bool) {
			if success {
				b.metrics.ConfigReload(metrics.ReloadSuccess)
				return
			}
			b.metrics.ConfigReload(metrics.ReloadError)
		},
		OnRollbackFailed: func(err error) {
			b.logger.Error("reload rollback failed; previous listeners could not be rebound", "error", err)
		},
	}
}

// runtimeServices 把运行时快照的服务端点暴露给生命周期核心（每次代际
// 上线时读取）：入站按声明顺序，错误前缀 "clientapp: inbound %s" 的 %s
// 即入站 type；运维端点错误前缀 "clientapp: admin endpoint"。
func runtimeServices(rt *Runtime) lifecycle.Services {
	svc := lifecycle.Services{Admin: lifecycle.Service{Serve: rt.Admin.Serve}}
	for i := range rt.Inbounds {
		is := &rt.Inbounds[i]
		svc.Inbounds = append(svc.Inbounds, lifecycle.Service{
			Kind:  is.Config.Type,
			Serve: is.Serve,
		})
	}
	return svc
}

// loadConfigFile 读取并解析客户端配置（lifecycle Load 钩子）；levelOverride
// 是启动参数 -log-level 的显式覆盖，非空时优先于文件值。
func loadConfigFile(path, levelOverride string) (*config.Config, error) {
	cfg, err := config.Load(path, KnownProtocols)
	if err != nil {
		return nil, err
	}
	if levelOverride != "" {
		cfg.Log.Level = levelOverride
	}
	return cfg, nil
}

// Build 依据配置构建完整运行时快照（含监听绑定）：除绑定外无副作用；
// 任何失败关闭已打开的一切并返回错误（不变量 3）。供 G4 示例配置守护
// 测试与直接构造场景使用；常驻服务请使用 New。
func Build(cfg *config.Config, opts BuildOptions) (*Runtime, error) {
	var live atomic.Pointer[Runtime]
	b := newBuilder(opts, &live)
	return lifecycle.Build(lifecycleOptions(&b), cfg, &live)
}

// enabledProtos 返回已启用的入站协议集合（metrics 按集合预初始化时间序列）。
func enabledProtos(cfg *config.Config) []string {
	seen := map[string]bool{}
	protos := make([]string, 0, len(cfg.Inbounds))
	for i := range cfg.Inbounds {
		var proto string
		switch cfg.Inbounds[i].Type {
		case config.TypeHTTP:
			proto = core.ProtoHTTP
		case config.TypeSOCKS5:
			proto = core.ProtoSOCKS5
		case config.TypeDNS:
			proto = core.ProtoDNS
		default:
			continue
		}
		if !seen[proto] {
			seen[proto] = true
			protos = append(protos, proto)
		}
	}
	return protos
}

// nodesOf 返回出口节点列表（未配置出站侧时为 nil）。
func nodesOf(cfg *config.Config) []config.Node {
	if cfg.Outbound == nil {
		return nil
	}
	return cfg.Outbound.Nodes
}

// dropForwardIdleConns 规则变化回调：丢弃当前快照转发路径的空闲上游连接。
func (a *App) dropForwardIdleConns() {
	if rt := a.live.Load(); rt != nil {
		rt.dropForwardIdleConns()
	}
}

// Serve 阻塞服务直到 ctx 取消或任一监听出错；返回前完成优雅关停
// （存量连接按排空期限收尾）。重载产出的新代际在切换时即上线，
// 不经过本函数的再次调度。
func (a *App) Serve(ctx context.Context) error { return a.core.Serve(ctx) }

// Reload 应用一份新配置（重载流水线，§8.2）：读文件与解析在上层完成；
// 这里先完整构建新运行时（规则源重检、指纹复用、协议传输与凭据重建），
// 全部成功后原子切换（先停旧监听再绑新监听，见 internal/lifecycle 的
// switchTo），旧快照排空。任何失败都返回错误并保持旧配置在原端口继续
// 服务——配置错误不会波及线上。
//
// 生效边界为“新拨号”：a.live 是全局原子快照，切换对新拨号立即生效，包括
// 被替换世代在途请求的后续拨号；请求级快照冻结不是本模型的语义。
func (a *App) Reload(next *config.Config) error { return a.core.Reload(next) }

// ReloadFile 读取、解析并应用配置文件（path 与启动时相同）。
// levelOverride 是启动参数 -log-level 的显式覆盖，非空时同样优先于文件值。
// 解析失败与构建失败一样保持旧配置继续服务，
// 并且每次尝试（无论失败在哪一步）都恰好计入一次 config_reloads_total。
func (a *App) ReloadFile(path, levelOverride string) error {
	return a.core.ReloadFile(path, levelOverride)
}

// Serving 报告应用是否正在服务（测试接缝：代际上线 / 关停的判定点）。
func (a *App) Serving() bool { return a.core.Serving() }

// —— 观测访问器 ——

// HTTPAddr 返回首个 HTTP 入站实际监听地址（未启用时为空）。
func (a *App) HTTPAddr() string { return a.inboundAddr(config.TypeHTTP) }

// SOCKS5Addr 返回首个 SOCKS5 入站实际监听地址（未启用时为空）。
func (a *App) SOCKS5Addr() string { return a.inboundAddr(config.TypeSOCKS5) }

// DNSAddr 返回首个 DNS 网关入站实际监听地址（未启用时为空）。
func (a *App) DNSAddr() string { return a.inboundAddr(config.TypeDNS) }

func (a *App) inboundAddr(t string) string {
	if rt := a.live.Load(); rt != nil {
		for i := range rt.Inbounds {
			if rt.Inbounds[i].Config.Type == t {
				return rt.Inbounds[i].Addr()
			}
		}
	}
	return ""
}

// MetricsAddr 返回运维端点实际监听地址（未启用时为空）。
func (a *App) MetricsAddr() string {
	if rt := a.live.Load(); rt != nil {
		return rt.Admin.Addr()
	}
	return ""
}
