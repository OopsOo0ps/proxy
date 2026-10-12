// Package clientapp 组装 proxy-client：入站监听、分流决策、出口节点池与指标端点。
package clientapp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/connlimit"
	"github.com/OopsOo0ps/proxy/internal/connpool"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/dialer"
	"github.com/OopsOo0ps/proxy/internal/dnsgw"
	"github.com/OopsOo0ps/proxy/internal/httpproxy"
	"github.com/OopsOo0ps/proxy/internal/logging"
	"github.com/OopsOo0ps/proxy/internal/metrics"
	"github.com/OopsOo0ps/proxy/internal/nodes"
	"github.com/OopsOo0ps/proxy/internal/routing"
	"github.com/OopsOo0ps/proxy/internal/ruleset"
	"github.com/OopsOo0ps/proxy/internal/socks5"
	"github.com/OopsOo0ps/proxy/internal/status"
	"github.com/OopsOo0ps/proxy/internal/trojan"
	"github.com/OopsOo0ps/proxy/pkg/version"
)

// App 是组装完成的 proxy-client 实例。
// 生命周期：New → Listen（绑定端口）→ Serve（阻塞服务直到 ctx 取消）。
// 配置热加载见 Reload：先完整构建新运行时，全部成功后再原子切换；
// 任何失败都保持旧配置原样服务。
type App struct {
	logger  *slog.Logger
	logCtrl *logging.Control
	metrics *metrics.Metrics

	httpSrv  *httpproxy.Server
	socksSrv *socks5.Server
	dnsSrv   *dnsgw.Server // 可选：DNS 网关（dns.listen 非空时启用）

	limiter *connlimit.Limiter
	status  *status.Status

	// policy 是运行期配置快照：各组件按请求/连接读取，Reload 原子替换。
	policy livePolicy

	httpLn     net.Listener
	socksLn    net.Listener
	dnsLn      *dnsgw.Listener
	metricsSrv *http.Server
	metricsLn  net.Listener

	reloadMu sync.Mutex
	closing  atomic.Bool
	serveCtx context.Context // Serve 启动后写入；重载替换预热池时作为其父 ctx
}

// clientRuntime 是一次配置构建出的完整运行时。
// 构建过程不触碰线上状态；全部就绪后整份切换（初始启动与热加载共用）。
type clientRuntime struct {
	cfg    *config.Client
	rules  *ruleset.Provider // 分流规则源（本地文件 / 远程 URL / 空），刷新时原地原子切换
	auth   *auth.Store       // nil：入站不校验认证
	dialer *dialer.Dialer    // 目标拨号（含分流与出口节点）
	pool   *nodes.Pool       // nil：未配置出口节点
	// connPool 是上游空闲隧道连接池；nil：未启用（pool.max_idle = 0）。
	connPool *connpool.Pool

	// DNS 网关的动态参数（dns.listen 非空时有效）：预解析后的生效值。
	dnsRemote  string
	dnsLocal   []string
	dnsTimeout time.Duration
}

// livePolicy 持有当前生效的运行时快照。读取是原子指针加载，
// 单次请求/连接内读取到的策略保持一致。
type livePolicy struct {
	snap atomic.Pointer[clientRuntime]
}

func (p *livePolicy) load() *clientRuntime { return p.snap.Load() }

// clientLive 把运行时快照适配为各组件需要的动态策略接口。
// 单个适配器同时满足 httpproxy / socks5 / dnsgw 三份消费方接口（方法集是三者
// 的并集；返回类型锚定 core 契约），新增热加载项只需维护这一处；
// 任意消费方接口增删方法都会让下方编译期断言失败，不会静默失配。
type clientLive struct{ app *App }

// Auth 返回当前凭据校验能力；未配置认证时必须返回真正的 nil 接口——
// 消费方以接口 == nil 判定“不校验”，nil *Store 装进接口会被误判为启用。
func (l clientLive) Auth() core.Authenticator {
	store := l.app.policy.load().auth
	if store == nil {
		return nil
	}
	return store
}
func (l clientLive) Dialer() core.TargetDialer { return l.app.policy.load().dialer }

// DialProxy 实现 core.ProxyDialer：DNS 网关用它把远程解析固定送往当前
// 快照的出口节点池，热加载语义与其余动态策略一致。
func (l clientLive) DialProxy(ctx context.Context, t core.Target) (net.Conn, core.Route, error) {
	return l.app.policy.load().dialer.DialProxy(ctx, t)
}

func (l clientLive) IdleTimeout() time.Duration {
	return l.app.policy.load().cfg.Timeouts.Idle.Std()
}
func (l clientLive) ReadHeaderTimeout() time.Duration {
	return l.app.policy.load().cfg.Timeouts.Handshake.Std()
}
func (l clientLive) HandshakeTimeout() time.Duration {
	return l.app.policy.load().cfg.Timeouts.Handshake.Std()
}
func (l clientLive) ShutdownTimeout() time.Duration {
	return l.app.policy.load().cfg.Timeouts.Shutdown.Std()
}
func (l clientLive) Router() dnsgw.RouteDecider { return l.app.policy.load().rules }
func (l clientLive) Remote() string             { return l.app.policy.load().dnsRemote }
func (l clientLive) Local() []string            { return l.app.policy.load().dnsLocal }
func (l clientLive) Timeout() time.Duration     { return l.app.policy.load().dnsTimeout }

var (
	_ httpproxy.LivePolicy = clientLive{}
	_ socks5.LivePolicy    = clientLive{}
	_ dnsgw.LivePolicy     = clientLive{}
	_ core.ProxyDialer     = clientLive{}
)

// New 校验依赖并组装应用（不绑定端口）。
// logCtrl 是运行时可调整的日志控制器（可为 nil，此时 /log/level 端点不可用）。
func New(cfg *config.Client, logger *slog.Logger, logCtrl *logging.Control) (*App, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	app := &App{logger: logger, logCtrl: logCtrl, metrics: metrics.New()}
	app.limiter = connlimit.New(cfg.Limits.EffectiveMaxConnections())

	rt, err := app.buildRuntime(cfg, nil)
	if err != nil {
		return nil, err
	}
	app.policy.snap.Store(rt)

	app.status = status.New(status.Options{
		Version: version.Get().Version,
		Checks:  app.healthChecks(),
		Runtime: app.runtimeStats,
	})
	if cfg.DNS.Listen != "" {
		dnsSrv, err := dnsgw.New(dnsgw.Options{
			ListenAddr: cfg.DNS.Listen,
			Remote:     rt.dnsRemote,
			Local:      rt.dnsLocal,
			Timeout:    rt.dnsTimeout,
			Router:     rt.rules,
			// 拨号经 clientLive 读取当前快照：远程解析始终跟随热加载后的出口节点。
			ProxyDialer:     clientLive{app: app},
			Logger:          logger,
			Observer:        app.metrics,
			ShutdownTimeout: cfg.Timeouts.Shutdown.Std(),
			Live:            clientLive{app: app},
		})
		if err != nil {
			return nil, err
		}
		app.dnsSrv = dnsSrv
	}

	app.httpSrv = &httpproxy.Server{
		Live:      clientLive{app: app},
		Logger:    logger,
		Telemetry: app.metrics,
	}
	app.socksSrv = &socks5.Server{
		Live:      clientLive{app: app},
		Logger:    logger,
		Telemetry: app.metrics,
	}
	return app, nil
}

// Listen 绑定配置中的所有监听端口。
func (a *App) Listen() error {
	cfg := a.policy.load().cfg
	if addr := cfg.Inbound.HTTP; addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("clientapp: listen http %s: %w", addr, err)
		}
		a.httpLn = connlimit.WrapListener(ln, a.limiter, func(conn net.Conn) {
			a.metrics.ConnRejected(core.ProtoHTTP)
			httpproxy.WriteOverloaded(conn)
		})
	}
	if addr := cfg.Inbound.SOCKS5; addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("clientapp: listen socks5 %s: %w", addr, err)
		}
		a.socksLn = connlimit.WrapListener(ln, a.limiter, func(conn net.Conn) {
			a.metrics.ConnRejected(core.ProtoSOCKS5)
			socks5.WriteOverloadReply(conn)
		})
	}
	if addr := cfg.Metrics.Listen; addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("clientapp: listen metrics %s: %w", addr, err)
		}
		if !config.IsLoopbackListen(addr) {
			a.logger.Warn("ops endpoints are bound to a non-loopback address; keep them behind a firewall and note PUT /log/level stays loopback-only", "listen", addr)
		}
		a.metricsLn = ln
		a.metricsSrv = &http.Server{
			Handler:           a.metricsHandler(),
			ReadHeaderTimeout: 5 * time.Second,
		}
	}
	if a.dnsSrv != nil {
		ln, err := dnsgw.Listen(cfg.DNS.Listen)
		if err != nil {
			return err
		}
		a.dnsLn = ln
	}
	return nil
}

// Serve 阻塞服务直到 ctx 取消或任一监听出错；返回前完成优雅关停。
func (a *App) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	a.reloadMu.Lock()
	a.serveCtx = ctx
	a.reloadMu.Unlock()
	defer func() {
		a.reloadMu.Lock()
		a.closing.Store(true)
		a.reloadMu.Unlock()
	}()

	a.policy.load().connPool.Start(ctx)
	a.policy.load().pool.StartHealthChecks(ctx)
	a.policy.load().rules.Start(ctx)
	// 关停一开始就释放池内空闲连接：它们没有在途数据，
	// 提前关闭既让服务端尽快回收，也避免排空期的新请求再领取。
	go func() {
		<-ctx.Done()
		a.policy.load().connPool.Close()
		a.policy.load().pool.Close()
		a.policy.load().rules.Close()
	}()
	defer func() {
		a.policy.load().connPool.Close()
		a.policy.load().pool.Close()
		a.policy.load().rules.Close()
	}()

	errCh := make(chan error, 4)
	running := 0
	if a.httpLn != nil {
		running++
		go func() { errCh <- a.httpSrv.Serve(ctx, a.httpLn) }()
	}
	if a.socksLn != nil {
		running++
		go func() { errCh <- a.socksSrv.Serve(ctx, a.socksLn) }()
	}
	if a.metricsSrv != nil {
		running++
		go func() { errCh <- a.serveMetrics(ctx) }()
	}
	if a.dnsSrv != nil && a.dnsLn != nil {
		running++
		go func() { errCh <- a.dnsSrv.Serve(ctx, a.dnsLn) }()
	}

	var firstErr error
	for i := 0; i < running; i++ {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
			cancel()
		}
	}
	return firstErr
}

// HTTPAddr 返回 HTTP 代理实际监听地址（未启用时为空）。
func (a *App) HTTPAddr() string { return addrOf(a.httpLn) }

// SOCKS5Addr 返回 SOCKS5 实际监听地址（未启用时为空）。
func (a *App) SOCKS5Addr() string { return addrOf(a.socksLn) }

// DNSAddr 返回 DNS 网关实际监听地址（未启用时为空）。
func (a *App) DNSAddr() string {
	if a.dnsLn == nil {
		return ""
	}
	return a.dnsLn.Addr().String()
}

// MetricsAddr 返回指标端点实际监听地址（未启用时为空）。
func (a *App) MetricsAddr() string { return addrOf(a.metricsLn) }

func (a *App) serveMetrics(ctx context.Context) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = a.metricsSrv.Shutdown(shutdownCtx)
		case <-done:
		}
	}()
	err := a.metricsSrv.Serve(a.metricsLn)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (a *App) metricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", a.metrics.Handler())
	mux.Handle("/health", a.status.Health())
	mux.Handle("/stats", a.status.Stats())
	mux.Handle("/log/level", logging.LevelHandler(a.logger, a.logCtrl.LevelVar()))
	return mux
}

// healthChecks 返回依赖健康检查：配置了出口节点时，池中无健康节点视为依赖不可用。
func (a *App) healthChecks() []func() error {
	return []func() error{func() error {
		pool := a.policy.load().pool
		if pool == nil {
			return nil
		}
		if pool.AnyHealthy() {
			return nil
		}
		return errors.New("no healthy exit nodes available")
	}}
}

// runtimeStats 组装 /stats 快照：活跃连接数与出口节点状态。
func (a *App) runtimeStats() status.Runtime {
	rt := a.policy.load()
	active := a.metrics.ActiveByProto()
	httpConns := active[core.ProtoHTTP]
	socksConns := active[core.ProtoSOCKS5]
	out := status.Runtime{
		Connections: status.Connections{
			HTTP:   httpConns,
			SOCKS5: socksConns,
			Total:  httpConns + socksConns,
		},
	}
	if rt.pool != nil {
		idle := rt.connPool.IdleCounts()
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
	if snap := rt.rules.Snapshot(); snap.Source != ruleset.SourceNone {
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
	// 0 = 不限制时不输出 limit 字段（与 README 描述一致）。
	if a.limiter != nil && a.limiter.Max() > 0 {
		out.Limit = &status.Limit{
			MaxConnections: a.limiter.Max(),
			Current:        a.limiter.Active(),
			Rejected:       a.limiter.Rejected(),
		}
	}
	return out
}

// Reload 应用一份新配置：先完整构建新运行时（规则源重读/重拉、TLS 与凭据重建、
// 节点池重建），全部成功后再原子切换；任何失败都返回错误并保持旧配置原样
// 服务——配置错误不会波及线上。监听地址属于启动时绑定的资源，变更需要重启，
// 会被明确拒绝（同样保持旧配置）。
//
// 生效边界为“新连接”：切换瞬间已在处理的请求继续使用旧快照，之后到达的
// 请求使用新快照；单个请求/连接内读取到的策略保持一致。
func (a *App) Reload(next *config.Client) (err error) {
	a.reloadMu.Lock()
	defer a.reloadMu.Unlock()
	if a.closing.Load() || (a.serveCtx != nil && a.serveCtx.Err() != nil) {
		return errors.New("clientapp: shutting down; reload ignored")
	}

	cur := a.policy.load()
	result := metrics.ReloadError
	defer func() { a.metrics.ConfigReload(result) }()

	if changed := config.ClientRestartOnlyChanges(cur.cfg, next); len(changed) > 0 {
		return fmt.Errorf("clientapp: %s changed: restart required (listen addresses cannot be rebound by hot reload)",
			strings.Join(changed, ", "))
	}
	rt, err := a.buildRuntime(next, cur)
	if err != nil {
		return fmt.Errorf("clientapp: build new configuration: %w", err)
	}
	// 提交：先启动新预热池，再原子切换快照，最后释放被替换的旧池。
	if rt.connPool != cur.connPool {
		rt.connPool.Start(a.poolCtx())
	}
	if rt.pool != cur.pool {
		rt.pool.StartHealthChecks(a.poolCtx())
	}
	if rt.rules != cur.rules {
		// 规则源整体替换时兜底失效转发路径空闲连接：新源首次拉取失败等
		// 场景不会触发 OnChange，但后续请求的决策已按新运行时生效。
		a.dropForwardIdleConns()
		rt.rules.Start(a.poolCtx())
	}
	a.policy.snap.Store(rt)
	if rt.connPool != cur.connPool {
		cur.connPool.Close()
	}
	if rt.pool != cur.pool {
		cur.pool.Close()
	}
	if rt.rules != cur.rules {
		cur.rules.Close()
	}
	a.limiter.SetMax(next.Limits.EffectiveMaxConnections())
	if a.logCtrl != nil {
		a.logCtrl.SetLevel(next.Log.Level)
		a.logCtrl.SetFormat(next.Log.Format)
	}
	result = metrics.ReloadSuccess
	a.logger.Info("configuration reloaded",
		"nodes", len(next.Nodes),
		"auth_users", len(next.Inbound.Auth),
		"routing_default", next.Routing.Default,
		"max_connections", next.Limits.EffectiveMaxConnections(),
		"dns_gateway", next.DNS.Listen != "",
	)
	return nil
}

// ReloadFile 读取、校验并应用配置文件（path 与启动时相同）。
// levelOverride 是启动参数 -log-level 的显式覆盖，非空时同样优先于文件值。
// 解析 / 校验失败与构建失败一样保持旧配置继续服务，
// 并且每次尝试（无论失败在哪一步）都恰好计入一次 config_reloads_total。
func (a *App) ReloadFile(path, levelOverride string) error {
	cfg, err := config.LoadClient(path)
	if err != nil {
		a.metrics.ConfigReload(metrics.ReloadError)
		return err
	}
	if levelOverride != "" {
		cfg.Log.Level = levelOverride
	}
	return a.Reload(cfg)
}

// buildRuntime 依据配置构建完整运行时；reuse 非 nil 时复用未变更的上游栈
// （节点池与预热池），避免无关重载抖动预热连接。规则源在每次构建时重新检查
// （本地文件严格重读、远程 URL 容错重拉），因此规则内容的修改也能通过重载
// 生效。任何失败都不产生外部副作用（失败路径关闭新建的池）。
func (a *App) buildRuntime(cfg *config.Client, reuse *clientRuntime) (*clientRuntime, error) {
	store, err := buildAuth(cfg)
	if err != nil {
		return nil, err
	}
	rt := &clientRuntime{cfg: cfg, auth: store}

	upstreamChanged := true
	if reuse != nil {
		// 指纹覆盖整个上游子结构（节点 / 预热池 / 健康检查 / TLS / 超时），
		// 新字段自动参与比较；计算失败按「已变更」处理，保守重建。
		if changed, err := upstreamStackChanged(reuse.cfg, cfg); err == nil {
			upstreamChanged = changed
		} else {
			a.logger.Warn("upstream fingerprint failed; rebuilding pools", "error", err)
		}
	}
	if upstreamChanged {
		baseTLS, err := buildClientTLS(cfg)
		if err != nil {
			return nil, err
		}
		connPool, err := buildConnPool(cfg, baseTLS, a.metrics, a.logger)
		if err != nil {
			return nil, err
		}
		pool, err := buildNodePool(cfg, baseTLS, connPool, a.metrics, a.logger)
		if err != nil {
			connPool.Close()
			return nil, err
		}
		rt.connPool = connPool
		rt.pool = pool
	} else {
		rt.connPool = reuse.connPool
		rt.pool = reuse.pool
	}
	// 规则源放在最后构建：复用时会立即重读 / 重拉一次（文件严格、URL 容错），
	// 这是本函数中唯一改动在役状态的一步，之后不再有失败点，保证
	// “重载要么整体生效、要么完全保持旧配置”。
	rules, err := a.buildRuleset(cfg, reuse)
	if err != nil {
		if upstreamChanged {
			rt.connPool.Close()
			rt.pool.Close()
		}
		return nil, err
	}
	rt.rules = rules
	rt.dialer = dialer.New(dialer.Options{
		Router:      rules,
		Pool:        rt.pool,
		DialTimeout: cfg.Timeouts.Dial.Std(),
	})

	if cfg.DNS.Listen != "" {
		rt.dnsRemote = cfg.DNS.EffectiveRemote()
		rt.dnsTimeout = cfg.DNS.EffectiveTimeout()
		rt.dnsLocal = a.resolveDNSLocal(cfg.DNS)
	}
	return rt, nil
}

// upstreamStackChanged 判断两份配置的出口链路栈是否相同：相同 ⇒ 复用现有
// 节点池与预热池；不同 ⇒ 重建。比较依据是 config.UpstreamFingerprint
// （整份子结构的哈希），不做逐字段手工列举——新增上游相关字段时指纹自动变化，
// 分类遗漏由 internal/config 的守卫测试在本地拦截。
func upstreamStackChanged(oldCfg, newCfg *config.Client) (bool, error) {
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

// resolveDNSLocal 返回生效的直连解析器列表；未显式配置时读取系统
// resolv.conf（读取失败或无可用条目时告警并保持为空，与既有启动行为一致）。
func (a *App) resolveDNSLocal(dns config.DNS) []string {
	if len(dns.Local) > 0 {
		return append([]string(nil), dns.Local...)
	}
	path := dnsgw.DefaultResolvConfPath
	resolved, err := dnsgw.LocalResolversFromResolvConf(path, dns.Listen)
	switch {
	case err != nil:
		a.logger.Warn("dns gateway: cannot read system resolvers, direct-routed names will fail",
			"path", path, "error", err)
		return nil
	case len(resolved) == 0:
		a.logger.Warn("dns gateway: no usable system resolvers found, direct-routed names will fail",
			"path", path, "hint", "set dns.local explicitly")
		return nil
	default:
		a.logger.Info("dns gateway: using system resolvers for direct-routed names",
			"path", path, "resolvers", resolved)
		return resolved
	}
}

// poolCtx 返回预热池后台任务的父 ctx：Serve 启动后为 Serve 的 ctx；
// 极端时序下（重载先于 Serve）使用进程级 ctx，由池的 Close 停止。
func (a *App) poolCtx() context.Context {
	if a.serveCtx != nil {
		return a.serveCtx
	}
	return context.Background()
}

// buildRuleset 构建分流规则源（本地文件 / 远程 URL / 空）并完成首次加载。
//
// reuse 非 nil 且规则源配置（类型、路径 / URL、刷新周期）未变时复用现有
// Provider：保留已加载规则与刷新循环，并立即重新检查一次源——本地文件严格
// 重读（失败拒绝本次重载），远程 URL 容错重拉（失败只告警、保持现有规则）。
// 规则源配置变化时重建；URL 首次拉取失败为告警语义（空规则 + 后续重试）。
func (a *App) buildRuleset(cfg *config.Client, reuse *clientRuntime) (*ruleset.Provider, error) {
	def, err := routing.ParseAction(cfg.Routing.Default)
	if err != nil {
		return nil, fmt.Errorf("routing.default: %w", err)
	}
	privateDirect := cfg.Routing.PrivateDirect == nil || *cfg.Routing.PrivateDirect
	spec := ruleset.SpecOf(cfg.Routing.RulesFile, cfg.Routing.RulesURL, cfg.Routing.EffectiveRulesRefreshInterval())

	if reuse != nil && reuse.rules != nil && reuse.rules.Spec() == spec {
		prov := reuse.rules
		prov.UpdateOptions(def, privateDirect)
		if err := prov.Recheck(context.Background()); err != nil {
			return nil, err
		}
		return prov, nil
	}
	prov, err := ruleset.New(ruleset.Options{
		FilePath:        cfg.Routing.RulesFile,
		URL:             cfg.Routing.RulesURL,
		RefreshInterval: cfg.Routing.EffectiveRulesRefreshInterval(),
		Default:         def,
		PrivateDirect:   privateDirect,
		Logger:          a.logger,
		Observer:        a.metrics,
		OnChange:        a.dropForwardIdleConns,
	})
	if err != nil {
		return nil, err
	}
	return prov, nil
}

// dropForwardIdleConns 在分流规则变化后丢弃转发路径（绝对地址请求）的空闲
// 上游连接，避免后续请求复用到旧路由建立的连接；在途请求不受影响，
// 新请求按新规则重新建连。httpSrv 在 App 生命周期内只创建一次，读安全。
func (a *App) dropForwardIdleConns() {
	if a.httpSrv != nil {
		a.httpSrv.CloseIdleConnections()
	}
}

// buildAuth 构建入站凭据存储；未配置认证时返回 nil。
func buildAuth(cfg *config.Client) (*auth.Store, error) {
	if len(cfg.Inbound.Auth) == 0 {
		return nil, nil
	}
	users := make([]auth.User, 0, len(cfg.Inbound.Auth))
	for _, u := range cfg.Inbound.Auth {
		users = append(users, auth.User{Username: u.Username, Password: u.Password})
	}
	return auth.NewStore(users)
}

// buildNodePool 构建出口节点池；未配置节点时返回 nil（仅直连）。
// 拨号优先从预热连接池领取空闲隧道；未命中或领取失效时新建隧道。
// 主动健康检查对节点做 TCP+TLS 握手探测（不发 Trojan 请求、不占预热池）；
// 节点被摘除时立即清空其空闲预热连接。
func buildNodePool(cfg *config.Client, baseTLS *tls.Config, connPool *connpool.Pool, m *metrics.Metrics, logger *slog.Logger) (*nodes.Pool, error) {
	if len(cfg.Nodes) == 0 {
		return nil, nil
	}
	// 配置模型 → 节点池运行时模型（nodes 包不反向依赖 config）。
	nodeCfgs := make([]nodes.Node, 0, len(cfg.Nodes))
	for _, n := range cfg.Nodes {
		nodeCfgs = append(nodeCfgs, nodes.Node{Addr: n.Addr, Password: n.Password, SNI: n.SNI})
	}
	dialFn := func(ctx context.Context, node nodes.Node, t core.Target) (net.Conn, error) {
		if conn, ok := connPool.Claim(ctx, node.Addr, t); ok {
			return conn, nil
		}
		nodeTLS := baseTLS.Clone()
		if node.SNI != "" {
			nodeTLS.ServerName = node.SNI
		}
		return trojan.Dial(ctx, trojan.ClientConfig{
			ServerAddr:       node.Addr,
			Password:         node.Password,
			TLSConfig:        nodeTLS,
			DialTimeout:      cfg.Timeouts.Dial.Std(),
			HandshakeTimeout: cfg.Timeouts.Handshake.Std(),
		}, t)
	}
	hc := cfg.HealthCheck
	opts := nodes.Options{
		Logger:   logger,
		Observer: m,
		// 故障转移总预算：整条候选节点的等待上限（缺省 30s，可配置）。
		FailoverBudget: cfg.Timeouts.Failover.Std(),
		Health: nodes.HealthOptions{
			Interval:  hc.EffectiveInterval(),
			Timeout:   hc.EffectiveTimeout(),
			Failures:  hc.EffectiveFailures(),
			Successes: hc.EffectiveSuccesses(),
		},
		OnRemove: func(addr string) {
			// 摘除后该节点不再接新流量：立即释放其空闲预热连接，避免积压死连接。
			connPool.DropNode(addr)
		},
	}
	if opts.Health.Interval > 0 {
		probeTimeout := hc.EffectiveTimeout()
		opts.Probe = func(ctx context.Context, node nodes.Node) error {
			nodeTLS := baseTLS.Clone()
			if node.SNI != "" {
				nodeTLS.ServerName = node.SNI
			}
			conn, err := trojan.Connect(ctx, trojan.ClientConfig{
				ServerAddr:       node.Addr,
				Password:         node.Password,
				TLSConfig:        nodeTLS,
				DialTimeout:      probeTimeout,
				HandshakeTimeout: probeTimeout,
			})
			if err != nil {
				return err
			}
			return conn.Close()
		}
	}
	return nodes.New(nodeCfgs, dialFn, opts)
}

// buildConnPool 构建上游空闲隧道连接池；未启用（max_idle = 0）或未配置节点时返回 nil。
func buildConnPool(cfg *config.Client, baseTLS *tls.Config, m *metrics.Metrics, logger *slog.Logger) (*connpool.Pool, error) {
	maxIdle := cfg.Pool.EffectiveMaxIdle()
	if maxIdle <= 0 || len(cfg.Nodes) == 0 {
		return nil, nil
	}
	specs := make([]connpool.Node, 0, len(cfg.Nodes))
	for _, node := range cfg.Nodes {
		node := node
		nodeTLS := baseTLS.Clone()
		if node.SNI != "" {
			nodeTLS.ServerName = node.SNI
		}
		hash := auth.SHA224Hex(node.Password)
		specs = append(specs, connpool.Node{
			Addr: node.Addr,
			// 预热只完成 TCP+TLS 握手；Trojan 请求在领取时补发（Start）。
			Dial: func(ctx context.Context) (net.Conn, error) {
				return trojan.Connect(ctx, trojan.ClientConfig{
					ServerAddr:       node.Addr,
					Password:         node.Password,
					TLSConfig:        nodeTLS,
					DialTimeout:      cfg.Timeouts.Dial.Std(),
					HandshakeTimeout: cfg.Timeouts.Handshake.Std(),
				})
			},
			Start: func(ctx context.Context, conn net.Conn, t core.Target) error {
				if err := trojan.StartRequest(ctx, conn, hash, t, cfg.Timeouts.Handshake.Std()); err != nil {
					return fmt.Errorf("trojan: write request to %s: %w", node.Addr, err)
				}
				return nil
			},
		})
	}
	connPool, err := connpool.New(specs, connpool.Options{
		MaxIdle:  maxIdle,
		IdleTTL:  cfg.Pool.EffectiveIdleTTL(),
		Logger:   logger,
		Observer: m,
	})
	if err != nil {
		return nil, err
	}
	return connPool, nil
}

func buildClientTLS(cfg *config.Client) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.TLS.InsecureSkipVerify, // 仅用于自签调试场景
	}
	if cfg.TLS.CAFile != "" {
		pemData, err := os.ReadFile(cfg.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("tls.ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("tls.ca_file: no certificates found in %s", cfg.TLS.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, nil
}

func addrOf(ln net.Listener) string {
	if ln == nil {
		return ""
	}
	return ln.Addr().String()
}
