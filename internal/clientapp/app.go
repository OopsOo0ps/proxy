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
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/connlimit"
	"github.com/OopsOo0ps/proxy/internal/connpool"
	"github.com/OopsOo0ps/proxy/internal/dialer"
	"github.com/OopsOo0ps/proxy/internal/dnsgw"
	"github.com/OopsOo0ps/proxy/internal/httpproxy"
	"github.com/OopsOo0ps/proxy/internal/logging"
	"github.com/OopsOo0ps/proxy/internal/metrics"
	"github.com/OopsOo0ps/proxy/internal/nodes"
	"github.com/OopsOo0ps/proxy/internal/routing"
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
	router *routing.Engine
	auth   *auth.Store    // nil：入站不校验认证
	dialer *dialer.Dialer // 目标拨号（含分流与出口节点）
	pool   *nodes.Pool    // nil：未配置出口节点
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

// httpLive / socksLive / dnsLive 把运行时快照适配为各组件需要的动态策略接口。
// 各组件接口的方法签名不同（各自定义 Dialer 返回类型），因此用适配器区分。
type httpLive struct{ app *App }

func (l httpLive) Auth() *auth.Store { return l.app.policy.load().auth }
func (l httpLive) Dialer() httpproxy.TargetDialer {
	return l.app.policy.load().dialer
}
func (l httpLive) IdleTimeout() time.Duration {
	return l.app.policy.load().cfg.Timeouts.Idle.Std()
}
func (l httpLive) ReadHeaderTimeout() time.Duration {
	return l.app.policy.load().cfg.Timeouts.Handshake.Std()
}
func (l httpLive) ShutdownTimeout() time.Duration {
	return l.app.policy.load().cfg.Timeouts.Shutdown.Std()
}

type socksLive struct{ app *App }

func (l socksLive) Auth() *auth.Store { return l.app.policy.load().auth }
func (l socksLive) Dialer() socks5.TargetDialer {
	return l.app.policy.load().dialer
}
func (l socksLive) HandshakeTimeout() time.Duration {
	return l.app.policy.load().cfg.Timeouts.Handshake.Std()
}
func (l socksLive) IdleTimeout() time.Duration {
	return l.app.policy.load().cfg.Timeouts.Idle.Std()
}
func (l socksLive) ShutdownTimeout() time.Duration {
	return l.app.policy.load().cfg.Timeouts.Shutdown.Std()
}

type dnsLive struct{ app *App }

func (l dnsLive) Router() dnsgw.RouteDecider { return l.app.policy.load().router }
func (l dnsLive) Remote() string             { return l.app.policy.load().dnsRemote }
func (l dnsLive) Local() []string            { return l.app.policy.load().dnsLocal }
func (l dnsLive) Timeout() time.Duration     { return l.app.policy.load().dnsTimeout }
func (l dnsLive) ShutdownTimeout() time.Duration {
	return l.app.policy.load().cfg.Timeouts.Shutdown.Std()
}

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
			Router:     rt.router,
			ProxyDial: func(ctx context.Context, host string, port uint16) (net.Conn, string, error) {
				conn, route, err := app.policy.load().dialer.DialProxy(ctx, host, port)
				if err != nil {
					return nil, "", err
				}
				return conn, route.Label(), nil
			},
			Logger:          logger,
			Metrics:         app.metrics,
			ShutdownTimeout: cfg.Timeouts.Shutdown.Std(),
			Live:            dnsLive{app: app},
		})
		if err != nil {
			return nil, err
		}
		app.dnsSrv = dnsSrv
	}

	app.httpSrv = &httpproxy.Server{
		Live:    httpLive{app: app},
		Logger:  logger,
		Metrics: app.metrics,
	}
	app.socksSrv = &socks5.Server{
		Live:    socksLive{app: app},
		Logger:  logger,
		Metrics: app.metrics,
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
			a.metrics.ConnRejected(metrics.ProtoHTTP)
			httpproxy.WriteOverloaded(conn)
		})
	}
	if addr := cfg.Inbound.SOCKS5; addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("clientapp: listen socks5 %s: %w", addr, err)
		}
		a.socksLn = connlimit.WrapListener(ln, a.limiter, func(conn net.Conn) {
			a.metrics.ConnRejected(metrics.ProtoSOCKS5)
			socks5.WriteOverloadReply(conn)
		})
	}
	if addr := cfg.Metrics.Listen; addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("clientapp: listen metrics %s: %w", addr, err)
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
	// 关停一开始就释放池内空闲连接：它们没有在途数据，
	// 提前关闭既让服务端尽快回收，也避免排空期的新请求再领取。
	go func() {
		<-ctx.Done()
		a.policy.load().connPool.Close()
	}()
	defer func() { a.policy.load().connPool.Close() }()

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
	httpConns := active[metrics.ProtoHTTP]
	socksConns := active[metrics.ProtoSOCKS5]
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
				Idle:              idle[n.Addr],
			})
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

// Reload 应用一份新配置：先完整构建新运行时（规则文件重读、TLS 与凭据重建、
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
	a.policy.snap.Store(rt)
	if rt.connPool != cur.connPool {
		cur.connPool.Close()
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
// （节点池与预热池），避免无关重载抖动预热连接。规则文件在每次构建时重读，
// 因此规则文件内容的修改也能通过重载生效。任何失败都不产生外部副作用
// （失败路径关闭新建的池）。
func (a *App) buildRuntime(cfg *config.Client, reuse *clientRuntime) (*clientRuntime, error) {
	router, err := buildRouter(cfg)
	if err != nil {
		return nil, err
	}
	store, err := buildAuth(cfg)
	if err != nil {
		return nil, err
	}
	rt := &clientRuntime{cfg: cfg, router: router, auth: store}

	upstreamChanged := reuse == nil ||
		!reflect.DeepEqual(reuse.cfg.Nodes, cfg.Nodes) ||
		!reflect.DeepEqual(reuse.cfg.Pool, cfg.Pool) ||
		!reflect.DeepEqual(reuse.cfg.TLS, cfg.TLS) ||
		!reflect.DeepEqual(reuse.cfg.Timeouts, cfg.Timeouts)
	if upstreamChanged {
		baseTLS, err := buildClientTLS(cfg)
		if err != nil {
			return nil, err
		}
		connPool, err := buildConnPool(cfg, baseTLS, a.metrics, a.logger)
		if err != nil {
			return nil, err
		}
		pool, err := buildNodePool(cfg, baseTLS, connPool)
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
	rt.dialer = dialer.New(dialer.Options{
		Router:      router,
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

// buildRouter 加载规则文件并构建分流引擎。
func buildRouter(cfg *config.Client) (*routing.Engine, error) {
	var rules *routing.Rules
	if cfg.Routing.RulesFile != "" {
		loaded, err := routing.LoadRulesFile(cfg.Routing.RulesFile)
		if err != nil {
			return nil, err
		}
		rules = loaded
	}
	def, err := routing.ParseAction(cfg.Routing.Default)
	if err != nil {
		return nil, fmt.Errorf("routing.default: %w", err)
	}
	privateDirect := cfg.Routing.PrivateDirect == nil || *cfg.Routing.PrivateDirect
	return routing.NewEngine(rules, routing.Options{Default: def, PrivateDirect: privateDirect})
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
func buildNodePool(cfg *config.Client, baseTLS *tls.Config, connPool *connpool.Pool) (*nodes.Pool, error) {
	if len(cfg.Nodes) == 0 {
		return nil, nil
	}
	dialFn := func(ctx context.Context, node config.Node, host string, port uint16) (net.Conn, error) {
		if conn, ok := connPool.Claim(ctx, node.Addr, host, port); ok {
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
		}, host, port)
	}
	return nodes.New(cfg.Nodes, dialFn, nodes.Options{})
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
			Start: func(conn net.Conn, host string, port uint16) error {
				if err := trojan.StartRequest(conn, hash, host, port, cfg.Timeouts.Handshake.Std()); err != nil {
					return fmt.Errorf("trojan: write request to %s: %w", node.Addr, err)
				}
				return nil
			},
		})
	}
	connPool, err := connpool.New(specs, connpool.Options{
		MaxIdle: maxIdle,
		IdleTTL: cfg.Pool.EffectiveIdleTTL(),
		Logger:  logger,
		Metrics: m,
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
