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
	"time"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/connpool"
	"github.com/OopsOo0ps/proxy/internal/dialer"
	"github.com/OopsOo0ps/proxy/internal/httpproxy"
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
type App struct {
	cfg     *config.Client
	logger  *slog.Logger
	metrics *metrics.Metrics

	httpSrv  *httpproxy.Server
	socksSrv *socks5.Server

	pool     *nodes.Pool    // 出口节点选择/冷却
	connPool *connpool.Pool // 上游空闲隧道连接池（预热）
	status   *status.Status

	httpLn     net.Listener
	socksLn    net.Listener
	metricsSrv *http.Server
	metricsLn  net.Listener
}

// New 校验依赖并组装应用（不绑定端口）。
func New(cfg *config.Client, logger *slog.Logger) (*App, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	engine, err := buildRouter(cfg)
	if err != nil {
		return nil, err
	}
	store, err := buildAuth(cfg)
	if err != nil {
		return nil, err
	}

	app := &App{cfg: cfg, logger: logger, metrics: metrics.New()}

	baseTLS, err := buildClientTLS(cfg)
	if err != nil {
		return nil, err
	}
	connPool, err := buildConnPool(cfg, baseTLS, app.metrics, logger)
	if err != nil {
		return nil, err
	}
	app.connPool = connPool

	pool, err := buildNodePool(cfg, baseTLS, connPool)
	if err != nil {
		return nil, err
	}
	app.pool = pool
	app.status = status.New(status.Options{
		Version: version.Get().Version,
		Checks:  app.healthChecks(),
		Runtime: app.runtimeStats,
	})
	targetDialer := dialer.New(dialer.Options{
		Router:      engine,
		Pool:        pool,
		DialTimeout: cfg.Timeouts.Dial.Std(),
	})

	app.httpSrv = &httpproxy.Server{
		Auth:        store,
		Dialer:      targetDialer,
		Logger:      logger,
		Metrics:     app.metrics,
		IdleTimeout: cfg.Timeouts.Idle.Std(),
	}
	app.socksSrv = &socks5.Server{
		Auth:             store,
		Dialer:           targetDialer,
		Logger:           logger,
		Metrics:          app.metrics,
		HandshakeTimeout: cfg.Timeouts.Handshake.Std(),
		IdleTimeout:      cfg.Timeouts.Idle.Std(),
	}
	return app, nil
}

// Listen 绑定配置中的所有监听端口。
func (a *App) Listen() error {
	if addr := a.cfg.Inbound.HTTP; addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("clientapp: listen http %s: %w", addr, err)
		}
		a.httpLn = ln
	}
	if addr := a.cfg.Inbound.SOCKS5; addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("clientapp: listen socks5 %s: %w", addr, err)
		}
		a.socksLn = ln
	}
	if addr := a.cfg.Metrics.Listen; addr != "" {
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
	return nil
}

// Serve 阻塞服务直到 ctx 取消或任一监听出错；返回前完成优雅关停。
func (a *App) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if a.connPool != nil {
		a.connPool.Start(ctx)
		defer a.connPool.Close()
	}

	errCh := make(chan error, 3)
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
	return mux
}

// healthChecks 返回依赖健康检查：配置了出口节点时，池中无健康节点视为依赖不可用。
func (a *App) healthChecks() []func() error {
	if a.pool == nil {
		return nil
	}
	return []func() error{func() error {
		if a.pool.AnyHealthy() {
			return nil
		}
		return errors.New("no healthy exit nodes available")
	}}
}

// runtimeStats 组装 /stats 快照：活跃连接数与出口节点状态。
func (a *App) runtimeStats() status.Runtime {
	active := a.metrics.ActiveByProto()
	httpConns := active[metrics.ProtoHTTP]
	socksConns := active[metrics.ProtoSOCKS5]
	rt := status.Runtime{
		Connections: status.Connections{
			HTTP:   httpConns,
			SOCKS5: socksConns,
			Total:  httpConns + socksConns,
		},
	}
	if a.pool != nil {
		idle := a.connPool.IdleCounts()
		for _, n := range a.pool.Snapshot() {
			rt.Upstreams = append(rt.Upstreams, status.Upstream{
				Addr:              n.Addr,
				Healthy:           n.Healthy,
				Fails:             n.Fails,
				CooldownRemaining: status.Seconds(n.CooldownRemaining),
				Idle:              idle[n.Addr],
			})
		}
	}
	return rt
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
