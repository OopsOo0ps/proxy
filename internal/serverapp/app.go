// Package serverapp 组装 proxy-server：TLS 隧道监听、凭据校验、出口直连与指标端点。
package serverapp

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
	"github.com/OopsOo0ps/proxy/internal/logging"
	"github.com/OopsOo0ps/proxy/internal/metrics"
	"github.com/OopsOo0ps/proxy/internal/netutil"
	"github.com/OopsOo0ps/proxy/internal/status"
	"github.com/OopsOo0ps/proxy/internal/trojan"
	"github.com/OopsOo0ps/proxy/pkg/version"
)

// App 是组装完成的 proxy-server 实例。
// 生命周期：New → Listen（绑定端口）→ Serve（阻塞服务直到 ctx 取消）。
// 配置热加载见 Reload：先完整构建新运行时，全部成功后再原子切换；
// 任何失败都保持旧配置原样服务。
type App struct {
	logger  *slog.Logger
	logCtrl *logging.Control
	metrics *metrics.Metrics
	tunnel  *trojan.Server
	tlsCfg  *tls.Config
	status  *status.Status
	limiter *connlimit.Limiter

	// policy 是运行期配置快照：各组件按连接读取，Reload 原子替换。
	policy livePolicy

	tunnelLn   net.Listener
	metricsSrv *http.Server
	metricsLn  net.Listener

	reloadMu sync.Mutex
	closing  atomic.Bool

	rejectMu    sync.Mutex
	rejectLogAt time.Time
}

// serverRuntime 是一次配置构建出的完整运行时（证书、凭据、伪装页与超时）。
type serverRuntime struct {
	cfg          *config.Server
	cert         *tls.Certificate
	certNotAfter time.Time
	verifier     *auth.Store
	decoy        []byte
}

// livePolicy 持有当前生效的运行时快照。
type livePolicy struct {
	snap atomic.Pointer[serverRuntime]
}

func (p *livePolicy) load() *serverRuntime { return p.snap.Load() }

// trojanLive 把运行时快照适配为 trojan.Server 的动态策略接口。
type trojanLive struct{ app *App }

func (l trojanLive) Verifier() trojan.Verifier { return l.app.policy.load().verifier }
func (l trojanLive) Decoy() []byte             { return l.app.policy.load().decoy }
func (l trojanLive) HandshakeTimeout() time.Duration {
	return l.app.policy.load().cfg.Timeouts.Handshake.Std()
}
func (l trojanLive) DialTimeout() time.Duration {
	return l.app.policy.load().cfg.Timeouts.Dial.Std()
}
func (l trojanLive) IdleTimeout() time.Duration {
	return l.app.policy.load().cfg.Timeouts.Idle.Std()
}
func (l trojanLive) ShutdownTimeout() time.Duration {
	return l.app.policy.load().cfg.Timeouts.Shutdown.Std()
}

// 编译期断言：消费方接口与适配器失配（增删方法）会直接编译失败。
var _ trojan.LivePolicy = trojanLive{}

// New 加载证书与凭据并组装应用（不绑定端口）。
// logCtrl 是运行时可调整的日志控制器（可为 nil，此时 /log/level 端点不可用）。
func New(cfg *config.Server, logger *slog.Logger, logCtrl *logging.Control) (*App, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	app := &App{
		logger:  logger,
		logCtrl: logCtrl,
		metrics: metrics.New(),
	}
	app.limiter = connlimit.New(cfg.Limits.EffectiveMaxConnections())
	rt, err := app.buildRuntime(cfg)
	if err != nil {
		return nil, err
	}
	app.policy.snap.Store(rt)
	app.tlsCfg = &tls.Config{
		// GetCertificate 每次握手读取当前快照，证书文件热重载即刻生效。
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return app.policy.load().cert, nil
		},
		MinVersion: tls.VersionTLS12,
	}
	app.status = status.New(status.Options{
		Version: version.Get().Version,
		Checks:  app.healthChecks(),
		Runtime: app.runtimeStats,
	})
	app.tunnel = &trojan.Server{
		Live: trojanLive{app: app},
		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: app.policy.load().cfg.Timeouts.Dial.Std()}
			return dialer.DialContext(ctx, "tcp", addr)
		},
		Logger:  logger,
		Metrics: app.metrics,
	}
	return app, nil
}

// Listen 绑定隧道与指标端口。
func (a *App) Listen() error {
	cfg := a.policy.load().cfg
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("serverapp: listen %s: %w", cfg.Listen, err)
	}
	ln = connlimit.WrapListener(ln, a.limiter, func(conn net.Conn) {
		a.metrics.ConnRejected(metrics.ProtoTunnel)
		a.logTunnelReject(conn)
		_ = conn.Close()
	})
	a.tunnelLn = tls.NewListener(ln, a.tlsCfg)

	if addr := cfg.Metrics.Listen; addr != "" {
		metricsLn, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("serverapp: listen metrics %s: %w", addr, err)
		}
		if !config.IsLoopbackListen(addr) {
			a.logger.Warn("ops endpoints are bound to a non-loopback address; keep them behind a firewall and note PUT /log/level stays loopback-only", "listen", addr)
		}
		a.metricsLn = metricsLn
		a.metricsSrv = &http.Server{
			Handler:           a.metricsHandler(),
			ReadHeaderTimeout: 5 * time.Second,
		}
	}
	return nil
}

// Serve 阻塞服务直到 ctx 取消或监听出错；返回前完成优雅关停。
func (a *App) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer a.closing.Store(true)

	errCh := make(chan error, 2)
	running := 1
	go func() { errCh <- a.tunnel.Serve(ctx, a.tunnelLn) }()
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

// TunnelAddr 返回隧道监听地址。
func (a *App) TunnelAddr() string {
	if a.tunnelLn == nil {
		return ""
	}
	return a.tunnelLn.Addr().String()
}

// MetricsAddr 返回指标端点监听地址（未启用时为空）。
func (a *App) MetricsAddr() string {
	if a.metricsLn == nil {
		return ""
	}
	return a.metricsLn.Addr().String()
}

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

// healthChecks 返回依赖健康检查：TLS 证书在运行中过期时依赖不可用。
func (a *App) healthChecks() []func() error {
	return []func() error{func() error {
		if time.Now().Before(a.policy.load().certNotAfter) {
			return nil
		}
		return errors.New("tls certificate expired")
	}}
}

// Reload 应用一份新配置：先完整构建新运行时（证书重载、凭据重建、
// 伪装页重读），全部成功后再原子切换；任何失败都返回错误并保持旧配置
// 原样服务。监听地址属于启动时绑定的资源，变更需要重启，会被明确拒绝。
//
// 生效边界为“新连接”：已在转发的隧道继续使用旧快照；新握手立即使用
// 新凭据与新证书。
func (a *App) Reload(next *config.Server) (err error) {
	a.reloadMu.Lock()
	defer a.reloadMu.Unlock()
	if a.closing.Load() {
		return errors.New("serverapp: shutting down; reload ignored")
	}

	cur := a.policy.load()
	result := metrics.ReloadError
	defer func() { a.metrics.ConfigReload(result) }()

	if changed := config.ServerRestartOnlyChanges(cur.cfg, next); len(changed) > 0 {
		return fmt.Errorf("serverapp: %s changed: restart required (listen addresses cannot be rebound by hot reload)",
			strings.Join(changed, ", "))
	}
	rt, err := a.buildRuntime(next)
	if err != nil {
		return fmt.Errorf("serverapp: build new configuration: %w", err)
	}
	a.policy.snap.Store(rt)
	a.limiter.SetMax(next.Limits.EffectiveMaxConnections())
	if a.logCtrl != nil {
		a.logCtrl.SetLevel(next.Log.Level)
		a.logCtrl.SetFormat(next.Log.Format)
	}
	result = metrics.ReloadSuccess
	a.logger.Info("configuration reloaded",
		"users", len(next.Users),
		"max_connections", next.Limits.EffectiveMaxConnections(),
		"tls_cert_not_after", rt.certNotAfter.UTC().Format(time.RFC3339),
	)
	return nil
}

// ReloadFile 读取、校验并应用配置文件（path 与启动时相同）。
// levelOverride 是启动参数 -log-level 的显式覆盖，非空时同样优先于文件值。
// 解析 / 校验失败与构建失败一样保持旧配置继续服务，
// 并且每次尝试（无论失败在哪一步）都恰好计入一次 config_reloads_total。
func (a *App) ReloadFile(path, levelOverride string) error {
	cfg, err := config.LoadServer(path)
	if err != nil {
		a.metrics.ConfigReload(metrics.ReloadError)
		return err
	}
	if levelOverride != "" {
		cfg.Log.Level = levelOverride
	}
	return a.Reload(cfg)
}

// buildRuntime 依据配置构建完整运行时；任何失败都不产生外部副作用。
func (a *App) buildRuntime(cfg *config.Server) (*serverRuntime, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("serverapp: load tls key pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("serverapp: parse tls certificate: %w", err)
	}

	users := make([]auth.User, 0, len(cfg.Users))
	for _, u := range cfg.Users {
		users = append(users, auth.User{Username: u.Username, Password: u.Password})
	}
	store, err := auth.NewStore(users)
	if err != nil {
		return nil, err
	}

	decoy := trojan.DefaultDecoyPage
	if cfg.DecoyFile != "" {
		data, err := os.ReadFile(cfg.DecoyFile)
		if err != nil {
			return nil, fmt.Errorf("serverapp: read decoy file: %w", err)
		}
		if len(data) == 0 {
			return nil, errors.New("serverapp: decoy file is empty")
		}
		decoy = data
	}
	return &serverRuntime{
		cfg:          cfg,
		cert:         &cert,
		certNotAfter: leaf.NotAfter,
		verifier:     store,
		decoy:        decoy,
	}, nil
}

// runtimeStats 组装 /stats 快照：隧道活跃连接数。
func (a *App) runtimeStats() status.Runtime {
	tunnel := a.metrics.ActiveByProto()[metrics.ProtoTunnel]
	rt := status.Runtime{
		Connections: status.Connections{Tunnel: tunnel, Total: tunnel},
	}
	if a.limiter != nil {
		rt.Limit = &status.Limit{
			MaxConnections: a.limiter.Max(),
			Current:        a.limiter.Active(),
			Rejected:       a.limiter.Rejected(),
		}
	}
	return rt
}

// logTunnelReject 记录一次隧道侧超限拒绝（每秒最多一条，避免过载时刷日志）。
func (a *App) logTunnelReject(conn net.Conn) {
	now := time.Now()
	a.rejectMu.Lock()
	logNow := now.Sub(a.rejectLogAt) >= time.Second
	if logNow {
		a.rejectLogAt = now
	}
	a.rejectMu.Unlock()
	if logNow {
		a.logger.Warn("connection limit reached; rejecting tunnel connection",
			"remote", netutil.RemoteIP(conn.RemoteAddr()))
	}
}
