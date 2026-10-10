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
	"sync"
	"time"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/connlimit"
	"github.com/OopsOo0ps/proxy/internal/metrics"
	"github.com/OopsOo0ps/proxy/internal/netutil"
	"github.com/OopsOo0ps/proxy/internal/status"
	"github.com/OopsOo0ps/proxy/internal/trojan"
	"github.com/OopsOo0ps/proxy/pkg/version"
)

// App 是组装完成的 proxy-server 实例。
// 生命周期：New → Listen（绑定端口）→ Serve（阻塞服务直到 ctx 取消）。
type App struct {
	cfg     *config.Server
	logger  *slog.Logger
	metrics *metrics.Metrics
	tunnel  *trojan.Server
	tlsCfg  *tls.Config
	status  *status.Status
	limiter *connlimit.Limiter

	certNotAfter time.Time
	tunnelLn     net.Listener
	metricsSrv   *http.Server
	metricsLn    net.Listener

	rejectMu    sync.Mutex
	rejectLogAt time.Time
}

// New 加载证书与凭据并组装应用（不绑定端口）。
func New(cfg *config.Server, logger *slog.Logger) (*App, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

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

	netDialer := &net.Dialer{Timeout: cfg.Timeouts.Dial.Std()}
	app := &App{
		cfg:          cfg,
		logger:       logger,
		metrics:      metrics.New(),
		certNotAfter: leaf.NotAfter,
		tlsCfg: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}
	app.limiter = connlimit.New(cfg.Limits.EffectiveMaxConnections())
	app.status = status.New(status.Options{
		Version: version.Get().Version,
		Checks:  app.healthChecks(),
		Runtime: app.runtimeStats,
	})
	app.tunnel = &trojan.Server{
		Verifier: store,
		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
			return netDialer.DialContext(ctx, "tcp", addr)
		},
		Decoy:            decoy,
		HandshakeTimeout: cfg.Timeouts.Handshake.Std(),
		DialTimeout:      cfg.Timeouts.Dial.Std(),
		IdleTimeout:      cfg.Timeouts.Idle.Std(),
		ShutdownTimeout:  cfg.Timeouts.Shutdown.Std(),
		Logger:           logger,
		Metrics:          app.metrics,
	}
	return app, nil
}

// Listen 绑定隧道与指标端口。
func (a *App) Listen() error {
	ln, err := net.Listen("tcp", a.cfg.Listen)
	if err != nil {
		return fmt.Errorf("serverapp: listen %s: %w", a.cfg.Listen, err)
	}
	ln = connlimit.WrapListener(ln, a.limiter, func(conn net.Conn) {
		a.metrics.ConnRejected(metrics.ProtoTunnel)
		a.logTunnelReject(conn)
		_ = conn.Close()
	})
	a.tunnelLn = tls.NewListener(ln, a.tlsCfg)

	if addr := a.cfg.Metrics.Listen; addr != "" {
		metricsLn, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("serverapp: listen metrics %s: %w", addr, err)
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
	return mux
}

// healthChecks 返回依赖健康检查：TLS 证书在运行中过期时依赖不可用。
func (a *App) healthChecks() []func() error {
	return []func() error{func() error {
		if time.Now().Before(a.certNotAfter) {
			return nil
		}
		return errors.New("tls certificate expired")
	}}
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
