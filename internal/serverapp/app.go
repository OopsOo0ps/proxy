// Package serverapp 组装 proxy-server：TLS 隧道监听、凭据校验、出口直连与指标端点。
package serverapp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/metrics"
	"github.com/OopsOo0ps/proxy/internal/trojan"
)

// App 是组装完成的 proxy-server 实例。
// 生命周期：New → Listen（绑定端口）→ Serve（阻塞服务直到 ctx 取消）。
type App struct {
	cfg     *config.Server
	logger  *slog.Logger
	metrics *metrics.Metrics
	tunnel  *trojan.Server
	tlsCfg  *tls.Config

	tunnelLn   net.Listener
	metricsSrv *http.Server
	metricsLn  net.Listener
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
		cfg:     cfg,
		logger:  logger,
		metrics: metrics.New(),
		tlsCfg: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}
	app.tunnel = &trojan.Server{
		Verifier: store,
		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
			return netDialer.DialContext(ctx, "tcp", addr)
		},
		Decoy:            decoy,
		HandshakeTimeout: cfg.Timeouts.Handshake.Std(),
		DialTimeout:      cfg.Timeouts.Dial.Std(),
		IdleTimeout:      cfg.Timeouts.Idle.Std(),
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
	return mux
}
