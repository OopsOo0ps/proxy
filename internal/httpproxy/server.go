// Package httpproxy 实现 HTTP/HTTPS 入站正向代理：
//   - CONNECT 方法：建立 TCP 隧道（HTTPS 及其它 TLS 流量的标准路径）
//   - 绝对地址请求（GET http://...）：经 Transport 转发
//
// 支持代理认证（Proxy-Authorization: Basic），认证失败返回标准 407，
// 响应体固定且不包含任何内部信息。
package httpproxy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/dialer"
	"github.com/OopsOo0ps/proxy/internal/logging"
	"github.com/OopsOo0ps/proxy/internal/metrics"
	"github.com/OopsOo0ps/proxy/internal/netutil"
	"github.com/OopsOo0ps/proxy/internal/relay"
	"github.com/OopsOo0ps/proxy/internal/routing"
	"github.com/OopsOo0ps/proxy/internal/shutdown"
)

// TargetDialer 建立到目标的连接（由路由与出口节点决定直连或经隧道）。
type TargetDialer interface {
	DialTarget(ctx context.Context, host string, port uint16) (net.Conn, dialer.Route, error)
	RouteFor(host string) routing.Action
}

// Server 是 HTTP/HTTPS 正向代理服务。
type Server struct {
	// Auth 为 nil 时不校验认证（建议仅用于环回监听）。
	Auth *auth.Store
	// Dialer 建立到目标的连接（必填）。
	Dialer TargetDialer
	// Logger 日志；为 nil 时静默。
	Logger *slog.Logger
	// Metrics 指标；可为 nil。
	Metrics *metrics.Metrics
	// IdleTimeout 隧道空闲回收，默认 90s。
	IdleTimeout time.Duration
	// ReadHeaderTimeout 请求头读取超时，默认 10s。
	ReadHeaderTimeout time.Duration
	// ShutdownTimeout 关停时等待存量请求结束的最长时间，默认 15s。
	ShutdownTimeout time.Duration
}

// Serve 在 ln 上提供代理服务；ctx 取消后优雅关停：
// 先停止接受新连接，让存量请求在关停期限内自然结束，超时后强制断开。
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	// handlerCtx 与关停信号解耦：收到关停后存量请求继续执行，
	// 只有超过关停期限（forceCancel）才被打断。
	handlerCtx, forceCancel := context.WithCancel(context.WithoutCancel(ctx))
	defer forceCancel()

	h := newHandler(s)
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: s.readHeaderTimeout(),
		BaseContext:       func(net.Listener) context.Context { return handlerCtx },
	}

	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- srv.Serve(ln) }()

	var serveErr error
	select {
	case serveErr = <-serveErrCh:
	case <-ctx.Done():
		s.logger().Info("shutdown: stopped accepting new connections",
			"drain_timeout", s.shutdownTimeout().String())
		deadline := time.Now().Add(s.shutdownTimeout())
		// 普通请求（非 CONNECT）由 net/http 排空；期限用尽时强制关闭。
		shutdownCtx, cancel := context.WithDeadline(context.Background(), deadline)
		if err := srv.Shutdown(shutdownCtx); err != nil {
			_ = srv.Close()
		}
		cancel()
		// CONNECT 隧道已被 Hijack，net/http 不再跟踪，需要自行等待排空。
		if shutdown.Wait(&h.wg, time.Until(deadline), forceCancel) {
			s.logger().Info("shutdown: all in-flight connections drained")
		} else {
			s.logger().Warn("shutdown: timeout exceeded, remaining connections closed")
		}
		serveErr = <-serveErrCh
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil
	}
	h.transport.CloseIdleConnections() // 释放池化的隧道连接
	return serveErr
}

type handler struct {
	srv       *Server
	transport *http.Transport
	proxy     *httputil.ReverseProxy
	wg        sync.WaitGroup
}

func newHandler(s *Server) *handler {
	h := &handler{srv: s}
	h.transport = &http.Transport{
		DialContext:           h.dialContext,
		MaxIdleConns:          64,
		IdleConnTimeout:       60 * time.Second,
		DisableCompression:    true, // 代理不做内容解压，保持透传语义
		ExpectContinueTimeout: time.Second,
	}
	h.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = pr.In.URL.Host
			pr.Out.Host = pr.In.URL.Host
			// 双重保险：绝不把代理凭据转发给目标站点。
			pr.Out.Header.Del("Proxy-Authorization")
			pr.Out.Header.Del("Proxy-Connection")
		},
		Transport:     h.transport,
		ErrorHandler:  h.onUpstreamError,
		FlushInterval: 100 * time.Millisecond,
	}
	return h
}

func (h *handler) dialContext(ctx context.Context, _, addr string) (net.Conn, error) {
	host, portString, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("httpproxy: invalid port %q", portString)
	}
	conn, route, err := h.srv.Dialer.DialTarget(ctx, host, uint16(port))
	if err != nil {
		return nil, err
	}
	if rec, ok := ctx.Value(dialRecordKey{}).(*dialRecord); ok {
		rec.set(route.Upstream)
	}
	return conn, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqID := logging.NewRequestID()
	logger := h.logger().With("request_id", reqID, "proto", "http", "client_ip", netutil.RemoteIP(remoteAddrOf(r)))

	if !h.authorize(w, r, logger) {
		h.srv.Metrics.Observe(metrics.ProtoHTTP, metrics.RouteNone, metrics.ResultAuthFail, time.Since(start))
		return
	}

	if r.Method == http.MethodConnect {
		h.serveConnect(w, r, logger, start)
		return
	}
	h.serveForward(w, r, logger, start, reqID)
}

// authorize 校验代理认证；失败时返回 407（固定文案，不泄露内部信息）。
func (h *handler) authorize(w http.ResponseWriter, r *http.Request, logger *slog.Logger) bool {
	if h.srv.Auth == nil {
		return true
	}
	username, password, ok := parseBasicAuth(r.Header.Get("Proxy-Authorization"))
	if !ok || !h.srv.Auth.Verify(username, password) {
		logger.Warn("proxy authentication failed")
		w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return false
	}
	return true
}

// serveConnect 处理 CONNECT：拨号目标、回应 200 并双向转发。
func (h *handler) serveConnect(w http.ResponseWriter, r *http.Request, logger *slog.Logger, start time.Time) {
	target := r.URL.Host
	if target == "" {
		target = r.Host
	}
	host, port, err := splitHostPortDefault(target, 443)
	if err != nil {
		logger.Warn("invalid CONNECT target", "target", target, "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		h.srv.Metrics.Observe(metrics.ProtoHTTP, metrics.RouteNone, metrics.ResultError, time.Since(start))
		return
	}
	target = net.JoinHostPort(host, strconv.Itoa(int(port)))

	h.wg.Add(1)
	defer h.wg.Done()
	h.srv.Metrics.ConnOpened(metrics.ProtoHTTP)
	defer h.srv.Metrics.ConnClosed(metrics.ProtoHTTP)

	conn, route, err := h.srv.Dialer.DialTarget(r.Context(), host, port)
	if err != nil {
		// 错误细节只进日志，对客户端统一 502。
		logger.Warn("dial target failed", "target", target, "error", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		h.srv.Metrics.Observe(metrics.ProtoHTTP, route.Action.String(), metrics.ResultDialFail, time.Since(start))
		return
	}
	defer func() { _ = conn.Close() }()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		logger.Error("response writer does not support hijacking")
		http.Error(w, "internal error", http.StatusInternalServerError)
		h.srv.Metrics.Observe(metrics.ProtoHTTP, route.Action.String(), metrics.ResultError, time.Since(start))
		return
	}
	clientConn, brw, err := hijacker.Hijack()
	if err != nil {
		logger.Error("hijack failed", "error", err)
		h.srv.Metrics.Observe(metrics.ProtoHTTP, route.Action.String(), metrics.ResultError, time.Since(start))
		return
	}
	defer func() { _ = clientConn.Close() }()

	if _, err := brw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		logger.Debug("write connect response failed", "error", err)
		return
	}
	if err := brw.Flush(); err != nil {
		logger.Debug("flush connect response failed", "error", err)
		return
	}

	// 客户端可能在发送 CONNECT 后立即发送载荷（如 TLS ClientHello），
	// 这些字节可能已被 bufio 预读，必须通过 PrefixConn 原样转发。
	stats, relayErr := relay.BiCopy(r.Context(), relay.PrefixConn(clientConn, brw.Reader), conn, h.srv.idleTimeout())
	result := metrics.ResultOK
	if !relay.IsExpected(relayErr) {
		result = metrics.ResultError
	}
	elapsed := time.Since(start)
	logger.Info("request completed",
		"method", "CONNECT",
		"target", target,
		"route", route.Action.String(),
		"upstream", route.Label(),
		"duration", elapsed.Round(time.Microsecond).String(),
		"duration_ms", elapsed.Milliseconds(),
		"bytes_up", stats.ClientToUpstream,
		"bytes_down", stats.UpstreamToClient,
		"result", result,
	)
	h.srv.Metrics.Observe(metrics.ProtoHTTP, route.Action.String(), result, elapsed)
}

// serveForward 处理绝对地址形式的普通 HTTP 请求。
func (h *handler) serveForward(w http.ResponseWriter, r *http.Request, logger *slog.Logger, start time.Time, reqID string) {
	if !r.URL.IsAbs() || r.URL.Host == "" || r.URL.Scheme != "http" {
		logger.Warn("rejecting unsupported request form", "method", r.Method, "url", r.URL.String())
		http.Error(w, "bad request", http.StatusBadRequest)
		h.srv.Metrics.Observe(metrics.ProtoHTTP, metrics.RouteNone, metrics.ResultError, time.Since(start))
		return
	}
	route := h.srv.Dialer.RouteFor(r.URL.Hostname())
	rec := &dialRecord{}
	ctx := logging.WithRequestID(context.WithValue(r.Context(), dialRecordKey{}, rec), reqID)

	sw := &statusRecorder{ResponseWriter: w}
	h.proxy.ServeHTTP(sw, r.WithContext(ctx))

	result := metrics.ResultOK
	if sw.status >= http.StatusInternalServerError {
		result = metrics.ResultError
	}
	elapsed := time.Since(start)
	logger.Info("request completed",
		"method", r.Method,
		"target", r.URL.Host,
		"route", route.String(),
		"upstream", rec.label(route),
		"status", sw.code(),
		"duration", elapsed.Round(time.Microsecond).String(),
		"duration_ms", elapsed.Milliseconds(),
		"result", result,
	)
	h.srv.Metrics.Observe(metrics.ProtoHTTP, route.String(), result, elapsed)
}

// onUpstreamError 处理 Transport 层的错误：对客户端统一 502，日志保留细节。
func (h *handler) onUpstreamError(w http.ResponseWriter, r *http.Request, err error) {
	logger := h.logger().With(
		"request_id", logging.RequestIDFrom(r.Context()),
		"proto", "http",
		"client_ip", netutil.RemoteIP(remoteAddrOf(r)),
	)
	logger.Warn("upstream error", "target", r.URL.Host, "error", err)
	w.WriteHeader(http.StatusBadGateway)
	_, _ = w.Write([]byte("bad gateway\n"))
}

// dialRecord 记录请求实际命中的出口节点（供转发路径日志使用）。
type dialRecord struct {
	mu       sync.Mutex
	upstream string
}

func (rec *dialRecord) set(upstream string) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.upstream = upstream
}

// label 返回 upstream 日志字段：命中节点地址，直连为 "direct"，
// 连接池复用无法得知具体节点时返回 "pool"。
func (rec *dialRecord) label(action routing.Action) string {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.upstream != "" {
		return rec.upstream
	}
	if action == routing.Proxy {
		return "pool"
	}
	return "direct"
}

type dialRecordKey struct{}

// statusRecorder 包装 ResponseWriter 以捕获响应状态码。
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// Unwrap 让 http.ResponseController 能访问底层 Writer（Flush 等）。
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *statusRecorder) code() int {
	if s.status == 0 {
		return http.StatusOK
	}
	return s.status
}

// parseBasicAuth 解析 "Basic base64(user:pass)" 形式。
func parseBasicAuth(header string) (username, password string, ok bool) {
	const prefix = "basic "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	user, pass, found := strings.Cut(string(decoded), ":")
	if !found {
		return "", "", false
	}
	return user, pass, true
}

// splitHostPortDefault 解析 "host[:port]"；无端口时使用默认端口。
// 兼容 CONNECT 中的 IPv6 字面量："[::1]:443"、"::1"。
func splitHostPortDefault(hostport string, defaultPort uint16) (string, uint16, error) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return "", 0, errors.New("httpproxy: empty target")
	}
	if host, portString, err := net.SplitHostPort(hostport); err == nil {
		if portString == "" {
			return host, defaultPort, nil
		}
		port, err := strconv.ParseUint(portString, 10, 16)
		if err != nil || port == 0 {
			return "", 0, fmt.Errorf("httpproxy: invalid port %q", portString)
		}
		return host, uint16(port), nil
	}
	host := strings.Trim(hostport, "[]")
	if host == "" || strings.ContainsAny(host, " \t") {
		return "", 0, fmt.Errorf("httpproxy: invalid target %q", hostport)
	}
	if strings.Contains(host, ":") {
		if _, err := netip.ParseAddr(host); err != nil {
			return "", 0, fmt.Errorf("httpproxy: invalid target %q", hostport)
		}
	}
	return host, defaultPort, nil
}

func (h *handler) logger() *slog.Logger {
	if h.srv.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return h.srv.Logger
}

func (s *Server) readHeaderTimeout() time.Duration {
	if s.ReadHeaderTimeout <= 0 {
		return 10 * time.Second
	}
	return s.ReadHeaderTimeout
}

func (s *Server) shutdownTimeout() time.Duration {
	if s.ShutdownTimeout <= 0 {
		return shutdown.DefaultTimeout
	}
	return s.ShutdownTimeout
}

func (s *Server) logger() *slog.Logger {
	if s.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return s.Logger
}

func (s *Server) idleTimeout() time.Duration {
	if s.IdleTimeout <= 0 {
		return 90 * time.Second
	}
	return s.IdleTimeout
}

func remoteAddrOf(r *http.Request) net.Addr {
	if r == nil || r.RemoteAddr == "" {
		return nil
	}
	return addrString(r.RemoteAddr)
}

// addrString 把 net/http 的字符串地址适配为 net.Addr。
type addrString string

func (a addrString) Network() string { return "tcp" }
func (a addrString) String() string  { return string(a) }
