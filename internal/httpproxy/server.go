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
	"io"
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
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/logging"
	"github.com/OopsOo0ps/proxy/internal/netutil"
	"github.com/OopsOo0ps/proxy/internal/relay"
	"github.com/OopsOo0ps/proxy/internal/session"
	"github.com/OopsOo0ps/proxy/internal/shutdown"
)

// TargetDialer 建立到目标的连接（由路由与出口节点决定直连或经隧道）。
// 契约锚在消费方（core.TargetDialer）：本包不感知出站实现，组装根可以用
// 单个运行期适配器同时满足两边的策略接口（见 internal/clientapp 的 clientLive）。
type TargetDialer = core.TargetDialer

// LivePolicy 提供配置热加载后的动态策略。
// 为 nil 时使用 Server 的静态字段（测试与直接构造场景）。
type LivePolicy interface {
	// Auth 返回当前入站凭据校验能力；nil 表示不校验认证。
	Auth() core.Authenticator
	// Dialer 返回当前目标拨号器。
	Dialer() TargetDialer
	// IdleTimeout 返回隧道空闲回收超时。
	IdleTimeout() time.Duration
	// ReadHeaderTimeout 返回请求头读取超时。
	ReadHeaderTimeout() time.Duration
	// ShutdownTimeout 返回关停排空期限。
	ShutdownTimeout() time.Duration
}

// WriteOverloaded 对因连接上限被拒绝的连接写明确的 503 响应后关闭。
// 响应文案固定，不包含任何内部信息；写操作带 2s 期限，慢客户端不会卡住拒绝路径。
func WriteOverloaded(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	const body = "proxy overloaded: connection limit reached\n"
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.WriteString(conn, "HTTP/1.1 503 Service Unavailable\r\n"+
		"Content-Type: text/plain; charset=utf-8\r\n"+
		"Retry-After: 1\r\n"+
		"Content-Length: "+strconv.Itoa(len(body))+"\r\n"+
		"Connection: close\r\n\r\n"+body)
}

// Server 是 HTTP/HTTPS 正向代理服务。
type Server struct {
	// Auth 为 nil 时不校验认证（建议仅用于环回监听）。
	Auth *auth.Store
	// Dialer 建立到目标的连接（必填）。
	Dialer TargetDialer
	// Live 提供热加载后的动态策略；非 nil 时优先于上方静态字段。
	Live LivePolicy
	// Logger 日志；为 nil 时静默。
	Logger *slog.Logger
	// Telemetry 是遥测出口；nil 时使用 core.NopTelemetry。
	Telemetry core.Telemetry
	// IdleTimeout 隧道空闲回收，默认 90s。
	IdleTimeout time.Duration
	// ReadHeaderTimeout 请求头读取超时，默认 10s。
	ReadHeaderTimeout time.Duration
	// ShutdownTimeout 关停时等待存量请求结束的最长时间，默认 15s。
	ShutdownTimeout time.Duration

	handlerMu sync.Mutex
	handler   *handler // Serve 启动后写入；CloseIdleConnections 读取
}

// CloseIdleConnections 丢弃转发路径（绝对地址请求）的空闲上游连接。
// 用途：分流规则变化后，避免后续请求复用到旧路由建立的连接（生效边界=新连接，
// 在途请求不受影响）。未调用 Serve 或 Serve 尚未启动 handler 时为空操作。
func (s *Server) CloseIdleConnections() {
	if s == nil {
		return
	}
	s.handlerMu.Lock()
	h := s.handler
	s.handlerMu.Unlock()
	if h != nil {
		h.transport.CloseIdleConnections()
	}
}

// Serve 在 ln 上提供代理服务；ctx 取消后优雅关停：
// 先停止接受新连接，让存量请求在关停期限内自然结束，超时后强制断开。
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	// handlerCtx 与关停信号解耦：收到关停后存量请求继续执行，
	// 只有超过关停期限（forceCancel）才被打断。
	handlerCtx, forceCancel := context.WithCancel(context.WithoutCancel(ctx))
	defer forceCancel()

	h := newHandler(s)
	s.handlerMu.Lock()
	s.handler = h
	s.handlerMu.Unlock()
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
	// 不变量 6（路径权威）：转发路径也以 DialTarget 返回的 Route 为准，
	// 记录成功与失败两条路径（失败时 DialTarget 仍返回实际尝试的路径）。
	conn, route, err := h.srv.dialerNow().DialTarget(ctx, core.Target{Host: host, Port: uint16(port)})
	if rec, ok := ctx.Value(dialRecordKey{}).(*dialRecord); ok {
		rec.set(route)
	}
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqID := logging.NewRequestID()
	clientIP := netutil.RemoteIP(remoteAddrOf(r))
	logger := h.logger().With("request_id", reqID, "proto", core.ProtoHTTP, "client_ip", clientIP)
	tel := h.srv.telemetryNow()

	// accept（net/http 接受）后即计（active +1）；终态由 ConnDone / ConnRejected 配对回收。
	tel.ConnOpened(core.ProtoHTTP)

	if !h.authorize(w, r, logger) {
		// 未进入服务即被拒（认证失败）：按拒绝计，无路由维度。
		tel.ConnRejected(core.ProtoHTTP, core.ResultDenied)
		return
	}

	if r.Method == http.MethodConnect {
		h.serveConnect(w, r, logger, start, reqID, clientIP)
		return
	}
	h.serveForward(w, r, logger, start, reqID, clientIP)
}

// authorize 校验代理认证；失败时返回 407（固定文案，不泄露内部信息）。
func (h *handler) authorize(w http.ResponseWriter, r *http.Request, logger *slog.Logger) bool {
	store := h.srv.authNow()
	if store == nil {
		return true
	}
	username, password, ok := parseBasicAuth(r.Header.Get("Proxy-Authorization"))
	if !ok || !store.Authenticate(username, password) {
		logger.Warn("proxy authentication failed")
		w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return false
	}
	return true
}

// serveConnect 处理 CONNECT：拨号目标、回应 200 并双向转发。
func (h *handler) serveConnect(w http.ResponseWriter, r *http.Request, logger *slog.Logger, start time.Time, reqID, clientIP string) {
	tel := h.srv.telemetryNow()
	target := r.URL.Host
	if target == "" {
		target = r.Host
	}
	host, port, err := splitHostPortDefault(target, 443)
	if err != nil {
		logger.Warn("invalid CONNECT target", "target", target, "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		// 未发生拨号：按拒绝计，不伪造路由维度。
		tel.ConnRejected(core.ProtoHTTP, core.ResultError)
		return
	}
	reqTarget := core.Target{Host: host, Port: port}

	h.wg.Add(1)
	defer h.wg.Done()

	conn, route, err := h.srv.dialerNow().DialTarget(r.Context(), reqTarget)
	if err != nil {
		// 错误细节只进日志，对客户端统一 502。
		logger.Warn("dial target failed", "target", reqTarget.String(), "route", route.Action.String(), "error", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		tel.ConnDone(core.ConnAttrs{
			RequestID: reqID,
			ClientIP:  clientIP,
			Proto:     core.ProtoHTTP,
			Target:    reqTarget,
			Route:     route,
			Result:    core.ResultDialFail,
			Duration:  time.Since(start),
		})
		return
	}
	defer func() { _ = conn.Close() }()

	if route.Action == core.RouteReject {
		// 路由拒绝：按协议回明确拒绝，结果记 denied（Route 是权威判定）。
		logger.Warn("routing rejected target", "target", reqTarget.String())
		http.Error(w, "forbidden", http.StatusForbidden)
		tel.ConnDone(core.ConnAttrs{
			RequestID: reqID,
			ClientIP:  clientIP,
			Proto:     core.ProtoHTTP,
			Target:    reqTarget,
			Route:     route,
			Result:    core.ResultDenied,
			Duration:  time.Since(start),
		})
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		logger.Error("response writer does not support hijacking")
		http.Error(w, "internal error", http.StatusInternalServerError)
		tel.ConnDone(core.ConnAttrs{
			RequestID: reqID,
			ClientIP:  clientIP,
			Proto:     core.ProtoHTTP,
			Target:    reqTarget,
			Route:     route,
			Result:    core.ResultError,
			Duration:  time.Since(start),
		})
		return
	}
	clientConn, brw, err := hijacker.Hijack()
	if err != nil {
		logger.Error("hijack failed", "error", err)
		tel.ConnDone(core.ConnAttrs{
			RequestID: reqID,
			ClientIP:  clientIP,
			Proto:     core.ProtoHTTP,
			Target:    reqTarget,
			Route:     route,
			Result:    core.ResultError,
			Duration:  time.Since(start),
		})
		return
	}
	defer func() { _ = clientConn.Close() }()

	if _, err := brw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		logger.Debug("write connect response failed", "error", err)
		tel.ConnDone(core.ConnAttrs{
			RequestID: reqID,
			ClientIP:  clientIP,
			Proto:     core.ProtoHTTP,
			Target:    reqTarget,
			Route:     route,
			Result:    core.ResultError,
			Duration:  time.Since(start),
		})
		return
	}
	if err := brw.Flush(); err != nil {
		logger.Debug("flush connect response failed", "error", err)
		tel.ConnDone(core.ConnAttrs{
			RequestID: reqID,
			ClientIP:  clientIP,
			Proto:     core.ProtoHTTP,
			Target:    reqTarget,
			Route:     route,
			Result:    core.ResultError,
			Duration:  time.Since(start),
		})
		return
	}

	// 客户端可能在发送 CONNECT 后立即发送载荷（如 TLS ClientHello），
	// 这些字节可能已被 bufio 预读，必须通过 PrefixConn 原样转发。
	stats, relayErr := relay.BiCopy(r.Context(), relay.PrefixConn(clientConn, brw.Reader), conn, h.srv.idleTimeout())
	result := core.ResultOK
	if relay.IsFailure(relayErr) {
		result = core.ResultError
	}
	elapsed := time.Since(start)
	label := route.Label
	if label == "" {
		label = route.Action.String()
	}
	attrs := append([]any{
		"method", "CONNECT",
		"target", reqTarget.String(),
		"route", route.Action.String(),
		"upstream", label,
	}, session.RelayAttrs(elapsed, stats.ClientToUpstream, stats.UpstreamToClient, result, relayErr)...)
	logger.Info("request completed", attrs...)
	tel.ConnDone(core.ConnAttrs{
		RequestID: reqID,
		ClientIP:  clientIP,
		Proto:     core.ProtoHTTP,
		Target:    reqTarget,
		Route:     route,
		Result:    result,
		Duration:  elapsed,
		BytesUp:   stats.ClientToUpstream,
		BytesDown: stats.UpstreamToClient,
	})
}

// serveForward 处理绝对地址形式的普通 HTTP 请求。
func (h *handler) serveForward(w http.ResponseWriter, r *http.Request, logger *slog.Logger, start time.Time, reqID, clientIP string) {
	tel := h.srv.telemetryNow()
	if !r.URL.IsAbs() || r.URL.Host == "" || r.URL.Scheme != "http" {
		logger.Warn("rejecting unsupported request form", "method", r.Method, "url", r.URL.String())
		http.Error(w, "bad request", http.StatusBadRequest)
		// 未发生拨号：按拒绝计，不伪造路由维度。
		tel.ConnRejected(core.ProtoHTTP, core.ResultError)
		return
	}
	rec := &dialRecord{}
	ctx := logging.WithRequestID(context.WithValue(r.Context(), dialRecordKey{}, rec), reqID)

	sw := &statusRecorder{ResponseWriter: w}
	h.proxy.ServeHTTP(sw, r.WithContext(ctx))

	result := core.ResultOK
	if sw.status >= http.StatusInternalServerError {
		result = core.ResultError
	}
	elapsed := time.Since(start)
	route, dialed := rec.get()
	if !dialed {
		// 本次请求未触发拨号：上游连接为既有连接复用（或拨号前置校验失败），
		// 单条请求实际走过的路径不可判定——按规范“池选择未定”的词汇标记
		//（Route{Proxy, "pool"}），不预判、不把未知伪造成真实直连/代理路径。
		route = core.Route{Action: core.RouteProxy, Label: "pool"}
	}
	logger.Info("request completed",
		"method", r.Method,
		"target", r.URL.Host,
		"route", obsRouteLabel(route),
		"upstream", obsUpstreamLabel(route),
		"status", sw.code(),
		"duration", elapsed.Round(time.Microsecond).String(),
		"duration_ms", elapsed.Milliseconds(),
		"result", result,
	)
	tel.ConnDone(core.ConnAttrs{
		RequestID: reqID,
		ClientIP:  clientIP,
		Proto:     core.ProtoHTTP,
		Target:    core.Target{Host: r.URL.Hostname()},
		Route:     route,
		Result:    result,
		Duration:  elapsed,
	})
}

// obsRouteLabel 返回观测用的 route 词汇：Label 为 "pool"（池选择未定）
// 时原样使用，其余取动作的观测写法。与 metrics 的 requests_total 口径一致。
func obsRouteLabel(r core.Route) string {
	if r.Label == "pool" {
		return "pool"
	}
	return r.Action.String()
}

// obsUpstreamLabel 返回日志的 upstream 字段：有出口标签用标签，
// 直连无标签时回退动作写法（"direct"）。
func obsUpstreamLabel(r core.Route) string {
	if r.Label != "" {
		return r.Label
	}
	return r.Action.String()
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

// dialRecord 记录转发请求实际走过的权威路径（不变量 6：来自 DialTarget
// 的返回值，供日志与遥测使用；未发生拨号时保持未记录）。
type dialRecord struct {
	mu     sync.Mutex
	route  core.Route
	dialed bool
}

func (rec *dialRecord) set(route core.Route) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.route, rec.dialed = route, true
}

func (rec *dialRecord) get() (core.Route, bool) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return rec.route, rec.dialed
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

// authNow 返回当前生效的凭据校验能力：Live 存在时以热加载快照为准；
// nil 表示不校验认证。nil 的 *auth.Store 必须显式转成 nil 接口，
// 否则装进接口后 != nil 会被误判为“启用认证”。
func (s *Server) authNow() core.Authenticator {
	if s.Live != nil {
		return s.Live.Auth()
	}
	if s.Auth == nil {
		return nil
	}
	return s.Auth
}

// dialerNow 返回当前生效的目标拨号器：Live 存在时以热加载快照为准。
func (s *Server) dialerNow() TargetDialer {
	if s.Live != nil {
		return s.Live.Dialer()
	}
	return s.Dialer
}

func (s *Server) readHeaderTimeout() time.Duration {
	if s.Live != nil {
		return s.Live.ReadHeaderTimeout()
	}
	if s.ReadHeaderTimeout <= 0 {
		return 10 * time.Second
	}
	return s.ReadHeaderTimeout
}

func (s *Server) shutdownTimeout() time.Duration {
	if s.Live != nil {
		return s.Live.ShutdownTimeout()
	}
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

// telemetryNow 返回当前遥测出口；未配置时使用 Nop（组件测试零构造）。
func (s *Server) telemetryNow() core.Telemetry {
	if s.Telemetry == nil {
		return core.NopTelemetry
	}
	return s.Telemetry
}

func (s *Server) idleTimeout() time.Duration {
	if s.Live != nil {
		return s.Live.IdleTimeout()
	}
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
