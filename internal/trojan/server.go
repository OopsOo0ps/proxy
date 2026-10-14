package trojan

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/defaults"
	"github.com/OopsOo0ps/proxy/internal/logging"
	"github.com/OopsOo0ps/proxy/internal/netutil"
	"github.com/OopsOo0ps/proxy/internal/relay"
	"github.com/OopsOo0ps/proxy/internal/session"
	"github.com/OopsOo0ps/proxy/internal/sockswire"
	"github.com/OopsOo0ps/proxy/internal/throttle"
)

// DefaultDecoyPage 是认证失败/非协议流量时返回的伪装页面。
// 内容刻意保持中性，不暴露代理的存在与任何配置信息。
var DefaultDecoyPage = []byte(`<!DOCTYPE html>
<html>
<head><title>Welcome</title></head>
<body><h1>It works!</h1><p>This server is up and running.</p></body>
</html>
`)

// Verifier 校验隧道口令摘要并返回匹配的用户名。
type Verifier interface {
	VerifyTunnel(hashHex string) (string, bool)
}

// LivePolicy 提供配置热加载后的动态策略。
// 为 nil 时使用 Server 的静态字段（测试与直接构造场景）。
type LivePolicy interface {
	// Verifier 返回当前口令校验器。
	Verifier() Verifier
	// Decoy 返回当前伪装页面；为空时使用 DefaultDecoyPage。
	Decoy() []byte
	// HandshakeTimeout 返回握手超时。
	HandshakeTimeout() time.Duration
	// DialTimeout 返回目标连接超时。
	DialTimeout() time.Duration
	// IdleTimeout 返回连接空闲回收超时。
	IdleTimeout() time.Duration
	// ShutdownTimeout 返回关停排空期限。
	ShutdownTimeout() time.Duration
}

// Server 是 Trojan 隧道服务端。
type Server struct {
	// Verifier 口令校验（必填）。
	Verifier Verifier
	// Dial 把解析出的目标接到对端字节流（必填）：服务端即出口，组合树的
	// direct 剪枝就是本字段（§5.3）——组装根注入共享的直连拨号器，
	// 返回的 Route 是权威路径（直连恒为 Route{Direct}）。
	Dial core.TargetDialer
	// Decoy 伪装页面；为空时使用 DefaultDecoyPage。
	Decoy []byte
	// Live 提供热加载后的动态策略；非 nil 时优先于上方静态字段。
	Live LivePolicy
	// HandshakeTimeout 握手超时，默认 defaults.HandshakeTimeout。
	HandshakeTimeout time.Duration
	// DialTimeout 目标连接超时，默认 defaults.DialTimeout。
	DialTimeout time.Duration
	// IdleTimeout 连接空闲回收，默认 defaults.IdleTimeout。
	IdleTimeout time.Duration
	// ShutdownTimeout 关停时等待存量隧道结束的最长时间，默认 defaults.DrainTimeout。
	ShutdownTimeout time.Duration
	// Logger 日志；为 nil 时静默。
	Logger *slog.Logger
	// Telemetry 是遥测出口；nil 时使用 core.NopTelemetry。
	Telemetry core.Telemetry
	// Throttle 是认证失败的按 IP 指数退避器；nil = 使用包级默认实例
	//（100ms 起、2s 封顶、容量 4096），开箱即用；测试可注入自定义实例。
	Throttle *throttle.IPThrottle
}

// defaultThrottle 是缺省的认证退避器（nil Throttle 时共用）。
var defaultThrottle = throttle.NewDefaultIPThrottle()

// throttleNow 返回生效的退避器（Throttle 优先，缺省默认实例）。
func (s *Server) throttleNow() *throttle.IPThrottle {
	if s.Throttle != nil {
		return s.Throttle
	}
	return defaultThrottle
}

// backoff 记录一次认证失败并按返回时长有界睡眠（d = 0 时不等待）。
func (s *Server) backoff(ip string) {
	if d := s.throttleNow().Delay(ip); d > 0 {
		time.Sleep(d)
	}
}

// Serve 在 ln 上接受并处理隧道连接；ctx 取消后优雅关停：
// 先停止接受新连接，让已在转发的隧道在关停期限内自然结束，超时后强制断开。
// accept/drain 机械部分委托 internal/session（与 socks5 共用同一实现），
// 本包实现 session.ConnHandler 提供协议逻辑。
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	return session.Serve(ctx, ln, tunnelHandler{srv: s, serveCtx: ctx}, session.Options{
		Logger:         s.Logger,
		DrainTimeout:   s.shutdownTimeout,
		DrainedMessage: "shutdown: all in-flight tunnels drained",
	})
}

// tunnelHandler 是隧道服务端的 session.ConnHandler：捕获 serveCtx，
// 让握手阶段的阻塞读取对关停立即敏感（存量已握手连接仍按排空期限处理）。
type tunnelHandler struct {
	srv      *Server
	serveCtx context.Context
}

// ServeConn 处理一条已接受的连接（session.ConnHandler）：握手 → 认证 →
// 拨号 → relay；拒绝路径与遥测事件发射都在这里。
// connCtx 承载强制断开期限（排空超时后被取消）。
func (h tunnelHandler) ServeConn(connCtx context.Context, conn net.Conn) {
	h.srv.handle(h.serveCtx, connCtx, conn)
}

func (s *Server) handle(ctx, connCtx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	start := time.Now()
	reqID := logging.NewRequestID()
	clientIP := netutil.RemoteIP(conn.RemoteAddr())
	logger := s.logger().With("request_id", reqID, "proto", core.ProtoTunnel, "client_ip", clientIP)
	tel := s.telemetryNow()

	// accept 后即计（active +1）；终态由 ConnDone / ConnRejected 配对回收。
	tel.ConnOpened(core.ProtoTunnel)

	_ = conn.SetDeadline(time.Now().Add(s.handshakeTimeout()))
	// 握手阶段对关停取消敏感：服务端关停时立即打断阻塞中的读取。
	// 客户端连接池会持有"已握手、待发送请求"的预热连接，等待它们
	// 自然超时会让优雅退出拖满一个握手超时；这类连接没有在途请求，
	// 直接关闭不丢任何数据。
	stopHandshakeWatch := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stopHandshakeWatch()
	br := bufio.NewReader(conn)

	req, err := ReadRequest(br)
	if err != nil {
		if ctx.Err() != nil {
			// 关停中断：不再回放伪装页面，直接退出（未进入服务，按拒绝计）。
			tel.ConnRejected(core.ProtoTunnel, core.ResultError)
			return
		}
		if IsNotProtocol(err) {
			// 非 Trojan 流量（例如浏览器直接访问）：伪装成普通 Web 服务。
			logger.Debug("non-protocol traffic, serving decoy", "error", err)
		} else {
			logger.Debug("handshake failed", "error", err)
		}
		s.serveDecoy(conn)
		// 未进入服务即被拒（认证/协议失败）：按拒绝计，无路由维度。
		tel.ConnRejected(core.ProtoTunnel, core.ResultDenied)
		return
	}
	stopHandshakeWatch()

	// 超过关停期限（forceCancel）时打断尚未进入转发的连接（如拨号中）。
	stopForce := context.AfterFunc(connCtx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stopForce()

	user, ok := s.verifierNow().VerifyTunnel(req.PasswordHash)
	if !ok {
		logger.Warn("tunnel authentication failed")
		// 认证失败：按 IP 指数退避（有界）后再回伪装页面，抑制口令爆破；
		// 伪装页面语义保持不变（与正常 Web 服务的时序差异被 2s 封顶约束）。
		s.backoff(clientIP)
		s.serveDecoy(conn)
		tel.ConnRejected(core.ProtoTunnel, core.ResultDenied)
		return
	}
	// 认证成功：清除该来源 IP 的失败记录（退避从头计）。
	s.throttleNow().Success(clientIP)
	if req.Command != sockswire.CmdConnect {
		// UDP ASSOCIATE 等命令暂不支持：直接关闭并记录。
		logger.Warn("unsupported tunnel command", "command", req.Command)
		tel.ConnRejected(core.ProtoTunnel, core.ResultError)
		return
	}

	target := core.Target{Host: req.Host, Port: req.Port}
	// 服务端即出口：出站是组装根注入的直连拨号器（组合树 direct 剪枝），
	// DialTarget 返回的 Route 是权威路径（直连恒为 Route{Direct}，无出口标签）。
	dialCtx, cancel := context.WithTimeout(connCtx, s.dialTimeout())
	defer cancel()
	upstream, route, err := s.dialNow().DialTarget(dialCtx, target)
	if err != nil {
		// 与官方行为一致：目标不可达时静默关闭，不做区分响应。
		logger.Warn("dial target failed", "target", target.String(), "error", err)
		tel.ConnDone(core.ConnAttrs{
			RequestID: reqID,
			ClientIP:  clientIP,
			Proto:     core.ProtoTunnel,
			Target:    target,
			Route:     route,
			Result:    core.ResultDialFail,
			Duration:  time.Since(start),
		})
		return
	}
	defer func() { _ = upstream.Close() }()

	_ = conn.SetDeadline(time.Time{})
	clientConn := relay.PrefixConn(conn, br)
	stats, relayErr := relay.BiCopy(connCtx, clientConn, upstream, s.idleTimeout())
	result := core.ResultOK
	if relay.IsFailure(relayErr) {
		result = core.ResultError
	}
	elapsed := time.Since(start)
	attrs := append([]any{
		"user", user,
		"target", target.String(),
		"route", route.Action.String(),
		"upstream", target.String(),
	}, session.RelayAttrs(elapsed, stats.ClientToUpstream, stats.UpstreamToClient, result, relayErr)...)
	logger.Info("tunnel completed", attrs...)
	tel.ConnDone(core.ConnAttrs{
		RequestID: reqID,
		ClientIP:  clientIP,
		Proto:     core.ProtoTunnel,
		Target:    target,
		Route:     route,
		Result:    result,
		Duration:  elapsed,
		BytesUp:   stats.ClientToUpstream,
		BytesDown: stats.UpstreamToClient,
	})
}

// serveDecoy 写出伪装网页并优雅关闭，避免 RST 截断响应。
func (s *Server) serveDecoy(conn net.Conn) {
	// 握手阶段可能已经触发超时，写入前先重置整体期限，保证响应完整送出。
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	page := s.decoyNow()
	if len(page) == 0 {
		page = DefaultDecoyPage
	}
	header := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(page))
	if _, err := io.WriteString(conn, header); err != nil {
		return
	}
	if _, err := conn.Write(page); err != nil {
		return
	}
	// 短暂排空对端后续数据，避免带未读数据的 close 触发 RST。
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, _ = io.CopyN(io.Discard, conn, 16*1024)
	// 为随后的 graceful close（TLS close_notify）留出写期限。
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
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

// verifierNow 返回当前生效的口令校验器：Live 存在时以热加载快照为准。
func (s *Server) verifierNow() Verifier {
	if s.Live != nil {
		return s.Live.Verifier()
	}
	return s.Verifier
}

// decoyNow 返回当前生效的伪装页面：Live 存在时以热加载快照为准。
func (s *Server) decoyNow() []byte {
	if s.Live != nil {
		return s.Live.Decoy()
	}
	return s.Decoy
}

// dialNow 返回当前生效的目标直连（Live 存在时以热加载快照为准）。
func (s *Server) dialNow() core.TargetDialer {
	if s.Dial != nil {
		return s.Dial
	}
	// 直接构造（测试与内嵌场景）未注入拨号器时回退共享直连实现，
	// 超时跟随当前生效配置。
	return dialNow{timeout: s.dialTimeout()}
}

type dialNow struct{ timeout time.Duration }

func (d dialNow) DialTarget(ctx context.Context, t core.Target) (net.Conn, core.Route, error) {
	conn, err := (&net.Dialer{Timeout: d.timeout}).DialContext(ctx, "tcp", t.String())
	if err != nil {
		return nil, core.Route{Action: core.RouteDirect}, err
	}
	return conn, core.Route{Action: core.RouteDirect}, nil
}

func (s *Server) handshakeTimeout() time.Duration {
	if s.Live != nil {
		return s.Live.HandshakeTimeout()
	}
	if s.HandshakeTimeout <= 0 {
		return defaults.HandshakeTimeout
	}
	return s.HandshakeTimeout
}

func (s *Server) dialTimeout() time.Duration {
	if s.Live != nil {
		return s.Live.DialTimeout()
	}
	if s.DialTimeout <= 0 {
		return defaults.DialTimeout
	}
	return s.DialTimeout
}

func (s *Server) idleTimeout() time.Duration {
	if s.Live != nil {
		return s.Live.IdleTimeout()
	}
	if s.IdleTimeout <= 0 {
		return defaults.IdleTimeout
	}
	return s.IdleTimeout
}

func (s *Server) shutdownTimeout() time.Duration {
	if s.Live != nil {
		return s.Live.ShutdownTimeout()
	}
	if s.ShutdownTimeout <= 0 {
		return defaults.DrainTimeout
	}
	return s.ShutdownTimeout
}
