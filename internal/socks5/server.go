package socks5

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"syscall"
	"time"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/defaults"
	"github.com/OopsOo0ps/proxy/internal/logging"
	"github.com/OopsOo0ps/proxy/internal/netutil"
	"github.com/OopsOo0ps/proxy/internal/relay"
	"github.com/OopsOo0ps/proxy/internal/session"
	"github.com/OopsOo0ps/proxy/internal/shutdown"
	"github.com/OopsOo0ps/proxy/internal/sockswire"
)

var (
	errNoAcceptableMethod = errors.New("socks5: no acceptable authentication method")
	errAuthFailed         = errors.New("socks5: authentication failed")
)

// TargetDialer 建立到目标的连接（由路由与出口节点决定直连或经隧道）。
// 契约锚在消费方（core.TargetDialer）：本包不感知出站实现，组装根可以用
// 单个运行期适配器同时满足两边的策略接口（见 internal/clientapp 的 clientLive）。
type TargetDialer = core.TargetDialer

// LivePolicy 提供配置热加载后的动态策略。
// 为 nil 时使用 Server 的静态字段（测试与直接构造场景）。
type LivePolicy interface {
	// Auth 返回当前凭据校验能力；nil 表示不要求认证。
	Auth() core.Authenticator
	// Dialer 返回当前目标拨号器。
	Dialer() TargetDialer
	// HandshakeTimeout 返回握手超时。
	HandshakeTimeout() time.Duration
	// IdleTimeout 返回连接空闲回收超时。
	IdleTimeout() time.Duration
	// ShutdownTimeout 返回关停排空期限。
	ShutdownTimeout() time.Duration
}

// WriteOverloadReply 对因连接上限被拒绝的 SOCKS5 连接回“无可用认证方式”
// （0x05 0xFF）后关闭：RFC 1928 在认证前没有专门的过载回复码，
// 这是客户端可感知且协议合法的明确失败。写操作带 2s 期限。
func WriteOverloadReply(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte{Version, MethodNoAcceptable})
}

// Server 是 SOCKS5 入站代理，仅支持 TCP CONNECT（UDP ASSOCIATE 暂不支持）。
type Server struct {
	// Auth 为 nil 时不要求认证；否则要求用户名/密码（RFC 1929）。
	Auth *auth.Store
	// Dialer 建立到目标的连接。
	Dialer TargetDialer
	// Live 提供热加载后的动态策略；非 nil 时优先于上方静态字段。
	Live LivePolicy
	// Logger 日志；为 nil 时静默。
	Logger *slog.Logger
	// Telemetry 是遥测出口；nil 时使用 core.NopTelemetry。
	Telemetry core.Telemetry
	// HandshakeTimeout 握手超时；<=0 时使用 defaults.HandshakeTimeout。
	HandshakeTimeout time.Duration
	// IdleTimeout 连接空闲回收；<=0 时使用 defaults.IdleTimeout。
	IdleTimeout time.Duration
	// ShutdownTimeout 关停时等待存量连接结束的最长时间；<=0 时使用 shutdown.DefaultTimeout（同源 defaults.DrainTimeout）。
	ShutdownTimeout time.Duration
}

// Serve 在 ln 上接受并处理 SOCKS5 连接；ctx 取消后优雅关停：
// 先停止接受新连接，让存量连接在关停期限内自然结束，超时后强制断开。
// accept/drain 机械部分委托 internal/session（与 trojan 服务端共用同一实现），
// 本包实现 session.ConnHandler 提供协议逻辑。
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	return session.Serve(ctx, ln, s, session.Options{
		Logger:       s.Logger,
		DrainTimeout: s.shutdownTimeout,
	})
}

// ServeConn 处理一条已接受的连接（session.ConnHandler）：握手 → 认证 →
// 提取 Target → 拨号 → relay；拒绝路径与遥测事件发射都在这里。
// connCtx 承载强制断开期限（排空超时后被取消）。
func (s *Server) ServeConn(connCtx context.Context, raw net.Conn) {
	defer func() { _ = raw.Close() }()

	// 强制关停时打断握手期连接，保证进程按期退出。
	stopForce := context.AfterFunc(connCtx, func() { _ = raw.SetDeadline(time.Now()) })
	defer stopForce()

	start := time.Now()
	reqID := logging.NewRequestID()
	clientIP := netutil.RemoteIP(raw.RemoteAddr())
	logger := s.logger().With("request_id", reqID, "proto", core.ProtoSOCKS5, "client_ip", clientIP)

	// accept 后即计（active +1）；终态由 ConnDone / ConnRejected 配对回收。
	s.telemetryNow().ConnOpened(core.ProtoSOCKS5)

	_ = raw.SetDeadline(time.Now().Add(s.handshakeTimeout()))

	br := bufio.NewReader(raw)
	if err := s.negotiate(br, raw); err != nil {
		if errors.Is(err, errAuthFailed) || errors.Is(err, errNoAcceptableMethod) {
			logger.Warn("socks5 authentication failed", "error", err)
			// 未进入服务即被拒（认证失败）：按拒绝计，无路由维度。
			s.telemetryNow().ConnRejected(core.ProtoSOCKS5, core.ResultDenied)
		} else {
			logger.Debug("socks5 handshake failed", "error", err)
			s.telemetryNow().ConnRejected(core.ProtoSOCKS5, core.ResultError)
		}
		return
	}

	host, port, cmd, err := readRequest(br)
	if err != nil {
		logger.Debug("socks5 request parse failed", "error", err)
		s.telemetryNow().ConnRejected(core.ProtoSOCKS5, core.ResultError)
		return
	}
	target := core.Target{Host: host, Port: port}

	switch cmd {
	case CmdConnect:
		// 继续下方的拨号流程。
	case CmdUDPAssociate:
		logger.Warn("socks5 UDP ASSOCIATE is not supported yet")
		_ = writeReply(raw, ReplyCmdNotSupported)
		s.telemetryNow().ConnRejected(core.ProtoSOCKS5, core.ResultError)
		return
	default: // BIND 及其他未知命令
		_ = writeReply(raw, ReplyCmdNotSupported)
		s.telemetryNow().ConnRejected(core.ProtoSOCKS5, core.ResultError)
		return
	}

	conn, route, err := s.dialerNow().DialTarget(connCtx, target)
	if err != nil {
		if route.Action != core.RouteProxy && route.Action != core.RouteDirect {
			// 未发生拨号的终态：按拒绝计，不伪造路由维度。
			_ = writeReply(raw, ReplyGeneralFailure)
			s.telemetryNow().ConnRejected(core.ProtoSOCKS5, core.ResultError)
			return
		}
		logger.Warn("dial target failed", "target", target.String(), "route", route.Action.String(), "error", err)
		reply := byte(ReplyGeneralFailure)
		if errors.Is(err, syscall.ECONNREFUSED) {
			reply = ReplyConnRefused
		}
		_ = writeReply(raw, reply)
		s.telemetryNow().ConnDone(core.ConnAttrs{
			RequestID: reqID,
			ClientIP:  clientIP,
			Proto:     core.ProtoSOCKS5,
			Target:    target,
			Route:     route,
			Result:    core.ResultDialFail,
			Duration:  time.Since(start),
		})
		return
	}
	if route.Action == core.RouteReject {
		// 路由拒绝：按协议回明确失败，结果记 denied（Route 是权威判定）。
		logger.Warn("routing rejected target", "target", target.String())
		_ = writeReply(raw, ReplyNotAllowed)
		s.telemetryNow().ConnDone(core.ConnAttrs{
			RequestID: reqID,
			ClientIP:  clientIP,
			Proto:     core.ProtoSOCKS5,
			Target:    target,
			Route:     route,
			Result:    core.ResultDenied,
			Duration:  time.Since(start),
		})
		return
	}
	defer func() { _ = conn.Close() }()

	if err := writeReply(raw, ReplySuccess); err != nil {
		logger.Debug("socks5 write reply failed", "error", err)
		s.telemetryNow().ConnDone(core.ConnAttrs{
			RequestID: reqID,
			ClientIP:  clientIP,
			Proto:     core.ProtoSOCKS5,
			Target:    target,
			Route:     route,
			Result:    core.ResultError,
			Duration:  time.Since(start),
		})
		return
	}
	_ = raw.SetDeadline(time.Time{})

	stats, relayErr := relay.BiCopy(connCtx, relay.PrefixConn(raw, br), conn, s.idleTimeout())
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
		"target", target.String(),
		"route", route.Action.String(),
		"upstream", label,
	}, session.RelayAttrs(elapsed, stats.ClientToUpstream, stats.UpstreamToClient, result, relayErr)...)
	logger.Info("request completed", attrs...)
	s.telemetryNow().ConnDone(core.ConnAttrs{
		RequestID: reqID,
		ClientIP:  clientIP,
		Proto:     core.ProtoSOCKS5,
		Target:    target,
		Route:     route,
		Result:    result,
		Duration:  elapsed,
		BytesUp:   stats.ClientToUpstream,
		BytesDown: stats.UpstreamToClient,
	})
}

// negotiate 完成版本/方法协商与（可选的）用户名密码认证。
func (s *Server) negotiate(br *bufio.Reader, w io.Writer) error {
	var head [2]byte // VER, NMETHODS
	if _, err := io.ReadFull(br, head[:]); err != nil {
		return fmt.Errorf("socks5: read greeting: %w", err)
	}
	if head[0] != Version {
		return fmt.Errorf("socks5: unsupported version %#x", head[0])
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return fmt.Errorf("socks5: read methods: %w", err)
	}

	want := byte(MethodNoAuth)
	if s.authNow() != nil {
		want = MethodUserPass
	}
	for _, m := range methods {
		if m != want {
			continue
		}
		if _, err := w.Write([]byte{Version, want}); err != nil {
			return fmt.Errorf("socks5: write method selection: %w", err)
		}
		if want == MethodUserPass {
			return s.authenticate(br, w)
		}
		return nil
	}
	_, _ = w.Write([]byte{Version, MethodNoAcceptable})
	return errNoAcceptableMethod
}

// authenticate 执行 RFC 1929 用户名/密码子协商。
func (s *Server) authenticate(br *bufio.Reader, w io.Writer) error {
	var head [2]byte // VER, ULEN
	if _, err := io.ReadFull(br, head[:]); err != nil {
		return fmt.Errorf("socks5: read auth header: %w", err)
	}
	if head[0] != UserPassVersion {
		return fmt.Errorf("socks5: unsupported auth version %#x", head[0])
	}
	username := make([]byte, int(head[1]))
	if _, err := io.ReadFull(br, username); err != nil {
		return fmt.Errorf("socks5: read username: %w", err)
	}
	var plen [1]byte
	if _, err := io.ReadFull(br, plen[:]); err != nil {
		return fmt.Errorf("socks5: read password length: %w", err)
	}
	password := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(br, password); err != nil {
		return fmt.Errorf("socks5: read password: %w", err)
	}

	ok := s.authNow().Authenticate(string(username), string(password))
	status := byte(UserPassStatusOK)
	if !ok {
		status = UserPassStatusFail
	}
	if _, err := w.Write([]byte{UserPassVersion, status}); err != nil {
		return fmt.Errorf("socks5: write auth result: %w", err)
	}
	if !ok {
		return errAuthFailed
	}
	return nil
}

// readRequest 读取 [VER, CMD, RSV, ATYP, ADDR, PORT]。
func readRequest(br *bufio.Reader) (host string, port uint16, cmd byte, err error) {
	var head [3]byte // VER, CMD, RSV
	if _, err := io.ReadFull(br, head[:]); err != nil {
		return "", 0, 0, fmt.Errorf("socks5: read request: %w", err)
	}
	if head[0] != Version {
		return "", 0, 0, fmt.Errorf("socks5: unsupported version %#x in request", head[0])
	}
	if head[2] != 0 {
		return "", 0, 0, fmt.Errorf("socks5: reserved byte must be zero, got %#x", head[2])
	}
	host, port, err = sockswire.DecodeAddr(br)
	return host, port, head[1], err
}

// writeReply 写出固定为 0.0.0.0:0 的回复。
func writeReply(w io.Writer, rep byte) error {
	_, err := w.Write([]byte{Version, rep, 0x00, ATYPIPv4, 0, 0, 0, 0, 0, 0})
	return err
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

// authNow 返回当前生效的凭据校验能力：Live 存在时以热加载快照为准；
// nil 表示不要求认证。nil 的 *auth.Store 必须显式转成 nil 接口，
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

func (s *Server) handshakeTimeout() time.Duration {
	if s.Live != nil {
		return s.Live.HandshakeTimeout()
	}
	if s.HandshakeTimeout <= 0 {
		return defaults.HandshakeTimeout
	}
	return s.HandshakeTimeout
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
		return shutdown.DefaultTimeout
	}
	return s.ShutdownTimeout
}
