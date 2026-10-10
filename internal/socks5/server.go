package socks5

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/dialer"
	"github.com/OopsOo0ps/proxy/internal/logging"
	"github.com/OopsOo0ps/proxy/internal/metrics"
	"github.com/OopsOo0ps/proxy/internal/netutil"
	"github.com/OopsOo0ps/proxy/internal/relay"
	"github.com/OopsOo0ps/proxy/internal/shutdown"
)

var (
	errNoAcceptableMethod = errors.New("socks5: no acceptable authentication method")
	errAuthFailed         = errors.New("socks5: authentication failed")
)

// TargetDialer 建立到目标的连接（由路由与出口节点决定直连或经隧道）。
type TargetDialer interface {
	DialTarget(ctx context.Context, host string, port uint16) (net.Conn, dialer.Route, error)
}

// LivePolicy 提供配置热加载后的动态策略。
// 为 nil 时使用 Server 的静态字段（测试与直接构造场景）。
type LivePolicy interface {
	// Auth 返回当前凭据存储；nil 表示不要求认证。
	Auth() *auth.Store
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
	// Metrics 指标；可为 nil。
	Metrics *metrics.Metrics
	// HandshakeTimeout 握手超时；<=0 时使用 10s。
	HandshakeTimeout time.Duration
	// IdleTimeout 连接空闲回收；<=0 时使用 90s。
	IdleTimeout time.Duration
	// ShutdownTimeout 关停时等待存量连接结束的最长时间；<=0 时使用默认值 15s。
	ShutdownTimeout time.Duration
}

// Serve 在 ln 上接受并处理 SOCKS5 连接；ctx 取消后优雅关停：
// 先停止接受新连接，让存量连接在关停期限内自然结束，超时后强制断开。
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	// handlerCtx 与关停信号解耦：收到关停后存量连接继续处理，
	// 只有超过关停期限（forceCancel）才被打断。
	handlerCtx, forceCancel := context.WithCancel(context.WithoutCancel(ctx))
	defer forceCancel()

	var wg sync.WaitGroup
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
		case <-done:
		}
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				s.drain(&wg, forceCancel)
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(handlerCtx, conn)
		}()
	}
}

// drain 排空存量连接；超过关停期限后强制中断仍阻塞的连接。
func (s *Server) drain(wg *sync.WaitGroup, forceCancel context.CancelFunc) {
	s.logger().Info("shutdown: stopped accepting new connections",
		"drain_timeout", s.shutdownTimeout().String())
	if shutdown.Wait(wg, s.shutdownTimeout(), forceCancel) {
		s.logger().Info("shutdown: all in-flight connections drained")
		return
	}
	s.logger().Warn("shutdown: timeout exceeded, remaining connections closed")
}

func (s *Server) handle(ctx context.Context, raw net.Conn) {
	defer func() { _ = raw.Close() }()

	// 强制关停时打断握手期连接，保证进程按期退出。
	stopForce := context.AfterFunc(ctx, func() { _ = raw.SetDeadline(time.Now()) })
	defer stopForce()

	start := time.Now()
	reqID := logging.NewRequestID()
	logger := s.logger().With("request_id", reqID, "proto", "socks5", "client_ip", netutil.RemoteIP(raw.RemoteAddr()))

	s.Metrics.ConnOpened(metrics.ProtoSOCKS5)
	defer s.Metrics.ConnClosed(metrics.ProtoSOCKS5)

	result := metrics.ResultError
	route := metrics.RouteNone
	defer func() {
		s.Metrics.Observe(metrics.ProtoSOCKS5, route, result, time.Since(start))
	}()

	_ = raw.SetDeadline(time.Now().Add(s.handshakeTimeout()))

	br := bufio.NewReader(raw)
	if err := s.negotiate(br, raw); err != nil {
		if errors.Is(err, errAuthFailed) || errors.Is(err, errNoAcceptableMethod) {
			result = metrics.ResultAuthFail
			logger.Warn("socks5 authentication failed", "error", err)
		} else {
			logger.Debug("socks5 handshake failed", "error", err)
		}
		return
	}

	host, port, cmd, err := readRequest(br)
	if err != nil {
		logger.Debug("socks5 request parse failed", "error", err)
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	switch cmd {
	case CmdConnect:
		// 继续下方的拨号流程。
	case CmdUDPAssociate:
		logger.Warn("socks5 UDP ASSOCIATE is not supported yet")
		_ = writeReply(raw, ReplyCmdNotSupported)
		return
	default: // BIND 及其他未知命令
		_ = writeReply(raw, ReplyCmdNotSupported)
		return
	}

	conn, r, err := s.dialerNow().DialTarget(ctx, host, port)
	route = r.Action.String()
	if err != nil {
		result = metrics.ResultDialFail
		logger.Warn("dial target failed", "target", target, "error", err)
		reply := byte(ReplyGeneralFailure)
		if errors.Is(err, syscall.ECONNREFUSED) {
			reply = ReplyConnRefused
		}
		_ = writeReply(raw, reply)
		return
	}
	defer func() { _ = conn.Close() }()

	if err := writeReply(raw, ReplySuccess); err != nil {
		logger.Debug("socks5 write reply failed", "error", err)
		return
	}
	_ = raw.SetDeadline(time.Time{})

	stats, relayErr := relay.BiCopy(ctx, relay.PrefixConn(raw, br), conn, s.idleTimeout())
	result = metrics.ResultOK
	if !relay.IsExpected(relayErr) {
		result = metrics.ResultError
	}
	elapsed := time.Since(start)
	logger.Info("request completed",
		"target", target,
		"route", route,
		"upstream", r.Label(),
		"duration", elapsed.Round(time.Microsecond).String(),
		"duration_ms", elapsed.Milliseconds(),
		"bytes_up", stats.ClientToUpstream,
		"bytes_down", stats.UpstreamToClient,
		"result", result,
	)
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

	ok := s.authNow().Verify(string(username), string(password))
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
	host, port, err = DecodeAddr(br)
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

// authNow 返回当前生效的凭据存储：Live 存在时以热加载快照为准。
func (s *Server) authNow() *auth.Store {
	if s.Live != nil {
		return s.Live.Auth()
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
		return 10 * time.Second
	}
	return s.HandshakeTimeout
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

func (s *Server) shutdownTimeout() time.Duration {
	if s.Live != nil {
		return s.Live.ShutdownTimeout()
	}
	if s.ShutdownTimeout <= 0 {
		return shutdown.DefaultTimeout
	}
	return s.ShutdownTimeout
}
