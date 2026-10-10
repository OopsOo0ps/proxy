package trojan

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/OopsOo0ps/proxy/internal/logging"
	"github.com/OopsOo0ps/proxy/internal/metrics"
	"github.com/OopsOo0ps/proxy/internal/netutil"
	"github.com/OopsOo0ps/proxy/internal/relay"
	"github.com/OopsOo0ps/proxy/internal/shutdown"
	"github.com/OopsOo0ps/proxy/internal/socks5"
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

// DialFunc 建立到目标地址的直连（服务端即出口）。
type DialFunc func(ctx context.Context, addr string) (net.Conn, error)

// Server 是 Trojan 隧道服务端。
type Server struct {
	// Verifier 口令校验（必填）。
	Verifier Verifier
	// Dial 目标直连（必填）。
	Dial DialFunc
	// Decoy 伪装页面；为空时使用 DefaultDecoyPage。
	Decoy []byte
	// Live 提供热加载后的动态策略；非 nil 时优先于上方静态字段。
	Live LivePolicy
	// HandshakeTimeout 握手超时，默认 10s。
	HandshakeTimeout time.Duration
	// DialTimeout 目标连接超时，默认 10s。
	DialTimeout time.Duration
	// IdleTimeout 连接空闲回收，默认 90s。
	IdleTimeout time.Duration
	// ShutdownTimeout 关停时等待存量隧道结束的最长时间，默认 15s。
	ShutdownTimeout time.Duration
	// Logger 日志；为 nil 时静默。
	Logger *slog.Logger
	// Metrics 指标；可为 nil。
	Metrics *metrics.Metrics
}

// Serve 在 ln 上接受并处理隧道连接；ctx 取消后优雅关停：
// 先停止接受新连接，让已在转发的隧道在关停期限内自然结束，超时后强制断开。
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	// relayCtx 与关停信号解耦：收到关停后已在转发的隧道继续排空，
	// 只有超过关停期限（forceCancel）才被打断。
	relayCtx, forceCancel := context.WithCancel(context.WithoutCancel(ctx))
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
			s.handle(ctx, relayCtx, conn)
		}()
	}
}

// drain 排空存量隧道；超过关停期限后强制中断仍在转发的连接。
func (s *Server) drain(wg *sync.WaitGroup, forceCancel context.CancelFunc) {
	s.logger().Info("shutdown: stopped accepting new connections",
		"drain_timeout", s.shutdownTimeout().String())
	if shutdown.Wait(wg, s.shutdownTimeout(), forceCancel) {
		s.logger().Info("shutdown: all in-flight tunnels drained")
		return
	}
	s.logger().Warn("shutdown: timeout exceeded, remaining connections closed")
}

func (s *Server) handle(ctx, relayCtx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	start := time.Now()
	reqID := logging.NewRequestID()
	logger := s.logger().With("request_id", reqID, "proto", "tunnel", "client_ip", netutil.RemoteIP(conn.RemoteAddr()))

	s.Metrics.ConnOpened(metrics.ProtoTunnel)
	defer s.Metrics.ConnClosed(metrics.ProtoTunnel)

	result := metrics.ResultError
	defer func() {
		s.Metrics.Observe(metrics.ProtoTunnel, metrics.RouteDirect, result, time.Since(start))
	}()

	_ = conn.SetDeadline(time.Now().Add(s.handshakeTimeout()))
	// 握手阶段对 ctx 取消敏感：服务端关停时立即打断阻塞中的读取。
	// 客户端连接池会持有"已握手、待发送请求"的预热连接，等待它们
	// 自然超时会让优雅退出拖满一个握手超时；这类连接没有在途请求，
	// 直接关闭不丢任何数据。
	stopHandshakeWatch := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stopHandshakeWatch()
	br := bufio.NewReader(conn)

	req, err := ReadRequest(br)
	if err != nil {
		if ctx.Err() != nil {
			// 关停中断：不再回放伪装页面，直接退出。
			return
		}
		if IsNotProtocol(err) {
			// 非 Trojan 流量（例如浏览器直接访问）：伪装成普通 Web 服务。
			logger.Debug("non-protocol traffic, serving decoy", "error", err)
		} else {
			logger.Debug("handshake failed", "error", err)
		}
		s.serveDecoy(conn)
		return
	}
	stopHandshakeWatch()

	// 超过关停期限（forceCancel）时打断尚未进入转发的连接（如拨号中）。
	stopForce := context.AfterFunc(relayCtx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stopForce()

	user, ok := s.verifierNow().VerifyTunnel(req.PasswordHash)
	if !ok {
		logger.Warn("tunnel authentication failed")
		result = metrics.ResultAuthFail
		s.serveDecoy(conn)
		return
	}
	if req.Command != socks5.CmdConnect {
		// UDP ASSOCIATE 等命令暂不支持：直接关闭并记录。
		logger.Warn("unsupported tunnel command", "command", req.Command)
		return
	}

	target := net.JoinHostPort(req.Host, strconv.Itoa(int(req.Port)))
	dialCtx, cancel := context.WithTimeout(relayCtx, s.dialTimeout())
	defer cancel()
	upstream, err := s.Dial(dialCtx, target)
	if err != nil {
		// 与官方行为一致：目标不可达时静默关闭，不做区分响应。
		logger.Warn("dial target failed", "target", target, "error", err)
		result = metrics.ResultDialFail
		return
	}
	defer func() { _ = upstream.Close() }()

	_ = conn.SetDeadline(time.Time{})
	clientConn := relay.PrefixConn(conn, br)
	stats, relayErr := relay.BiCopy(relayCtx, clientConn, upstream, s.idleTimeout())
	result = metrics.ResultOK
	if relay.IsFailure(relayErr) {
		result = metrics.ResultError
	}
	elapsed := time.Since(start)
	attrs := []any{
		"user", user,
		"target", target,
		"route", metrics.RouteDirect,
		"upstream", target,
		"duration", elapsed.Round(time.Microsecond).String(),
		"duration_ms", elapsed.Milliseconds(),
		"bytes_up", stats.ClientToUpstream,
		"bytes_down", stats.UpstreamToClient,
		"result", result,
	}
	if relayErr != nil {
		attrs = append(attrs, "error", relayErr.Error())
	}
	logger.Info("tunnel completed", attrs...)
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

func (s *Server) handshakeTimeout() time.Duration {
	if s.Live != nil {
		return s.Live.HandshakeTimeout()
	}
	if s.HandshakeTimeout <= 0 {
		return 10 * time.Second
	}
	return s.HandshakeTimeout
}

func (s *Server) dialTimeout() time.Duration {
	if s.Live != nil {
		return s.Live.DialTimeout()
	}
	if s.DialTimeout <= 0 {
		return 10 * time.Second
	}
	return s.DialTimeout
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
