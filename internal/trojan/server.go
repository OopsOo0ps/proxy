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
	// HandshakeTimeout 握手超时，默认 10s。
	HandshakeTimeout time.Duration
	// DialTimeout 目标连接超时，默认 10s。
	DialTimeout time.Duration
	// IdleTimeout 连接空闲回收，默认 90s。
	IdleTimeout time.Duration
	// Logger 日志；为 nil 时静默。
	Logger *slog.Logger
	// Metrics 指标；可为 nil。
	Metrics *metrics.Metrics
}

// Serve 在 ln 上接受并处理隧道连接，ctx 取消后关闭监听并等待存量连接退出。
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(ctx, conn)
		}()
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
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
	br := bufio.NewReader(conn)

	req, err := ReadRequest(br)
	if err != nil {
		if IsNotProtocol(err) {
			// 非 Trojan 流量（例如浏览器直接访问）：伪装成普通 Web 服务。
			logger.Debug("non-protocol traffic, serving decoy", "error", err)
		} else {
			logger.Debug("handshake failed", "error", err)
		}
		s.serveDecoy(conn)
		return
	}

	user, ok := s.Verifier.VerifyTunnel(req.PasswordHash)
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
	dialCtx, cancel := context.WithTimeout(ctx, s.dialTimeout())
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
	stats, relayErr := relay.BiCopy(ctx, clientConn, upstream, s.idleTimeout())
	result = metrics.ResultOK
	if !relay.IsExpected(relayErr) {
		result = metrics.ResultError
	}
	elapsed := time.Since(start)
	logger.Info("tunnel completed",
		"user", user,
		"target", target,
		"route", metrics.RouteDirect,
		"upstream", target,
		"duration", elapsed.Round(time.Microsecond).String(),
		"duration_ms", elapsed.Milliseconds(),
		"bytes_up", stats.ClientToUpstream,
		"bytes_down", stats.UpstreamToClient,
		"result", result,
	)
}

// serveDecoy 写出伪装网页并优雅关闭，避免 RST 截断响应。
func (s *Server) serveDecoy(conn net.Conn) {
	// 握手阶段可能已经触发超时，写入前先重置整体期限，保证响应完整送出。
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	page := s.Decoy
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

func (s *Server) handshakeTimeout() time.Duration {
	if s.HandshakeTimeout <= 0 {
		return 10 * time.Second
	}
	return s.HandshakeTimeout
}

func (s *Server) dialTimeout() time.Duration {
	if s.DialTimeout <= 0 {
		return 10 * time.Second
	}
	return s.DialTimeout
}

func (s *Server) idleTimeout() time.Duration {
	if s.IdleTimeout <= 0 {
		return 90 * time.Second
	}
	return s.IdleTimeout
}
