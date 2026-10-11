package trojan

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/socks5"
	"github.com/OopsOo0ps/proxy/internal/testutil"
)

// logBuffer 是并发安全的日志缓冲（slog handler 可能与测试协程并发写入）。
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitTunnelRecord 轮询日志缓冲，直到出现一条 tunnel completed 完成记录。
func waitTunnelRecord(t *testing.T, buf *logBuffer) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(buf.String(), "\n") {
			if !strings.Contains(line, "tunnel completed") {
				continue
			}
			var rec map[string]any
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatalf("log line is not valid JSON: %v (%q)", err, line)
			}
			return rec
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no tunnel completed record in:\n%s", buf.String())
	return nil
}

// startResetAfterWrite 启动一个目标：读到首个请求字节后写出 payload，
// 随即以 RST 断开（模拟出站侧异常中止）。
func startResetAfterWrite(t *testing.T, payload []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen reset target: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		_, _ = conn.Write(payload)
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		_ = conn.Close()
	}()
	return ln.Addr().String()
}

func TestWriteReadRequestRoundTrip(t *testing.T) {
	hash := auth.SHA224Hex("secret")
	cases := []struct {
		host string
		port uint16
	}{
		{"example.com", 443},
		{"1.2.3.4", 80},
		{"::1", 8443},
		// 二进制地址/端口含 0x0A 的回归用例：不能按文本行扫描 CRLF。
		{"127.0.0.1", 0x0A11},
		{"10.1.2.3", 443},
		{"example.com", 0x0D0A},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		if err := WriteRequest(&buf, hash, tc.host, tc.port); err != nil {
			t.Fatalf("WriteRequest: %v", err)
		}
		req, err := ReadRequest(bufio.NewReader(&buf))
		if err != nil {
			t.Fatalf("ReadRequest: %v", err)
		}
		if req.PasswordHash != hash {
			t.Fatalf("hash = %q, want %q", req.PasswordHash, hash)
		}
		if req.Command != socks5.CmdConnect {
			t.Fatalf("command = %#x, want connect", req.Command)
		}
		if req.Host != tc.host || req.Port != tc.port {
			t.Fatalf("target = (%q, %d), want (%q, %d)", req.Host, req.Port, tc.host, tc.port)
		}
	}
}

func TestWriteRequestFormat(t *testing.T) {
	hash := auth.SHA224Hex("pw")
	var buf bytes.Buffer
	if err := WriteRequest(&buf, hash, "example.com", 443); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	if !bytes.HasPrefix(raw, []byte(hash+"\r\n")) {
		t.Fatalf("request should start with hash + CRLF, got %q", raw)
	}
	if !bytes.HasSuffix(raw, []byte("\r\n")) {
		t.Fatalf("request should end with CRLF, got %q", raw)
	}
	if !bytes.Contains(raw, []byte{socks5.CmdConnect}) {
		t.Fatal("request should contain connect command")
	}
}

func TestReadRequestRejects(t *testing.T) {
	validPrefix := strings.Repeat("a", 56) + "\r\n" + "\x01\x01\x01\x01\x01\x00\x50"
	cases := map[string]string{
		"http probe":         "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		"short hash":         "abc\r\n\x01\x01\x01\x01\x01\x00\x50\r\n",
		"bad hash hex":       strings.Repeat("g", 56) + "\r\n",
		"no crlf":            strings.Repeat("a", 56) + "\n",
		"bad terminator":     validPrefix + "\r\r",
		"missing terminator": validPrefix,
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ReadRequest(bufio.NewReader(strings.NewReader(payload)))
			if err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}

	// HTTP 探测流量应被识别为“非协议流量”。
	_, err := ReadRequest(bufio.NewReader(strings.NewReader("GET / HTTP/1.1\r\n\r\n")))
	if !IsNotProtocol(err) {
		t.Fatalf("expected IsNotProtocol for HTTP probe, got %v", err)
	}
}

func TestReadRequestRejectsOversizedLine(t *testing.T) {
	long := strings.Repeat("a", MaxHandshakeLine+10) + "\r\n"
	if _, err := ReadRequest(bufio.NewReader(strings.NewReader(long))); err == nil {
		t.Fatal("oversized line should be rejected")
	}
}

func TestIsPasswordLineValid(t *testing.T) {
	if !IsPasswordLineValid(strings.Repeat("a1B2", 14)) {
		t.Fatal("valid hex should pass")
	}
	for _, bad := range []string{"", "xyz", strings.Repeat("a", 55), strings.Repeat("a", 57), strings.Repeat("g", 56)} {
		if IsPasswordLineValid(bad) {
			t.Fatalf("%q should be invalid", bad)
		}
	}
}

// startEcho 启动回显 TCP 服务。
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// startTLSServer 启动带自签证书的 Trojan 服务端，返回地址与客户端 TLS 配置。
func startTLSServer(t *testing.T, srv *Server, handshakeTimeout time.Duration) (string, *tls.Config) {
	t.Helper()
	cert, caPEM, err := testutil.NewTLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := testutil.ClientTLSConfig(caPEM)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})

	if srv.HandshakeTimeout == 0 {
		srv.HandshakeTimeout = handshakeTimeout
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, tlsLn) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve returned %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("Serve did not stop")
		}
	})
	return ln.Addr().String(), tlsCfg
}

func TestServerHappyPath(t *testing.T) {
	echoAddr := startEcho(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port, _ := strconv.ParseUint(portStr, 10, 16)

	store, err := auth.NewStore([]auth.User{{Username: "alice", Password: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Verifier: store,
		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
			return net.Dial("tcp", addr)
		},
	}
	nodeAddr, clientTLS := startTLSServer(t, srv, 3*time.Second)

	conn, err := Dial(context.Background(), ClientConfig{
		ServerAddr: nodeAddr,
		Password:   "secret",
		TLSConfig:  clientTLS,
	}, host, uint16(port))
	if err != nil {
		t.Fatalf("trojan.Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	payload := []byte("trojan payload")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

// TestServerClientResetDuringRelayIsNotError：对端（proxy-client / 浏览器
// 链路）在数据完整转发后的收尾阶段直接 RST——这正是 CI 偶发红的场景：
// 完成记录必须按正常收尾记为 result=ok（错误详情保留在日志中），
// 不能因为拆除阶段的 RST/FIN 竞态被误判为 error。
func TestServerClientResetDuringRelayIsNotError(t *testing.T) {
	echoAddr := startEcho(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port, _ := strconv.ParseUint(portStr, 10, 16)

	store, err := auth.NewStore([]auth.User{{Username: "alice", Password: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	logs := &logBuffer{}
	srv := &Server{
		Verifier: store,
		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
			return net.Dial("tcp", addr)
		},
		Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	nodeAddr, clientTLS := startTLSServer(t, srv, 3*time.Second)

	conn, err := Dial(context.Background(), ClientConfig{
		ServerAddr: nodeAddr,
		Password:   "secret",
		TLSConfig:  clientTLS,
	}, host, uint16(port))
	if err != nil {
		t.Fatalf("trojan.Dial: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	payload := []byte("trojan payload")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	// 数据已完整送达：不发 close_notify/FIN，直接 RST 模拟对端 abortive close。
	raw, ok := conn.(*tls.Conn).NetConn().(*net.TCPConn)
	if !ok {
		t.Fatal("tunnel is not backed by *net.TCPConn")
	}
	if err := raw.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	_ = raw.Close()

	rec := waitTunnelRecord(t, logs)
	if rec["result"] != "ok" {
		t.Fatalf("result = %v, want ok (record: %v)", rec["result"], rec)
	}
	if detail, _ := rec["error"].(string); !strings.Contains(detail, "connection reset") {
		t.Fatalf("error detail = %q, want 收到 connection reset 详情", detail)
	}
}

// TestServerUpstreamResetDuringRelayIsNotError：出站侧（目标站点）RST 同样是
// 收尾中止（Linux 上 TLS 目标站点读完 close_notify 后关闭、未读 FIN 触发
// 内核 RST），完成记录记为 result=ok，错误详情带 upstream 来源标注。
func TestServerUpstreamResetDuringRelayIsNotError(t *testing.T) {
	targetAddr := startResetAfterWrite(t, []byte("partial"))
	host, portStr, _ := net.SplitHostPort(targetAddr)
	port, _ := strconv.ParseUint(portStr, 10, 16)

	store, err := auth.NewStore([]auth.User{{Username: "alice", Password: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	logs := &logBuffer{}
	srv := &Server{
		Verifier: store,
		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
			return net.Dial("tcp", addr)
		},
		Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	nodeAddr, clientTLS := startTLSServer(t, srv, 3*time.Second)

	conn, err := Dial(context.Background(), ClientConfig{
		ServerAddr: nodeAddr,
		Password:   "secret",
		TLSConfig:  clientTLS,
	}, host, uint16(port))
	if err != nil {
		t.Fatalf("trojan.Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 8)); err != nil {
		t.Fatalf("read partial response: %v", err)
	}
	_ = conn.(*tls.Conn).CloseWrite()

	rec := waitTunnelRecord(t, logs)
	if rec["result"] != "ok" {
		t.Fatalf("result = %v, want ok (record: %v)", rec["result"], rec)
	}
	if detail, _ := rec["error"].(string); !strings.Contains(detail, "upstream") || !strings.Contains(detail, "connection reset") {
		t.Fatalf("error detail = %q, want upstream 来源标注与 connection reset 详情", detail)
	}
}

func TestServerAuthFailureServesDecoy(t *testing.T) {
	store, err := auth.NewStore([]auth.User{{Username: "alice", Password: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Verifier: store,
		Dial: func(context.Context, string) (net.Conn, error) {
			t.Error("dial must not be called on auth failure")
			return nil, errors.New("unreachable")
		},
	}
	nodeAddr, clientTLS := startTLSServer(t, srv, 3*time.Second)

	// 错误口令：应返回伪装网页而不是任何代理错误。
	conn, err := Dial(context.Background(), ClientConfig{
		ServerAddr: nodeAddr,
		Password:   "wrong-password",
		TLSConfig:  clientTLS,
	}, "example.com", 443)
	if err != nil {
		t.Fatalf("trojan.Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read decoy: %v", err)
	}
	page := string(data)
	if !strings.HasPrefix(page, "HTTP/1.1 200 OK") {
		t.Fatalf("decoy should look like an HTTP response, got %q", page)
	}
	if !strings.Contains(page, "It works!") {
		t.Fatalf("decoy page missing expected content: %q", page)
	}
	for _, leak := range []string{"trojan", "proxy", "password", "node"} {
		if strings.Contains(strings.ToLower(page), leak) {
			t.Fatalf("decoy response leaks %q: %q", leak, page)
		}
	}
}

func TestServerHTTPProbeGetsDecoy(t *testing.T) {
	store, err := auth.NewStore([]auth.User{{Username: "alice", Password: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Verifier: store,
		Dial:     func(context.Context, string) (net.Conn, error) { return nil, errors.New("unreachable") },
	}
	nodeAddr, clientTLS := startTLSServer(t, srv, 3*time.Second)

	// 模拟普通浏览器以 HTTPS 直接访问节点。
	conn, err := tls.Dial("tcp", nodeAddr, clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: node\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.HasPrefix(string(data), "HTTP/1.1 200 OK") {
		t.Fatalf("probe should receive decoy page, got %q", data)
	}
}

func TestServerTargetDialFailureClosesSilently(t *testing.T) {
	store, err := auth.NewStore([]auth.User{{Username: "alice", Password: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Verifier: store,
		Dial:     func(context.Context, string) (net.Conn, error) { return nil, errors.New("connection refused") },
	}
	nodeAddr, clientTLS := startTLSServer(t, srv, 3*time.Second)

	conn, err := Dial(context.Background(), ClientConfig{
		ServerAddr: nodeAddr,
		Password:   "secret",
		TLSConfig:  clientTLS,
	}, "example.com", 443)
	if err != nil {
		t.Fatalf("trojan.Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 官方行为：目标不可达时静默关闭（不发任何数据）。
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		t.Fatalf("expected silent close, got data %q", buf[:n])
	}
	if err == nil {
		t.Fatal("expected close error")
	}
}

func TestServerUnsupportedCommand(t *testing.T) {
	store, err := auth.NewStore([]auth.User{{Username: "alice", Password: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Verifier: store,
		Dial:     func(context.Context, string) (net.Conn, error) { return nil, errors.New("unreachable") },
	}
	nodeAddr, clientTLS := startTLSServer(t, srv, 3*time.Second)

	conn, err := tls.Dial("tcp", nodeAddr, clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	addr, _ := socks5.EncodeAddr("example.com", 53)
	req := append([]byte(auth.SHA224Hex("secret")+"\r\n"), socks5.CmdUDPAssociate)
	req = append(req, addr...)
	req = append(req, '\r', '\n')
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("unsupported command should close the connection silently")
	}
}

func TestServerHandshakeTimeout(t *testing.T) {
	store, err := auth.NewStore([]auth.User{{Username: "alice", Password: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Verifier: store,
		Dial:     func(context.Context, string) (net.Conn, error) { return nil, errors.New("unreachable") },
	}
	nodeAddr, clientTLS := startTLSServer(t, srv, 300*time.Millisecond)

	conn, err := tls.Dial("tcp", nodeAddr, clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	// 什么都不发：服务端应在握手超时后（尝试）返回伪装响应并关闭连接。
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	if _, err := io.ReadAll(conn); err != nil && !errors.Is(err, io.EOF) {
		// 连接被对端关闭属于预期行为；仅当读取完全失败（如超时）时才算错误。
		t.Fatalf("read: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("handshake timeout took %v", elapsed)
	}
}

func TestClientDialErrors(t *testing.T) {
	// 端口无人监听。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := ln.Addr().String()
	_ = ln.Close()
	if _, err := Dial(context.Background(), ClientConfig{ServerAddr: closedAddr, Password: "x"}, "example.com", 443); err == nil {
		t.Fatal("expected dial error for closed port")
	}

	// 明文 TCP 服务：TLS 握手应失败。
	plainLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = plainLn.Close() }()
	go func() {
		for {
			conn, err := plainLn.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	if _, err := Dial(context.Background(), ClientConfig{ServerAddr: plainLn.Addr().String(), Password: "x"}, "example.com", 443); err == nil {
		t.Fatal("expected TLS handshake error for plain TCP server")
	}
}

func TestConnectThenStartRequest(t *testing.T) {
	echoAddr := startEcho(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port, _ := strconv.ParseUint(portStr, 10, 16)

	store, err := auth.NewStore([]auth.User{{Username: "alice", Password: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Verifier: store,
		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
			return net.Dial("tcp", addr)
		},
	}
	nodeAddr, clientTLS := startTLSServer(t, srv, 3*time.Second)

	// 预热路径：先只完成 TLS 握手，模拟连接池中的空闲连接。
	conn, err := Connect(context.Background(), ClientConfig{
		ServerAddr: nodeAddr,
		Password:   "secret",
		TLSConfig:  clientTLS,
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// 领取路径：停留一段时间后（小于服务端握手超时）再补发 Trojan 请求。
	time.Sleep(50 * time.Millisecond)
	if err := StartRequest(context.Background(), conn, auth.SHA224Hex("secret"), host, uint16(port), time.Second); err != nil {
		t.Fatalf("StartRequest: %v", err)
	}

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte("warm tunnel payload")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

func TestServerShutdownInterruptsPendingHandshake(t *testing.T) {
	// 客户端连接池会持有"已握手、待发送请求"的连接；服务端关停时
	// 这类连接应立即被打断，而不是拖满整个握手超时。
	store, err := auth.NewStore([]auth.User{{Username: "alice", Password: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Verifier: store,
		Dial:     func(context.Context, string) (net.Conn, error) { return nil, errors.New("unreachable") },
	}
	cert, caPEM, err := testutil.NewTLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := testutil.ClientTLSConfig(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})

	srv.HandshakeTimeout = 30 * time.Second // 足够长，只有主动打断才能让 Serve 尽快返回
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, tlsLn) }()

	conn, err := Connect(context.Background(), ClientConfig{
		ServerAddr: ln.Addr().String(),
		Password:   "secret",
		TLSConfig:  clientTLS,
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not stop; pending handshake connection should be interrupted")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("shutdown took %v, want prompt interruption", elapsed)
	}

	// 客户端应感知连接已被服务端关闭。
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("client should observe closed connection after shutdown")
	}
}

// startTLSServerControlled 启动 Trojan 服务端并暴露关停触发与 Serve 结束信号。
// Serve 的返回值由清理函数断言，测试正文只需等待 finished 关闭。
func startTLSServerControlled(t *testing.T, srv *Server) (addr string, clientTLS *tls.Config, shutdown func(), finished <-chan struct{}) {
	t.Helper()
	cert, caPEM, err := testutil.NewTLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := testutil.ClientTLSConfig(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	finishedCh := make(chan struct{})
	go func() {
		errCh <- srv.Serve(ctx, tlsLn)
		close(finishedCh)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-finishedCh:
		case <-time.After(5 * time.Second):
			t.Error("Serve did not stop")
			return
		}
		if err := <-errCh; err != nil {
			t.Errorf("Serve returned %v", err)
		}
	})
	return ln.Addr().String(), tlsCfg, cancel, finishedCh
}

// waitDialRefused 轮询直到监听地址拒绝新连接（关停已生效）。
func waitDialRefused(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err != nil {
			return
		}
		_ = conn.Close()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("listener still accepts new connections after shutdown")
}

// echoRoundTrip 在隧道上回显一次数据，验证转发仍然可用。
func echoRoundTrip(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

func TestServerDrainsInflightTunnelOnShutdown(t *testing.T) {
	echoAddr := startEcho(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatal(err)
	}

	store, err := auth.NewStore([]auth.User{{Username: "alice", Password: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Verifier: store,
		Dial: func(_ context.Context, addr string) (net.Conn, error) {
			return net.Dial("tcp", addr)
		},
		ShutdownTimeout: 3 * time.Second,
	}
	nodeAddr, clientTLS, shutdown, finished := startTLSServerControlled(t, srv)

	conn, err := Dial(context.Background(), ClientConfig{
		ServerAddr: nodeAddr,
		Password:   "secret",
		TLSConfig:  clientTLS,
	}, host, uint16(port))
	if err != nil {
		t.Fatalf("trojan.Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// 先做一次往返，确保服务端已进入转发阶段（而非握手期）。
	echoRoundTrip(t, conn, []byte("before shutdown"))

	shutdown()
	waitDialRefused(t, nodeAddr)

	// 存量隧道在关停后必须继续可用（drain 不丢请求）。
	echoRoundTrip(t, conn, []byte("drained tunnel payload"))

	_ = conn.Close()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after the in-flight tunnel closed")
	}
}

func TestServerForceClosesTunnelAfterShutdownTimeout(t *testing.T) {
	echoAddr := startEcho(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatal(err)
	}

	store, err := auth.NewStore([]auth.User{{Username: "alice", Password: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Verifier: store,
		Dial: func(_ context.Context, addr string) (net.Conn, error) {
			return net.Dial("tcp", addr)
		},
		ShutdownTimeout: 200 * time.Millisecond,
	}
	nodeAddr, clientTLS, shutdown, finished := startTLSServerControlled(t, srv)

	conn, err := Dial(context.Background(), ClientConfig{
		ServerAddr: nodeAddr,
		Password:   "secret",
		TLSConfig:  clientTLS,
	}, host, uint16(port))
	if err != nil {
		t.Fatalf("trojan.Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// 先做一次往返，确保服务端已进入转发阶段（而非握手期）。
	echoRoundTrip(t, conn, []byte("before shutdown"))

	start := time.Now()
	shutdown()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not exit after the shutdown timeout")
	}
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond {
		t.Fatalf("Serve returned after %v, want the drain timeout to elapse first", elapsed)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("tunnel should be closed after forced shutdown")
	}
}
