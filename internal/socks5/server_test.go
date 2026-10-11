package socks5

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/dialer"
	"github.com/OopsOo0ps/proxy/internal/routing"
)

// mustPort 解析端口字符串，失败即终止测试。
func mustPort(t *testing.T, s string) uint16 {
	t.Helper()
	p, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		t.Fatalf("parse port %q: %v", s, err)
	}
	return uint16(p)
}

// stubDialer 是可注入的 TargetDialer 测试桩。
type stubDialer struct {
	mu   sync.Mutex
	host string
	port uint16
	dial func(ctx context.Context, host string, port uint16) (net.Conn, error)
}

func (d *stubDialer) DialTarget(ctx context.Context, host string, port uint16) (net.Conn, dialer.Route, error) {
	d.mu.Lock()
	d.host, d.port = host, port
	d.mu.Unlock()
	if d.dial == nil {
		return nil, dialer.Route{}, errors.New("stub: no dial")
	}
	conn, err := d.dial(ctx, host, port)
	return conn, dialer.Route{Action: routing.Direct}, err
}

func (d *stubDialer) RouteFor(string) routing.Action { return routing.Direct }

// startEcho 启动一个回显 TCP 服务，并返回其地址。
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

// startServer 启动 SOCKS5 服务并返回其地址。
func startServer(t *testing.T, srv *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks5: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
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
	return ln.Addr().String()
}

// socks5Connect 执行一次完整的 SOCKS5 客户端交换，返回连接、回复码与错误。
// username 为空表示仅尝试无认证方式。
func socks5Connect(t *testing.T, proxyAddr, username, password, targetHost string, targetPort uint16) (net.Conn, byte, error) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 问候：优先提供用户名密码方式，同时提供无认证方式。
	if username != "" {
		if _, err := conn.Write([]byte{Version, 2, MethodUserPass, MethodNoAuth}); err != nil {
			return conn, 0, err
		}
	} else {
		if _, err := conn.Write([]byte{Version, 1, MethodNoAuth}); err != nil {
			return conn, 0, err
		}
	}
	var sel [2]byte
	if _, err := io.ReadFull(conn, sel[:]); err != nil {
		return conn, 0, err
	}
	if sel[0] != Version {
		return conn, 0, errors.New("bad version in method selection")
	}
	switch sel[1] {
	case MethodUserPass:
		authReq := []byte{UserPassVersion, byte(len(username))}
		authReq = append(authReq, username...)
		authReq = append(authReq, byte(len(password)))
		authReq = append(authReq, password...)
		if _, err := conn.Write(authReq); err != nil {
			return conn, 0, err
		}
		var resp [2]byte
		if _, err := io.ReadFull(conn, resp[:]); err != nil {
			return conn, 0, err
		}
		if resp[0] != UserPassVersion || resp[1] != UserPassStatusOK {
			return conn, 0, errAuthFailed
		}
	case MethodNoAuth:
		// 无需子协商。
	default:
		return conn, 0, errNoAcceptableMethod
	}

	addr, err := EncodeAddr(targetHost, targetPort)
	if err != nil {
		return conn, 0, err
	}
	req := append([]byte{Version, CmdConnect, 0x00}, addr...)
	if _, err := conn.Write(req); err != nil {
		return conn, 0, err
	}

	var head [4]byte // VER, REP, RSV, ATYP
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return conn, 0, err
	}
	if head[0] != Version {
		return conn, head[1], errors.New("bad version in reply")
	}
	// 跳过绑定地址（服务端固定返回 IPv4）。
	switch head[3] {
	case ATYPIPv4:
		var rest [6]byte
		if _, err := io.ReadFull(conn, rest[:]); err != nil {
			return conn, head[1], err
		}
	case ATYPIPv6:
		var rest [18]byte
		if _, err := io.ReadFull(conn, rest[:]); err != nil {
			return conn, head[1], err
		}
	default:
		return conn, head[1], errors.New("unexpected reply atyp")
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, head[1], nil
}

func TestServerConnectNoAuth(t *testing.T) {
	echoAddr := startEcho(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustPort(t, portStr)

	srv := &Server{
		Dialer: &stubDialer{dial: func(ctx context.Context, host string, port uint16) (net.Conn, error) {
			return net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
		}},
	}
	proxyAddr := startServer(t, srv)

	conn, rep, err := socks5Connect(t, proxyAddr, "", "", host, port)
	if err != nil {
		t.Fatalf("socks5 connect: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if rep != ReplySuccess {
		t.Fatalf("reply = %#x, want success", rep)
	}

	payload := []byte("hello socks")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

func TestServerRequiresAuth(t *testing.T) {
	store, err := auth.NewStore([]auth.User{{Username: "alice", Password: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	host := "127.0.0.1"
	echoAddr := startEcho(t)
	_, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustPort(t, portStr)

	srv := &Server{
		Auth: store,
		Dialer: &stubDialer{dial: func(ctx context.Context, host string, port uint16) (net.Conn, error) {
			return net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
		}},
	}
	proxyAddr := startServer(t, srv)

	// 只提供无认证方式：应被拒绝（0xFF）。
	conn, _, err := socks5Connect(t, proxyAddr, "", "", host, port)
	if !errors.Is(err, errNoAcceptableMethod) {
		t.Fatalf("err = %v, want no acceptable method", err)
	}
	_ = conn.Close()

	// 用户名密码错误：认证失败。
	conn, _, err = socks5Connect(t, proxyAddr, "alice", "wrong", host, port)
	if !errors.Is(err, errAuthFailed) {
		t.Fatalf("err = %v, want auth failed", err)
	}
	_ = conn.Close()

	// 正确凭据：连接成功。
	conn, rep, err := socks5Connect(t, proxyAddr, "alice", "secret", host, port)
	if err != nil {
		t.Fatalf("connect with auth: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if rep != ReplySuccess {
		t.Fatalf("reply = %#x, want success", rep)
	}
}

func TestServerUnsupportedCommands(t *testing.T) {
	srv := &Server{Dialer: &stubDialer{dial: func(context.Context, string, uint16) (net.Conn, error) {
		return nil, errors.New("should not be called")
	}}}
	proxyAddr := startServer(t, srv)

	for _, cmd := range []byte{CmdBind, CmdUDPAssociate} {
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write([]byte{Version, 1, MethodNoAuth}); err != nil {
			t.Fatal(err)
		}
		var sel [2]byte
		if _, err := io.ReadFull(conn, sel[:]); err != nil {
			t.Fatal(err)
		}
		addr, _ := EncodeAddr("1.2.3.4", 80)
		if _, err := conn.Write(append([]byte{Version, cmd, 0x00}, addr...)); err != nil {
			t.Fatal(err)
		}
		var reply [2]byte
		if _, err := io.ReadFull(conn, reply[:]); err != nil {
			t.Fatalf("cmd %#x: read reply: %v", cmd, err)
		}
		if reply[1] != ReplyCmdNotSupported {
			t.Fatalf("cmd %#x: reply = %#x, want command-not-supported", cmd, reply[1])
		}
		_ = conn.Close()
	}
}

func TestServerDialFailure(t *testing.T) {
	srv := &Server{Dialer: &stubDialer{dial: func(context.Context, string, uint16) (net.Conn, error) {
		return nil, errors.New("boom")
	}}}
	proxyAddr := startServer(t, srv)

	conn, rep, err := socks5Connect(t, proxyAddr, "", "", "203.0.113.9", 80)
	if err != nil {
		t.Fatalf("socks5 connect: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if rep != ReplyGeneralFailure && rep != ReplyConnRefused {
		t.Fatalf("reply = %#x, want failure", rep)
	}
}

func TestServerRejectsBadVersion(t *testing.T) {
	srv := &Server{Dialer: &stubDialer{}}
	proxyAddr := startServer(t, srv)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte{0x04, 1, 0x00}); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	if _, err := conn.Read(buf[:]); err == nil {
		t.Fatal("server should close connection on bad version")
	}
}

func TestServerPassesTargetToDialer(t *testing.T) {
	echoAddr := startEcho(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustPort(t, portStr)

	stub := &stubDialer{dial: func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		return net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	}}
	srv := &Server{Dialer: stub}
	proxyAddr := startServer(t, srv)

	conn, rep, err := socks5Connect(t, proxyAddr, "", "", host, port)
	if err != nil || rep != ReplySuccess {
		t.Fatalf("connect: rep=%#x err=%v", rep, err)
	}
	defer func() { _ = conn.Close() }()

	stub.mu.Lock()
	gotHost, gotPort := stub.host, stub.port
	stub.mu.Unlock()
	if gotHost != host || gotPort != port {
		t.Fatalf("dialer got %s:%d, want %s:%d", gotHost, gotPort, host, port)
	}
}

// startServerControlled 启动 SOCKS5 服务并暴露关停触发与 Serve 结束信号。
// Serve 的返回值由清理函数断言，测试正文只需等待 finished 关闭。
func startServerControlled(t *testing.T, srv *Server) (addr string, shutdown func(), finished <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks5: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	finishedCh := make(chan struct{})
	go func() {
		errCh <- srv.Serve(ctx, ln)
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
	return ln.Addr().String(), cancel, finishedCh
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

// echoRoundTrip 在连接上回显一次数据，验证隧道仍然可用。
func echoRoundTrip(t *testing.T, conn net.Conn, payload string) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

func TestServeDrainsInflightOnShutdown(t *testing.T) {
	echoAddr := startEcho(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustPort(t, portStr)

	stub := &stubDialer{dial: func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		return net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	}}
	proxyAddr, shutdown, finished := startServerControlled(t, &Server{
		Dialer:          stub,
		ShutdownTimeout: 3 * time.Second,
	})

	conn, rep, err := socks5Connect(t, proxyAddr, "", "", host, port)
	if err != nil || rep != ReplySuccess {
		t.Fatalf("connect: rep=%#x err=%v", rep, err)
	}
	defer func() { _ = conn.Close() }()

	shutdown()
	waitDialRefused(t, proxyAddr)

	// 存量连接在关停后必须继续可用（drain 不丢请求）。
	echoRoundTrip(t, conn, "drained payload")

	_ = conn.Close()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after the in-flight connection closed")
	}
}

func TestServeForceClosesAfterShutdownTimeout(t *testing.T) {
	echoAddr := startEcho(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustPort(t, portStr)

	stub := &stubDialer{dial: func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		return net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	}}
	proxyAddr, shutdown, finished := startServerControlled(t, &Server{
		Dialer:          stub,
		ShutdownTimeout: 200 * time.Millisecond,
	})

	conn, rep, err := socks5Connect(t, proxyAddr, "", "", host, port)
	if err != nil || rep != ReplySuccess {
		t.Fatalf("connect: rep=%#x err=%v", rep, err)
	}
	defer func() { _ = conn.Close() }()

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
		t.Fatal("connection should be closed after forced shutdown")
	}
}

func TestWriteOverloadReply(t *testing.T) {
	server, client := net.Pipe()
	go WriteOverloadReply(server)

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	var reply [2]byte
	if _, err := io.ReadFull(client, reply[:]); err != nil {
		t.Fatalf("read overload reply: %v", err)
	}
	if reply[0] != Version || reply[1] != MethodNoAcceptable {
		t.Fatalf("overload reply = %v, want [0x05 0xFF]", reply)
	}
	if _, err := client.Read(reply[:1]); err == nil {
		t.Fatal("connection should be closed after the overload reply")
	}
}
