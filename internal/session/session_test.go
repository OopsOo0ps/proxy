package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// startServe 在回环 listener 上启动 Serve，返回地址、关停函数与完成信号。
func startServe(t *testing.T, o Options, handle func(serveCtx, connCtx context.Context, conn net.Conn)) (addr string, cancel context.CancelFunc, finished <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	fin := make(chan error, 1)
	go func() { fin <- Serve(ctx, ln, o, handle) }()
	return ln.Addr().String(), cancel, fin
}

// roundTrip 发送一个字节并回读，确认连接仍在服务。
func roundTrip(t *testing.T, conn net.Conn, b byte) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{b}); err != nil {
		t.Fatal(err)
	}
	var got [1]byte
	if _, err := io.ReadFull(conn, got[:]); err != nil {
		t.Fatal(err)
	}
	if got[0] != b {
		t.Fatalf("echo = %#x, want %#x", got[0], b)
	}
}

// TestServeDrainsInflightOnShutdown 钉住核心语义：关停后停止接受新连接，
// 存量连接在排空期限内继续可用；connCtx 在排空期不被取消，serveCtx 立即取消；
// 两条关停日志保留现有文案与字段。
func TestServeDrainsInflightOnShutdown(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	var mu sync.Mutex
	var seenServeCtxErr, seenConnCtxErr error
	handle := func(serveCtx, connCtx context.Context, conn net.Conn) {
		defer func() { _ = conn.Close() }()
		var got [1]byte
		for {
			if _, err := conn.Read(got[:]); err != nil {
				mu.Lock()
				seenServeCtxErr = serveCtx.Err()
				seenConnCtxErr = connCtx.Err()
				mu.Unlock()
				return
			}
			if _, err := conn.Write(got[:]); err != nil {
				return
			}
		}
	}

	addr, cancel, finished := startServe(t, Options{
		Logger:       logger,
		DrainTimeout: func() time.Duration { return 3 * time.Second },
	}, handle)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	roundTrip(t, conn, 'a') // 关停前：请求正常服务

	cancel()                // 关停：停止接受新连接，进入排空期
	roundTrip(t, conn, 'b') // 排空期内：存量连接继续可用

	// 关闭客户端连接让 handle 退出，Serve 应在排空期限内自然返回。
	_ = conn.Close()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after in-flight connection ended")
	}

	mu.Lock()
	defer mu.Unlock()
	if seenConnCtxErr != nil {
		t.Fatalf("connCtx canceled during drain: %v", seenConnCtxErr)
	}
	if !errors.Is(seenServeCtxErr, context.Canceled) {
		t.Fatalf("serveCtx.Err() = %v, want context.Canceled", seenServeCtxErr)
	}

	out := buf.String()
	if !strings.Contains(out, "shutdown: stopped accepting new connections") ||
		!strings.Contains(out, "drain_timeout=3s") {
		t.Fatalf("missing started log line: %s", out)
	}
	if !strings.Contains(out, DrainedConnections) {
		t.Fatalf("missing drained log line: %s", out)
	}
}

// TestServeForceClosesAfterShutdownTimeout 钉住强制路径：排空期限到点后
// connCtx 被取消，超时告警日志保留现有文案。
func TestServeForceClosesAfterShutdownTimeout(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	entered := make(chan struct{})
	handle := func(serveCtx, connCtx context.Context, conn net.Conn) {
		close(entered) // handle 进入即计入 wg，保证 cancel 前已被接受
		defer func() { _ = conn.Close() }()
		<-connCtx.Done() // 模拟阻塞中的协议处理：仅对强制取消敏感
	}

	addr, cancel, finished := startServe(t, Options{
		Logger:       logger,
		DrainTimeout: func() time.Duration { return 200 * time.Millisecond },
	}, handle)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("handle was not entered")
	}

	start := time.Now()
	cancel()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not exit after the drain timeout")
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
		t.Fatalf("Serve returned after %v, want the drain timeout to elapse first", elapsed)
	}

	// 客户端连接应随强制阶段被 handle 关闭。
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if _, err := conn.Read(one[:]); err == nil {
		t.Fatal("connection should be closed after forced shutdown")
	}

	if !strings.Contains(buf.String(), "shutdown: timeout exceeded, remaining connections closed") {
		t.Fatalf("missing timeout log line: %s", buf.String())
	}
}

// TestServeReturnsAcceptError 钉住非关停路径：Accept 的非关停错误原样返回。
func TestServeReturnsAcceptError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fin := make(chan error, 1)
	go func() {
		fin <- Serve(context.Background(), ln, Options{}, func(context.Context, context.Context, net.Conn) {})
	}()
	_ = ln.Close()
	select {
	case err := <-fin:
		if err == nil {
			t.Fatal("Serve should return the accept error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after listener closed")
	}
}

// TestDrainedMessageOverride 钉住排空完成日志的文案保留：现有文案逐字迁移
// （通用入站 connections 为默认，隧道服务端覆盖为 tunnels）。
func TestDrainedMessageOverride(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	_, cancel, finished := startServe(t, Options{
		Logger:         logger,
		DrainTimeout:   func() time.Duration { return time.Second },
		DrainedMessage: "shutdown: all in-flight tunnels drained",
	}, func(serveCtx, connCtx context.Context, conn net.Conn) {})

	cancel()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after shutdown")
	}

	out := buf.String()
	if !strings.Contains(out, "shutdown: all in-flight tunnels drained") {
		t.Fatalf("missing overridden drained message: %s", out)
	}
	if strings.Contains(out, DrainedConnections) {
		t.Fatalf("default message should not appear when overridden: %s", out)
	}
}

// TestDrainTimeoutDefault 钉住 getter 缺省：DrainTimeout 为 nil 时使用
// shutdown.DefaultTimeout（15s）。
func TestDrainTimeoutDefault(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	_, cancel, finished := startServe(t, Options{Logger: logger},
		func(serveCtx, connCtx context.Context, conn net.Conn) {})
	cancel()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after shutdown")
	}
	if !strings.Contains(buf.String(), "drain_timeout=15s") {
		t.Fatalf("missing default drain timeout: %s", buf.String())
	}
}

// TestRelayAttrs 钉住完成日志公共尾部：字段顺序与形状为三处转发型入站
// （httpproxy CONNECT / socks5 / trojan）共用，出错时附 error 字段。
func TestRelayAttrs(t *testing.T) {
	got := RelayAttrs(1500*time.Microsecond, 11, 22, "ok", nil)
	want := []any{
		"duration", "1.5ms",
		"duration_ms", int64(1),
		"bytes_up", int64(11),
		"bytes_down", int64(22),
		"result", "ok",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("RelayAttrs = %v, want %v", got, want)
	}

	got = RelayAttrs(time.Second, 0, 0, "error", errors.New("reset by peer"))
	want = []any{
		"duration", "1s",
		"duration_ms", int64(1000),
		"bytes_up", int64(0),
		"bytes_down", int64(0),
		"result", "error",
		"error", "reset by peer",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("RelayAttrs with error = %v, want %v", got, want)
	}
}

// TestDrainWithNilLogger：Logger 为 nil 时静默排空（DiscardHandler 分支）。
func TestDrainWithNilLogger(t *testing.T) {
	_, cancel, finished := startServe(t, Options{},
		func(serveCtx, connCtx context.Context, conn net.Conn) {})
	cancel()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after shutdown")
	}
}

// TestDrainTimeoutNonPositive 钉住 getter 原样生效：非 nil getter 返回 <=0
// 时不做二次钳制（期限立即到点），与既有组件行为一致。
func TestDrainTimeoutNonPositive(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	entered := make(chan struct{})
	handle := func(serveCtx, connCtx context.Context, conn net.Conn) {
		close(entered) // handle 进入即计入 wg，保证 cancel 前已被接受
		defer func() { _ = conn.Close() }()
		<-connCtx.Done()
	}

	addr, cancel, finished := startServe(t, Options{
		Logger:       logger,
		DrainTimeout: func() time.Duration { return 0 },
	}, handle)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("handle was not entered")
	}

	cancel()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not exit promptly with a non-positive drain timeout")
	}
	if !strings.Contains(buf.String(), "drain_timeout=0s") ||
		!strings.Contains(buf.String(), "shutdown: timeout exceeded, remaining connections closed") {
		t.Fatalf("missing zero-timeout drain logs: %s", buf.String())
	}
}
