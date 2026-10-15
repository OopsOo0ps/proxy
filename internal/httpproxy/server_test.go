package httpproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/connlimit"
	"github.com/OopsOo0ps/proxy/internal/core"
)

// syncBuffer 是并发安全的日志缓冲（slog handler 可能与测试协程并发写入）。
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitLogRecord 轮询日志缓冲，直到出现包含 substr 的 JSON 记录。
func waitLogRecord(t *testing.T, buf *syncBuffer, substr string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(buf.String(), "\n") {
			if !strings.Contains(line, substr) {
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
	t.Fatalf("log line containing %q not found in:\n%s", substr, buf.String())
	return nil
}

// stubDialer 是可注入的 TargetDialer 测试桩。
type stubDialer struct {
	dial  func(ctx context.Context, t core.Target) (net.Conn, error)
	route core.RouteAction
}

func (d *stubDialer) DialTarget(ctx context.Context, t core.Target) (net.Conn, core.Route, error) {
	if d.dial == nil {
		return nil, core.Route{Action: d.route}, errors.New("stub: no dial")
	}
	conn, err := d.dial(ctx, t)
	return conn, core.Route{Action: d.route}, err
}

// mustPort 解析端口字符串，失败即终止测试。
func mustPort(t *testing.T, s string) uint16 {
	t.Helper()
	p, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		t.Fatalf("parse port %q: %v", s, err)
	}
	return uint16(p)
}

// startProxy 启动 HTTP 代理服务并返回其地址。
func startProxy(t *testing.T, srv *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
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

func echoDialer(t *testing.T) *stubDialer {
	t.Helper()
	return &stubDialer{route: core.RouteDirect, dial: func(ctx context.Context, t core.Target) (net.Conn, error) {
		return net.Dial("tcp", t.String())
	}}
}

func TestConnectTunnel(t *testing.T) {
	echoAddr := startEcho(t)
	proxyAddr := startProxy(t, &Server{Dialer: echoDialer(t)})

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echoAddr, echoAddr); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("status line = %q, want 200", status)
	}
	// 读完响应头。
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}

	payload := []byte("tunnel data")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

// TestConnectClientResetAfterDataIsOK：浏览器式收尾——数据已完整转发后
// 客户端直接 RST（内置内核在接收缓冲尚有未读收尾字节时的行为）。
// 完成记录必须记为 result=ok（错误详情保留在日志），不能误判为 error。
func TestConnectClientResetAfterDataIsOK(t *testing.T) {
	echoAddr := startEcho(t)
	logs := &syncBuffer{}
	proxyAddr := startProxy(t, &Server{
		Dialer: echoDialer(t),
		Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echoAddr, echoAddr); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("status line = %q, want 200", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}

	payload := []byte("tunnel data")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	// 数据已送达：不发 FIN，直接 RST 模拟浏览器的 abortive close。
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatal("connection is not *net.TCPConn")
	}
	if err := tcp.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	_ = tcp.Close()

	rec := waitLogRecord(t, logs, "request completed")
	if rec["result"] != "ok" {
		t.Fatalf("result = %v, want ok (record: %v)", rec["result"], rec)
	}
	if detail, _ := rec["error"].(string); !strings.Contains(detail, "connection reset") {
		t.Fatalf("error detail = %q, want 收到 connection reset 详情", detail)
	}
}

func TestConnectPipelinedPayload(t *testing.T) {
	echoAddr := startEcho(t)
	proxyAddr := startProxy(t, &Server{Dialer: echoDialer(t)})

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 单次写入：CONNECT 请求头 + 立即发送的载荷（模拟 TLS ClientHello 紧随其后）。
	payload := []byte("immediate-payload")
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echoAddr, echoAddr)
	if _, err := conn.Write(append([]byte(req), payload...)); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("status line = %q, want 200", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("pipelined payload lost: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

func TestConnectAuth(t *testing.T) {
	echoAddr := startEcho(t)
	store, err := auth.NewStore([]auth.User{{Username: "alice", Password: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr := startProxy(t, &Server{Auth: store, Dialer: echoDialer(t)})

	// 无凭据：407 且带标准质询头。
	resp := rawConnect(t, proxyAddr, echoAddr, "")
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
	if resp.Header.Get("Proxy-Authenticate") == "" {
		t.Fatal("407 response must include Proxy-Authenticate")
	}
	body := readAll(t, resp.Body)
	if strings.Contains(strings.ToLower(body), "alice") || strings.Contains(strings.ToLower(body), "user") {
		t.Fatalf("407 body leaks credential hints: %q", body)
	}

	// 错误凭据：407。
	bad := base64.StdEncoding.EncodeToString([]byte("alice:wrong"))
	resp = rawConnect(t, proxyAddr, echoAddr, "Basic "+bad)
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("bad credentials status = %d, want 407", resp.StatusCode)
	}

	// 正确凭据：200。
	good := base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	resp = rawConnect(t, proxyAddr, echoAddr, "Basic "+good)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid credentials status = %d, want 200", resp.StatusCode)
	}
}

// rawConnect 通过原始 HTTP 请求发起 CONNECT，返回解析后的响应。
func rawConnect(t *testing.T, proxyAddr, target, proxyAuth string) *http.Response {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if proxyAuth != "" {
		req += "Proxy-Authorization: " + proxyAuth + "\r\n"
	}
	req += "\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp
}

func readAll(t *testing.T, r io.Reader) string {
	t.Helper()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(data)
}

func TestConnectDialFailure(t *testing.T) {
	srv := &Server{Dialer: &stubDialer{route: core.RouteProxy, dial: func(context.Context, core.Target) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}}}
	proxyAddr := startProxy(t, srv)

	resp := rawConnect(t, proxyAddr, "example.com:443", "")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

func TestForwardAbsoluteForm(t *testing.T) {
	var gotProxyAuth string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProxyAuth = r.Header.Get("Proxy-Authorization")
		_, _ = w.Write([]byte("hello from target"))
	}))
	defer target.Close()

	proxyAddr := startProxy(t, &Server{Dialer: &stubDialer{route: core.RouteDirect, dial: func(ctx context.Context, t core.Target) (net.Conn, error) {
		return net.Dial("tcp", t.String())
	}}})

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	cred := base64.StdEncoding.EncodeToString([]byte("u:p"))
	req := fmt.Sprintf("GET %s/ HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\nProxy-Connection: keep-alive\r\n\r\n",
		target.URL, strings.TrimPrefix(target.URL, "http://"), cred)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if body := readAll(t, resp.Body); body != "hello from target" {
		t.Fatalf("body = %q", body)
	}
	if gotProxyAuth != "" {
		t.Fatalf("Proxy-Authorization must not be forwarded to origin, got %q", gotProxyAuth)
	}
}

func TestForwardRejectsRelativeForm(t *testing.T) {
	proxyAddr := startProxy(t, &Server{Dialer: &stubDialer{route: core.RouteDirect}})

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestForwardUpstreamError(t *testing.T) {
	proxyAddr := startProxy(t, &Server{Dialer: &stubDialer{route: core.RouteDirect, dial: func(context.Context, core.Target) (net.Conn, error) {
		return nil, errors.New("boom")
	}}})

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

func TestSplitHostPortDefault(t *testing.T) {
	cases := []struct {
		in       string
		defPort  uint16
		wantHost string
		wantPort uint16
		wantErr  bool
	}{
		{"example.com:8443", 443, "example.com", 8443, false},
		{"example.com", 443, "example.com", 443, false},
		{"[::1]:8443", 443, "::1", 8443, false},
		{"::1", 443, "::1", 443, false},
		{"1.2.3.4:80", 443, "1.2.3.4", 80, false},
		{"1.2.3.4", 80, "1.2.3.4", 80, false},
		{"example.com:0", 443, "", 0, true},
		{"example.com:abc", 443, "", 0, true},
		{"", 443, "", 0, true},
	}
	for _, tc := range cases {
		host, port, err := splitHostPortDefault(tc.in, tc.defPort)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("splitHostPortDefault(%q) expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("splitHostPortDefault(%q): %v", tc.in, err)
		}
		if host != tc.wantHost || port != tc.wantPort {
			t.Fatalf("splitHostPortDefault(%q) = (%q, %d), want (%q, %d)", tc.in, host, port, tc.wantHost, tc.wantPort)
		}
	}
}

func TestParseBasicAuth(t *testing.T) {
	good := base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))
	if user, pass, ok := parseBasicAuth("Basic " + good); !ok || user != "alice" || pass != "s3cret" {
		t.Fatalf("parseBasicAuth = (%q, %q, %v)", user, pass, ok)
	}
	if user, pass, ok := parseBasicAuth("basic " + good); !ok || user != "alice" || pass != "s3cret" {
		t.Fatal("scheme matching should be case-insensitive")
	}
	for _, bad := range []string{"", "Bearer token", "Basic !!!notbase64!!!", "Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon"))} {
		if _, _, ok := parseBasicAuth(bad); ok {
			t.Fatalf("parseBasicAuth(%q) should fail", bad)
		}
	}
}

// recTelemetry 记录 core.Telemetry 三类事件（事件序列与 ConnAttrs 组装断言用）。
type recTelemetry struct {
	mu       sync.Mutex
	opened   []string
	rejected []string
	done     []core.ConnAttrs
}

func (r *recTelemetry) ConnOpened(proto string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.opened = append(r.opened, proto)
}

func (r *recTelemetry) ConnRejected(proto, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rejected = append(r.rejected, proto+"/"+reason)
}

func (r *recTelemetry) ConnDone(a core.ConnAttrs) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.done = append(r.done, a)
}

func (r *recTelemetry) snapshot() (opened, rejected []string, done []core.ConnAttrs) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.opened...), append([]string(nil), r.rejected...), append([]core.ConnAttrs(nil), r.done...)
}

// TestTelemetryConnectEventSequence 钉住 CONNECT 隧道的三事件口径：
// ConnOpened 后恰好一个 ConnDone，Route 取 DialTarget 的权威路径，
// 字节数来自双向转发的统计。
func TestTelemetryConnectEventSequence(t *testing.T) {
	echoAddr := startEcho(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustPort(t, portStr)

	tel := &recTelemetry{}
	proxyAddr := startProxy(t, &Server{
		Dialer:    &stubDialer{route: core.RouteProxy, dial: func(ctx context.Context, t core.Target) (net.Conn, error) { return net.Dial("tcp", t.String()) }},
		Telemetry: tel,
	})

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echoAddr, echoAddr); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	if status, err := br.ReadString('\n'); err != nil || !strings.Contains(status, "200") {
		t.Fatalf("status = %q err = %v, want 200", status, err)
	}
	payload := []byte("telemetry payload")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		opened, _, done := tel.snapshot()
		if len(opened) == 1 && len(done) == 1 {
			if done[0].Route.Action != core.RouteProxy {
				t.Fatalf("route = %v, want proxy（权威路径来自 DialTarget）", done[0].Route.Action)
			}
			if done[0].Proto != core.ProtoHTTP || done[0].Result != core.ResultOK {
				t.Fatalf("attrs = %+v, want http/ok", done[0])
			}
			if done[0].Target.Host != host || done[0].Target.Port != port {
				t.Fatalf("target = %s, want %s", done[0].Target, echoAddr)
			}
			if done[0].BytesUp != int64(len(payload)) || done[0].BytesDown != int64(len(payload)) {
				t.Fatalf("bytes = %d/%d, want %d/%d", done[0].BytesUp, done[0].BytesDown, len(payload), len(payload))
			}
			if done[0].RequestID == "" || done[0].ClientIP == "" || done[0].Duration <= 0 {
				t.Fatalf("attrs = %+v, want request_id/client_ip/duration filled", done[0])
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	opened, rejected, done := tel.snapshot()
	t.Fatalf("telemetry events did not pair: opened=%v rejected=%v done=%+v", opened, rejected, done)
}

// TestTelemetryAuthFailureRejected 钉住认证失败的口径：未进入服务即被拒，
// 记 ConnRejected(denied)，不产生 ConnDone（无路由维度）。
func TestTelemetryAuthFailureRejected(t *testing.T) {
	echoAddr := startEcho(t)
	store, err := auth.NewStore([]auth.User{{Username: "alice", Password: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	tel := &recTelemetry{}
	proxyAddr := startProxy(t, &Server{Auth: store, Dialer: echoDialer(t), Telemetry: tel})

	resp := rawConnect(t, proxyAddr, echoAddr, "")
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		opened, rejected, done := tel.snapshot()
		if len(rejected) == 1 {
			if rejected[0] != core.ProtoHTTP+"/"+core.ResultDenied {
				t.Fatalf("rejected = %v, want http/denied", rejected)
			}
			if len(opened) != 1 || len(done) != 0 {
				t.Fatalf("events = opened=%v done=%+v, want opened×1 and no done", opened, done)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	opened, rejected, done := tel.snapshot()
	t.Fatalf("rejection not observed: opened=%v rejected=%v done=%+v", opened, rejected, done)
}

// startProxyControlled 启动代理并暴露关停触发与 Serve 结束信号，供关停测试使用。
// Serve 的返回值由清理函数断言，测试正文只需等待 finished 关闭。
func startProxyControlled(t *testing.T, srv *Server) (addr string, shutdown func(), finished <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
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

// connectTunnel 建立一次 CONNECT 隧道并读完响应头。
func connectTunnel(t *testing.T, proxyAddr, target string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		_ = conn.Close()
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		t.Fatalf("read status: %v", err)
	}
	if !strings.Contains(status, "200") {
		_ = conn.Close()
		t.Fatalf("status = %q, want 200", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			t.Fatalf("read header: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	return conn
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

func TestServeDrainsInflightConnectOnShutdown(t *testing.T) {
	echoAddr := startEcho(t)
	proxyAddr, shutdown, finished := startProxyControlled(t, &Server{
		Dialer:          echoDialer(t),
		ShutdownTimeout: 3 * time.Second,
	})

	conn := connectTunnel(t, proxyAddr, echoAddr)
	defer func() { _ = conn.Close() }()

	shutdown()
	waitDialRefused(t, proxyAddr)

	// 存量隧道在关停后必须继续可用（drain 不丢请求）。
	echoRoundTrip(t, conn, "drained payload")

	// 隧道结束后 Serve 应在期限内正常返回。
	_ = conn.Close()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after the in-flight tunnel closed")
	}
}

func TestServeForceClosesTunnelAfterShutdownTimeout(t *testing.T) {
	echoAddr := startEcho(t)
	proxyAddr, shutdown, finished := startProxyControlled(t, &Server{
		Dialer:          echoDialer(t),
		ShutdownTimeout: 200 * time.Millisecond,
	})

	conn := connectTunnel(t, proxyAddr, echoAddr)
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

	// 客户端应感知隧道已被强制关闭。
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("tunnel should be closed after forced shutdown")
	}
}

func TestWriteOverloaded(t *testing.T) {
	server, client := net.Pipe()
	go WriteOverloaded(server)

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	raw, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	text := string(raw)
	if !strings.HasPrefix(text, "HTTP/1.1 503 Service Unavailable") {
		t.Fatalf("status line = %q, want 503", strings.SplitN(text, "\r\n", 2)[0])
	}
	for _, want := range []string{"Retry-After: 1", "Connection: close", "proxy overloaded: connection limit reached"} {
		if !strings.Contains(text, want) {
			t.Fatalf("overload response missing %q:\n%s", want, text)
		}
	}
}

// BenchmarkConnectHandshake 测量 CONNECT 入站握手热路径：
// 建连 → 解析请求 → 出站拨号（内存管道上游）→ 200 响应 → 关闭。
// 上游用内存管道隔离网络变量，度量代理自身处理开销；每次迭代会新建一条本机 TCP 连接。
func BenchmarkConnectHandshake(b *testing.B) {
	srv := &Server{Dialer: &stubDialer{route: core.RouteDirect, dial: func(context.Context, core.Target) (net.Conn, error) {
		upstream, peer := net.Pipe()
		// 立即关闭对端：上游方向读到 EOF 后转发自然结束，不会因管道不可半关闭而死等。
		_ = peer.Close()
		return upstream, nil
	}}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	b.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			b.Error("Serve did not stop")
		}
	})
	addr := ln.Addr().String()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			b.Fatalf("dial proxy: %v", err)
		}
		if _, err := fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
			b.Fatalf("write CONNECT: %v", err)
		}
		br := bufio.NewReader(conn)
		status, err := br.ReadString('\n')
		if err != nil {
			b.Fatalf("read status: %v", err)
		}
		if !strings.Contains(status, "200") {
			b.Fatalf("status = %q, want 200", status)
		}
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				b.Fatalf("read header: %v", err)
			}
			if line == "\r\n" {
				break
			}
		}
		_ = conn.Close()
	}
}

// TestCloseIdleConnectionsNilSafe 验证 CloseIdleConnections 在未启动 Serve
// 或 nil 接收者时为空操作（规则变化回调可能在 Serve 之前触发）。
func TestCloseIdleConnectionsNilSafe(t *testing.T) {
	var s *Server
	s.CloseIdleConnections()
	(&Server{}).CloseIdleConnections()
}

// TestServeIdleKeepAliveReleased 验证转发路径（net/http）的 keep-alive 空闲
// 连接会在 IdleTimeout 后被回收并归还 connlimit 名额：与 CONNECT 隧道共用
// 同一份并发预算时，一条闲置的 keep-alive 连接不能永久占坑。
func TestServeIdleKeepAliveReleased(t *testing.T) {
	// 上游目标：一个普通 HTTP 服务，供绝对地址请求转发。
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello from target"))
	}))
	defer target.Close()

	store, err := auth.NewStore([]auth.User{{Username: "u", Password: "p"}})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// 名额只有 1：第一条 keep-alive 连接占用期间，第二条必须被拒绝/搁置；
	// 空闲回收后名额归还，第二条才能被接受。
	limiter := connlimit.New(1)
	wrapped := connlimit.WrapListener(ln, limiter, nil)

	srv := &Server{
		Auth:        store,
		Dialer:      echoDialer(t),
		IdleTimeout: 300 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, wrapped) }()
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

	cred := base64.StdEncoding.EncodeToString([]byte("u:p"))
	sendForwardRequest := func(t *testing.T, conn net.Conn) {
		t.Helper()
		req := fmt.Sprintf("GET %s/ HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
			target.URL, strings.TrimPrefix(target.URL, "http://"), cred)
		if _, err := conn.Write([]byte(req)); err != nil {
			t.Fatalf("write request: %v", err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		if body := readAll(t, resp.Body); body != "hello from target" {
			t.Fatalf("body = %q", body)
		}
	}

	// 第一条连接：完成一次带认证的绝对地址请求后保持打开（不置 Connection: close）。
	first, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	sendForwardRequest(t, first)

	// 名额被第一条连接占用：第二条此时不应被服务（可能被拒或被搁置）。
	blocked, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocked.Close() }()
	_ = blocked.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := blocked.Write([]byte("GET http://ignored/ HTTP/1.1\r\nHost: ignored\r\n\r\n")); err != nil {
		t.Fatalf("write blocked request: %v", err)
	}
	if resp, err := http.ReadResponse(bufio.NewReader(blocked), nil); err == nil {
		// 被拒绝是允许的结局（直接关闭或 503），但绝不能给出正常代理响应。
		if resp.StatusCode == http.StatusOK {
			t.Fatal("second connection served while quota is held by idle keep-alive conn")
		}
		_ = resp.Body.Close()
	}

	// 空闲回收：约 300ms（IdleTimeout）后服务端应关闭该 keep-alive 连接。
	// 断言"最终关闭"而非精确时刻，避免 CI 抖动。
	_ = first.SetReadDeadline(time.Now().Add(2 * time.Second))
	deadline := time.Now().Add(2 * time.Second)
	buf := make([]byte, 1)
	for {
		_, err := first.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.ECONNRESET) {
				break
			}
			t.Fatalf("expected idle close (EOF/reset) within deadline, got %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("keep-alive connection not closed after idle timeout")
		}
	}

	// 名额已归还：第二条连接应能被正常服务。
	second, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	sendForwardRequest(t, second)
}
