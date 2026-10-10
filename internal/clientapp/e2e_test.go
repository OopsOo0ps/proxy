package clientapp_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/clientapp"
	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/serverapp"
	"github.com/OopsOo0ps/proxy/internal/socks5"
	"github.com/OopsOo0ps/proxy/internal/testutil"
)

func testTimeouts() config.Timeouts {
	return config.Timeouts{
		Dial:      config.Duration(5 * time.Second),
		Handshake: config.Duration(5 * time.Second),
		Idle:      config.Duration(30 * time.Second),
	}
}

func boolPtr(b bool) *bool { return &b }

// serverHandle 封装一个测试用 proxy-server。
type serverHandle struct {
	addr        string
	metricsAddr string
	stop        func()
}

// startServer 启动一个测试用 proxy-server（自签证书）。
func startServer(t *testing.T, password string, logger *slog.Logger, withMetrics bool) *serverHandle {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile, err := testutil.WriteTLSCertFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Server{
		Listen:   "127.0.0.1:0",
		TLS:      config.ServerTLS{CertFile: certFile, KeyFile: keyFile},
		Users:    []config.User{{Username: "node-user", Password: password}},
		Timeouts: testTimeouts(),
		Log:      config.Log{Level: "debug", Format: "json"},
	}
	if withMetrics {
		cfg.Metrics.Listen = "127.0.0.1:0"
	}
	app, err := serverapp.New(cfg, logger)
	if err != nil {
		t.Fatalf("serverapp.New: %v", err)
	}
	if err := app.Listen(); err != nil {
		t.Fatalf("serverapp.Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.Serve(ctx) }()

	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("server %s Serve: %v", app.TunnelAddr(), err)
				}
			case <-time.After(5 * time.Second):
				t.Error("server Serve did not stop")
			}
		})
	}
	t.Cleanup(stop)
	return &serverHandle{addr: app.TunnelAddr(), metricsAddr: app.MetricsAddr(), stop: stop}
}

// startClient 启动一个测试用 proxy-client。
func startClient(t *testing.T, cfg *config.Client, logger *slog.Logger) *clientapp.App {
	t.Helper()
	app, err := clientapp.New(cfg, logger)
	if err != nil {
		t.Fatalf("clientapp.New: %v", err)
	}
	if err := app.Listen(); err != nil {
		t.Fatalf("clientapp.Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("client Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("client Serve did not stop")
		}
	})
	return app
}

// baseClientCfg 构造测试用客户端配置：双入站 + 指定节点 + 强制代理。
func baseClientCfg(nodes []config.Node) *config.Client {
	cfg := &config.Client{
		Inbound:  config.Inbound{HTTP: "127.0.0.1:0", SOCKS5: "127.0.0.1:0"},
		Nodes:    nodes,
		TLS:      config.ClientTLS{InsecureSkipVerify: true}, // 自签测试证书
		Routing:  config.Routing{Default: "proxy", PrivateDirect: boolPtr(false)},
		Timeouts: testTimeouts(),
		Log:      config.Log{Level: "debug", Format: "json"},
	}
	return cfg
}

// browser 返回经 client HTTP 入站的浏览器式客户端。
// proxyURL 可携带用户名密码（http://user:pass@host:port）。
func browser(t *testing.T, proxyURL string, attempts int) *http.Client {
	t.Helper()
	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:               http.ProxyURL(u),
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:   true, // 每次请求重新建联，便于统计节点使用
			MaxIdleConnsPerHost: attempts,
		},
	}
}

// startTLSTarget 启动一个返回固定内容的 HTTPS 目标站点。
func startTLSTarget(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// scrapeMetrics 抓取 /metrics 文本。
func scrapeMetrics(t *testing.T, addr string) string {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("scrape metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// waitForMetric 轮询 /metrics 直到输出包含 want。
// 指标写入发生在请求收尾（晚于完成日志），与抓取之间存在天然时序差。
func waitForMetric(t *testing.T, addr, want string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var body string
	for time.Now().Before(deadline) {
		body = scrapeMetrics(t, addr)
		if strings.Contains(body, want) {
			return body
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("metric %q not found within deadline:\n%s", want, body)
	return ""
}

func TestE2EConnectSuccessRateAndThreeNodes(t *testing.T) {
	passwords := []string{"node-1-secret", "node-2-secret", "node-3-secret"}
	nodes := make([]config.Node, 0, len(passwords))
	nodeLogs := make([]*lockedBuffer, 0, len(passwords))
	for _, pw := range passwords {
		logs := &lockedBuffer{}
		logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		h := startServer(t, pw, logger, false)
		nodes = append(nodes, config.Node{Addr: h.addr, Password: pw})
		nodeLogs = append(nodeLogs, logs)
	}

	target := startTLSTarget(t)
	cfg := baseClientCfg(nodes)
	app := startClient(t, cfg, nil)

	client := browser(t, "http://"+app.HTTPAddr(), 100)
	const attempts = 100
	success := 0
	for i := 0; i < attempts; i++ {
		resp, err := client.Get(target.URL)
		if err != nil {
			t.Logf("request %d failed: %v", i, err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK && string(body) == "ok" {
			success++
		}
	}
	rate := float64(success) / float64(attempts)
	if rate < 0.95 {
		t.Fatalf("CONNECT 转发成功率 %.1f%%（%d/%d）低于验收标准 95%%", rate*100, success, attempts)
	}
	t.Logf("CONNECT 转发成功率 %.1f%%（%d/%d）", rate*100, success, attempts)

	// 验收：至少 3 个节点全部可用——逐一确认每个节点都实际承载过成功请求
	//（以服务端隧道完成日志为证据）。
	for i, logs := range nodeLogs {
		record := waitForLog(t, logs, "tunnel completed")
		assertLogFields(t, record, map[string]func(any) error{
			"result": func(v any) error {
				if v != "ok" {
					return fmt.Errorf("result = %v", v)
				}
				return nil
			},
		})
		t.Logf("节点 %d 已成功承载流量", i+1)
	}
}

func TestE2EFailoverAndAllNodesDown(t *testing.T) {
	passwords := []string{"pw-1", "pw-2", "pw-3"}
	handles := make([]*serverHandle, 0, 3)
	nodes := make([]config.Node, 0, 3)
	for _, pw := range passwords {
		h := startServer(t, pw, nil, true)
		handles = append(handles, h)
		nodes = append(nodes, config.Node{Addr: h.addr, Password: pw})
	}

	target := startTLSTarget(t)
	cfg := baseClientCfg(nodes)
	app := startClient(t, cfg, nil)
	client := browser(t, "http://"+app.HTTPAddr(), 20)

	// 停掉两个节点，流量应自动转移到剩余节点。
	handles[1].stop()
	handles[2].stop()

	success := 0
	const attempts = 20
	for i := 0; i < attempts; i++ {
		resp, err := client.Get(target.URL)
		if err != nil {
			t.Logf("failover request %d failed: %v", i, err)
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			success++
		}
	}
	if success != attempts {
		t.Fatalf("failover 后成功率 = %d/%d，期望全部成功", success, attempts)
	}

	// 全部节点离线：请求应失败（客户端返回 502，浏览器侧表现为错误）。
	handles[0].stop()
	resp, err := client.Get(target.URL)
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode < 500 {
			t.Fatalf("所有节点离线时仍返回 %d", resp.StatusCode)
		}
	}
}

func TestE2EPrivateTargetGoesDirect(t *testing.T) {
	// 私网目标 + 无可用节点：直连应当成功（private_direct 默认开启）。
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("direct-ok"))
	}))
	defer target.Close()

	cfg := baseClientCfg(nil)
	cfg.Routing.PrivateDirect = boolPtr(true)
	app := startClient(t, cfg, nil)

	client := browser(t, "http://"+app.HTTPAddr(), 1)
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("direct request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "direct-ok" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
}

func TestE2EProxyWithoutNodesFails(t *testing.T) {
	// 无节点且目标需走代理：应返回 502，而不是静默失败。
	target := startTLSTarget(t)
	cfg := baseClientCfg(nil)
	app := startClient(t, cfg, nil)

	client := browser(t, "http://"+app.HTTPAddr(), 1)
	resp, err := client.Get(target.URL)
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode < 500 {
			t.Fatalf("expected 502, got %d", resp.StatusCode)
		}
	}
}

func TestE2EHTTPInboundAuth(t *testing.T) {
	h := startServer(t, "node-secret", nil, false)
	target := startTLSTarget(t)

	cfg := baseClientCfg([]config.Node{{Addr: h.addr, Password: "node-secret"}})
	cfg.Inbound.Auth = []config.User{{Username: "alice", Password: "secret"}}
	app := startClient(t, cfg, nil)

	// 无凭据：407。
	anon := browser(t, "http://"+app.HTTPAddr(), 1)
	if resp, err := anon.Get(target.URL); err == nil {
		defer func() { _ = resp.Body.Close() }()
		t.Fatalf("expected 407 without credentials, got %d", resp.StatusCode)
	}

	// 错误凭据：失败。
	bad := browser(t, "http://alice:wrong@"+app.HTTPAddr(), 1)
	if resp, err := bad.Get(target.URL); err == nil {
		defer func() { _ = resp.Body.Close() }()
		t.Fatalf("expected failure with bad credentials, got %d", resp.StatusCode)
	}

	// 正确凭据：成功。
	good := browser(t, "http://alice:secret@"+app.HTTPAddr(), 1)
	resp, err := good.Get(target.URL)
	if err != nil {
		t.Fatalf("authenticated request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// startEcho 启动回显 TCP 服务。
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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

// socks5Dial 通过 SOCKS5 代理建立到目标的连接。
func socks5Dial(t *testing.T, proxyAddr, username, password, targetHost string, targetPort uint16) (net.Conn, error) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	greeting := []byte{socks5.Version, 2, socks5.MethodUserPass, socks5.MethodNoAuth}
	if username == "" {
		greeting = []byte{socks5.Version, 1, socks5.MethodNoAuth}
	}
	if _, err := conn.Write(greeting); err != nil {
		_ = conn.Close()
		return nil, err
	}
	var selection [2]byte
	if _, err := io.ReadFull(conn, selection[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	switch selection[1] {
	case socks5.MethodUserPass:
		req := []byte{socks5.UserPassVersion, byte(len(username))}
		req = append(req, username...)
		req = append(req, byte(len(password)))
		req = append(req, password...)
		if _, err := conn.Write(req); err != nil {
			_ = conn.Close()
			return nil, err
		}
		var result [2]byte
		if _, err := io.ReadFull(conn, result[:]); err != nil {
			_ = conn.Close()
			return nil, err
		}
		if result[1] != socks5.UserPassStatusOK {
			_ = conn.Close()
			return nil, errors.New("socks5: authentication failed")
		}
	case socks5.MethodNoAuth:
	default:
		_ = conn.Close()
		return nil, errors.New("socks5: no acceptable method")
	}

	addr, err := socks5.EncodeAddr(targetHost, targetPort)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if _, err := conn.Write(append([]byte{socks5.Version, socks5.CmdConnect, 0x00}, addr...)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	skip := 0
	switch head[3] {
	case socks5.ATYPIPv4:
		skip = 6
	case socks5.ATYPIPv6:
		skip = 18
	case socks5.ATYPDomain:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			_ = conn.Close()
			return nil, err
		}
		skip = int(l[0]) + 2
	default:
		_ = conn.Close()
		return nil, errors.New("socks5: bad reply address type")
	}
	if _, err := io.CopyN(io.Discard, conn, int64(skip)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if head[1] != socks5.ReplySuccess {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5: reply %#x", head[1])
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func TestE2ESOCKS5Inbound(t *testing.T) {
	h := startServer(t, "node-secret", nil, false)
	targetAddr := startEcho(t)
	targetHost, portStr, _ := net.SplitHostPort(targetAddr)
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatal(err)
	}

	cfg := baseClientCfg([]config.Node{{Addr: h.addr, Password: "node-secret"}})
	cfg.Inbound.Auth = []config.User{{Username: "alice", Password: "secret"}}
	app := startClient(t, cfg, nil)

	// 错误凭据应被拒绝。
	if conn, err := socks5Dial(t, app.SOCKS5Addr(), "alice", "wrong", targetHost, uint16(port)); err == nil {
		_ = conn.Close()
		t.Fatal("bad credentials must be rejected")
	}

	// 正确凭据：10 次经隧道回显。
	for i := 0; i < 10; i++ {
		conn, err := socks5Dial(t, app.SOCKS5Addr(), "alice", "secret", targetHost, uint16(port))
		if err != nil {
			t.Fatalf("socks5 dial %d: %v", i, err)
		}
		payload := []byte(fmt.Sprintf("ping-%d", i))
		if _, err := conn.Write(payload); err != nil {
			_ = conn.Close()
			t.Fatalf("write %d: %v", i, err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil {
			_ = conn.Close()
			t.Fatalf("read %d: %v", i, err)
		}
		_ = conn.Close()
		if string(got) != string(payload) {
			t.Fatalf("echo %d = %q, want %q", i, got, payload)
		}
	}
}

// lockedBuffer 是并发安全的日志缓冲（slog handler 可能多协程写入）。
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *lockedBuffer) findLine(substr string) string {
	for _, line := range strings.Split(b.String(), "\n") {
		if strings.Contains(line, substr) {
			return line
		}
	}
	return ""
}

func waitForLog(t *testing.T, buf *lockedBuffer, substr string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if line := buf.findLine(substr); line != "" {
			var record map[string]any
			if err := json.Unmarshal([]byte(line), &record); err != nil {
				t.Fatalf("log line is not valid JSON: %v (%q)", err, line)
			}
			return record
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("log line containing %q not found in:\n%s", substr, buf.String())
	return nil
}

func TestE2EMetricsAndStructuredLogs(t *testing.T) {
	serverLogs := &lockedBuffer{}
	clientLogs := &lockedBuffer{}
	serverLogger := slog.New(slog.NewJSONHandler(serverLogs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	clientLogger := slog.New(slog.NewJSONHandler(clientLogs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	h := startServer(t, "node-secret", serverLogger, true)
	target := startTLSTarget(t)

	cfg := baseClientCfg([]config.Node{{Addr: h.addr, Password: "node-secret"}})
	cfg.Metrics.Listen = "127.0.0.1:0"
	app := startClient(t, cfg, clientLogger)

	client := browser(t, "http://"+app.HTTPAddr(), 1)
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	// 客户端完成日志应包含验收字段。
	clientRecord := waitForLog(t, clientLogs, "request completed")
	assertLogFields(t, clientRecord, map[string]func(v any) error{
		"request_id": func(v any) error {
			s, _ := v.(string)
			if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(s) {
				return fmt.Errorf("request_id = %v", v)
			}
			return nil
		},
		"client_ip": func(v any) error {
			if v != "127.0.0.1" {
				return fmt.Errorf("client_ip = %v", v)
			}
			return nil
		},
		"upstream": func(v any) error {
			if s, _ := v.(string); s != h.addr {
				return fmt.Errorf("upstream = %v, want %s", v, h.addr)
			}
			return nil
		},
		"duration": func(v any) error {
			if s, _ := v.(string); s == "" {
				return errors.New("duration is empty")
			}
			return nil
		},
	})

	// 服务端隧道日志应包含同样字段。
	serverRecord := waitForLog(t, serverLogs, "tunnel completed")
	assertLogFields(t, serverRecord, map[string]func(v any) error{
		"request_id": func(v any) error {
			if s, _ := v.(string); len(s) != 16 {
				return fmt.Errorf("request_id = %v", v)
			}
			return nil
		},
		"client_ip": func(v any) error {
			if v != "127.0.0.1" {
				return fmt.Errorf("client_ip = %v", v)
			}
			return nil
		},
		"upstream": func(v any) error {
			if s, _ := v.(string); s == "" {
				return errors.New("upstream is empty")
			}
			return nil
		},
		"duration": func(v any) error {
			if s, _ := v.(string); s == "" {
				return errors.New("duration is empty")
			}
			return nil
		},
	})

	// /metrics 需暴露三个核心指标并记录本次请求。
	clientMetrics := scrapeMetrics(t, app.MetricsAddr())
	for _, name := range []string{"requests_total", "request_duration_seconds", "active_connections"} {
		if !strings.Contains(clientMetrics, name) {
			t.Fatalf("client /metrics missing %q", name)
		}
	}
	serverMetrics := scrapeMetrics(t, h.metricsAddr)
	for _, name := range []string{"requests_total", "request_duration_seconds", "active_connections"} {
		if !strings.Contains(serverMetrics, name) {
			t.Fatalf("server /metrics missing %q", name)
		}
	}
	waitForMetric(t, app.MetricsAddr(), `requests_total{proto="http",result="ok",route="proxy"} 1`)
	waitForMetric(t, h.metricsAddr, `requests_total{proto="tunnel",result="ok",route="direct"} 1`)
}

// assertLogFields 校验记录中各字段存在且满足断言。
func assertLogFields(t *testing.T, record map[string]any, checks map[string]func(any) error) {
	t.Helper()
	for key, check := range checks {
		value, ok := record[key]
		if !ok {
			t.Fatalf("log record missing %q: %v", key, record)
		}
		if err := check(value); err != nil {
			t.Fatalf("log field %q invalid: %v", key, err)
		}
	}
}
