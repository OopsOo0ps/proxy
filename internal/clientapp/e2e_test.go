package clientapp_test

import (
	"bufio"
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
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/clientapp"
	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/logging"
	"github.com/OopsOo0ps/proxy/internal/serverapp"
	"github.com/OopsOo0ps/proxy/internal/socks5"
	"github.com/OopsOo0ps/proxy/internal/testutil"
	"github.com/OopsOo0ps/proxy/internal/trojan"
)

func testTimeouts() config.Timeouts {
	return config.Timeouts{
		Dial:      config.Duration(5 * time.Second),
		Handshake: config.Duration(5 * time.Second),
		Idle:      config.Duration(30 * time.Second),
		Shutdown:  config.Duration(3 * time.Second),
	}
}

// testServerTimeouts 是测试用服务端超时：握手超时明显大于客户端预热池的
// 空闲 TTL（默认 5s，个别用例 30s），与生产默认 10s > 5s 的关系一致。
// 两者接近或相等时，空闲连接可能在池中就被服务端按握手超时回收并回放
// 伪装响应，把「领取竞态」人为放大成常态。
func testServerTimeouts() config.Timeouts {
	tt := testTimeouts()
	tt.Handshake = config.Duration(60 * time.Second)
	return tt
}

func boolPtr(b bool) *bool { return &b }

func intPtr(v int) *int { return &v }

// serverHandle 封装一个测试用 proxy-server。
type serverHandle struct {
	addr        string
	metricsAddr string
	stop        func()
}

// startServer 启动一个测试用 proxy-server（自签证书）。
func startServer(t *testing.T, password string, logger *slog.Logger, withMetrics bool) *serverHandle {
	t.Helper()
	return startServerWith(t, password, logger, withMetrics, nil)
}

// startServerWith 启动测试用 proxy-server；mutate 可在启动前调整配置（如连接上限）。
func startServerWith(t *testing.T, password string, logger *slog.Logger, withMetrics bool, mutate func(*config.Server)) *serverHandle {
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
		Timeouts: testServerTimeouts(),
		Log:      config.Log{Level: "debug", Format: "json"},
	}
	if withMetrics {
		cfg.Metrics.Listen = "127.0.0.1:0"
	}
	if mutate != nil {
		mutate(cfg)
	}
	app, err := serverapp.New(cfg, logger, nil)
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
	app, err := clientapp.New(cfg, logger, nil)
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
	clientLogs := &lockedBuffer{}
	clientLogger := slog.New(slog.NewJSONHandler(clientLogs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	app := startClient(t, cfg, clientLogger)

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

	// 验收一：至少 3 个节点全部可用——每个节点都实际承载过请求
	//（以服务端隧道完成日志为证据）。
	// 验收二：本轮所有连接的收尾记录都不得出现 error：收尾阶段 RST/FIN
	// 竞态曾把「数据已完整送达」的连接误记为 error（历史 flaky）；
	// 修复后入站侧对端主动中止按正常收尾分类，这里做全量断言。
	deadline := time.Now().Add(5 * time.Second)
	var perNode [][]map[string]any
	for {
		total := 0
		perNode = perNode[:0]
		for _, logs := range nodeLogs {
			records := parseRecords(t, logs, "tunnel completed")
			perNode = append(perNode, records)
			total += len(records)
		}
		if total >= success {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("隧道完成记录共 %d 条，少于成功请求数 %d", total, success)
		}
		time.Sleep(25 * time.Millisecond)
	}
	for i, records := range perNode {
		if len(records) == 0 {
			t.Errorf("节点 %d 未承载任何流量", i+1)
			continue
		}
		for _, rec := range records {
			if rec["result"] != "ok" {
				t.Errorf("节点 %d 出现非 ok 收尾记录: %v", i+1, rec)
			}
		}
		t.Logf("节点 %d 已成功承载流量（完成记录 %d 条）", i+1, len(records))
	}

	// 客户端侧：每个成功请求的 CONNECT 收尾记录同样不得出现 error。
	for _, rec := range waitForRecordCount(t, clientLogs, `"method":"CONNECT"`, success) {
		if rec["result"] != "ok" {
			t.Errorf("客户端出现非 ok 收尾记录: %v", rec)
		}
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

// parseRecords 解析缓冲中所有包含 substr 的 JSON 记录行。
func parseRecords(t *testing.T, buf *lockedBuffer, substr string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(buf.String(), "\n") {
		if !strings.Contains(line, substr) {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not valid JSON: %v (%q)", err, line)
		}
		out = append(out, rec)
	}
	return out
}

// waitForRecordCount 轮询缓冲，直到包含 substr 的记录达到 want 条后返回全部记录。
func waitForRecordCount(t *testing.T, buf *lockedBuffer, substr string, want int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var records []map[string]any
	for time.Now().Before(deadline) {
		records = parseRecords(t, buf, substr)
		if len(records) >= want {
			return records
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("记录数 %d < %d（substr=%q）:\n%s", len(records), want, substr, buf.String())
	return nil
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

// getJSON 请求端点并把 JSON 响应解码到 out，返回状态码。
func getJSON(t *testing.T, url string, out any) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
	return resp.StatusCode
}

func TestE2EHealthAndStatsEndpoints(t *testing.T) {
	h := startServer(t, "node-secret", nil, false)
	cfg := baseClientCfg([]config.Node{{Addr: h.addr, Password: "node-secret"}})
	cfg.Metrics.Listen = "127.0.0.1:0"
	app := startClient(t, cfg, nil)

	// 健康：200 + status ok + uptime。
	var health struct {
		Status string  `json:"status"`
		Uptime float64 `json:"uptime"`
	}
	if code := getJSON(t, "http://"+app.MetricsAddr()+"/health", &health); code != http.StatusOK {
		t.Fatalf("/health status = %d, want 200", code)
	}
	if health.Status != "ok" || health.Uptime < 0 {
		t.Fatalf("/health = %+v", health)
	}

	// 状态：连接数、上游节点状态与内存占用。
	var stats struct {
		Version     string  `json:"version"`
		Uptime      float64 `json:"uptime"`
		Connections struct {
			Total int64 `json:"total"`
		} `json:"connections"`
		Upstreams []struct {
			Addr    string `json:"addr"`
			Healthy bool   `json:"healthy"`
			Fails   int    `json:"fails"`
		} `json:"upstreams"`
		Memory struct {
			AllocBytes uint64 `json:"alloc_bytes"`
			SysBytes   uint64 `json:"sys_bytes"`
			NumGC      uint32 `json:"num_gc"`
			Goroutines int    `json:"goroutines"`
		} `json:"memory"`
	}
	if code := getJSON(t, "http://"+app.MetricsAddr()+"/stats", &stats); code != http.StatusOK {
		t.Fatalf("/stats status = %d, want 200", code)
	}
	if stats.Version == "" {
		t.Fatal("/stats version 为空")
	}
	if len(stats.Upstreams) != 1 {
		t.Fatalf("upstreams = %+v, want 1 个节点", stats.Upstreams)
	}
	up := stats.Upstreams[0]
	if up.Addr != h.addr || !up.Healthy || up.Fails != 0 {
		t.Fatalf("upstream = %+v, want 健康节点 %s", up, h.addr)
	}
	if stats.Connections.Total != 0 {
		t.Fatalf("无流量时 connections.total = %d, want 0", stats.Connections.Total)
	}
	if stats.Memory.SysBytes == 0 || stats.Memory.Goroutines <= 0 {
		t.Fatalf("memory = %+v", stats.Memory)
	}
}

func TestE2EHealthReportsNodesCooling(t *testing.T) {
	// 节点指向一个刚关闭的端口：请求失败后节点进入冷却，/health 应转为 503。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close()

	cfg := baseClientCfg([]config.Node{{Addr: deadAddr, Password: "pw"}})
	cfg.Metrics.Listen = "127.0.0.1:0"
	app := startClient(t, cfg, nil)

	// 触发一次失败的拨号（失败在响应前已计入节点状态）。
	target := startTLSTarget(t)
	client := browser(t, "http://"+app.HTTPAddr(), 1)
	if resp, err := client.Get(target.URL); err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode < 500 {
			t.Fatalf("expected proxy failure, got %d", resp.StatusCode)
		}
	}

	var health struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if code := getJSON(t, "http://"+app.MetricsAddr()+"/health", &health); code != http.StatusServiceUnavailable {
		t.Fatalf("/health status = %d, want 503", code)
	}
	if health.Status != "unavailable" || !strings.Contains(health.Reason, "no healthy exit nodes") {
		t.Fatalf("/health = %+v", health)
	}

	var stats struct {
		Upstreams []struct {
			Addr              string  `json:"addr"`
			Healthy           bool    `json:"healthy"`
			Fails             int     `json:"fails"`
			CooldownRemaining float64 `json:"cooldown_remaining"`
		} `json:"upstreams"`
	}
	if code := getJSON(t, "http://"+app.MetricsAddr()+"/stats", &stats); code != http.StatusOK {
		t.Fatalf("/stats status = %d, want 200", code)
	}
	if len(stats.Upstreams) != 1 {
		t.Fatalf("upstreams = %+v", stats.Upstreams)
	}
	up := stats.Upstreams[0]
	if up.Healthy || up.Fails != 1 || up.CooldownRemaining <= 0 {
		t.Fatalf("upstream = %+v, want 冷却中（1 次失败）", up)
	}
}

// durationPtr 返回 config.Duration 指针（测试配置构造用）。
func durationPtr(d time.Duration) *config.Duration {
	v := config.Duration(d)
	return &v
}

// freeTCPAddr 返回一个刚释放的本地端口地址（供“同址重启节点”的用例）。
func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// upstreamStats 是 /stats 中单个上游节点的字段（测试用子集）。
type upstreamStats struct {
	Addr              string  `json:"addr"`
	Healthy           bool    `json:"healthy"`
	Fails             int     `json:"fails"`
	CooldownRemaining float64 `json:"cooldown_remaining"`
	Removed           bool    `json:"removed"`
	ProbeFails        int     `json:"probe_fails"`
	Idle              int     `json:"idle"`
}

// waitUpstream 轮询 /stats 直到 addr 节点满足条件，返回最后一次快照。
func waitUpstream(t *testing.T, metricsAddr, addr string, cond func(upstreamStats) bool) upstreamStats {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	var last upstreamStats
	for time.Now().Before(deadline) {
		var stats struct {
			Upstreams []upstreamStats `json:"upstreams"`
		}
		if code := getJSON(t, "http://"+metricsAddr+"/stats", &stats); code != http.StatusOK {
			t.Fatalf("/stats status = %d, want 200", code)
		}
		for _, up := range stats.Upstreams {
			if up.Addr == addr {
				last = up
				if cond(up) {
					return up
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("upstream %s not in expected state, last = %+v", addr, last)
	return last
}

// metricSeriesValue 提取 /metrics 中以 series 为前缀的单行指标值；未找到返回 0。
func metricSeriesValue(t *testing.T, metricsAddr, series string) int {
	t.Helper()
	body := scrapeMetrics(t, metricsAddr)
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, series) {
			continue
		}
		fields := strings.Fields(line)
		v, err := strconv.Atoi(fields[len(fields)-1])
		if err != nil {
			t.Fatalf("parse metric line %q: %v", line, err)
		}
		return v
	}
	return 0
}

func TestE2EHealthCheckRemovesAndRejoinsNode(t *testing.T) {
	// 稳定节点 + 可重启节点（固定端口，便于同址重启后再加回）。
	stable := startServer(t, "stable-secret", nil, false)
	flakyAddr := freeTCPAddr(t)
	flakyLogs := &lockedBuffer{}
	flakyLogger := slog.New(slog.NewJSONHandler(flakyLogs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	flaky := startServerWith(t, "flaky-secret", flakyLogger, false, func(c *config.Server) {
		c.Listen = flakyAddr
	})

	nodes := []config.Node{
		{Addr: stable.addr, Password: "stable-secret"},
		{Addr: flaky.addr, Password: "flaky-secret"},
	}
	target := startTLSTarget(t)
	cfg := baseClientCfg(nodes)
	cfg.Metrics.Listen = "127.0.0.1:0"
	cfg.Pool = config.Pool{MaxIdle: intPtr(2), IdleTTL: config.Duration(30 * time.Second)}
	cfg.HealthCheck = config.HealthCheck{
		Interval:  durationPtr(100 * time.Millisecond),
		Timeout:   config.Duration(300 * time.Millisecond),
		Failures:  intPtr(2),
		Successes: intPtr(2),
	}
	app := startClient(t, cfg, nil)

	// 初始：两个节点都健康，且各自预热 2 条空闲连接等待摘除时被清理。
	flakyIdle := `upstream_pool_idle_connections{node="` + flaky.addr + `"}`
	waitForMetric(t, app.MetricsAddr(), flakyIdle+" 2")
	waitForMetric(t, app.MetricsAddr(), `upstream_healthy{node="`+flaky.addr+`"} 1`)

	// 停掉 flaky 节点：健康检查连续失败后应摘除（硬摘除），并清空其空闲连接。
	flaky.stop()
	up := waitUpstream(t, app.MetricsAddr(), flaky.addr, func(up upstreamStats) bool { return up.Removed })
	if up.Healthy || up.ProbeFails < 2 {
		t.Fatalf("removed upstream = %+v, want 已摘除且探测失败 ≥ 2", up)
	}
	waitForMetric(t, app.MetricsAddr(), `upstream_healthy{node="`+flaky.addr+`"} 0`)
	waitForMetric(t, app.MetricsAddr(), flakyIdle+" 0")
	waitForMetric(t, app.MetricsAddr(), `upstream_health_probes_total{node="`+flaky.addr+`",result="failure"}`)

	// 剩余健康节点仍然可用：流量全部成功，/health 保持 200。
	client := browser(t, "http://"+app.HTTPAddr(), 10)
	for i := 0; i < 6; i++ {
		resp, err := client.Get(target.URL)
		if err != nil {
			t.Fatalf("request %d during removal: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200", i, resp.StatusCode)
		}
	}
	var health struct {
		Status string `json:"status"`
	}
	if code := getJSON(t, "http://"+app.MetricsAddr()+"/health", &health); code != http.StatusOK || health.Status != "ok" {
		t.Fatalf("/health = %d/%s, want 200/ok（仍有健康节点）", code, health.Status)
	}

	// 同址重启 flaky 节点：健康检查连续成功达阈值后自动加回并重新承载流量。
	flaky = startServerWith(t, "flaky-secret", flakyLogger, false, func(c *config.Server) {
		c.Listen = flakyAddr
	})
	up = waitUpstream(t, app.MetricsAddr(), flaky.addr, func(up upstreamStats) bool { return !up.Removed })
	if !up.Healthy || up.ProbeFails != 0 {
		t.Fatalf("rejoined upstream = %+v, want 已加回且探测失败清零", up)
	}
	waitForMetric(t, app.MetricsAddr(), `upstream_healthy{node="`+flaky.addr+`"} 1`)
	waitForMetric(t, app.MetricsAddr(), `upstream_health_probes_total{node="`+flaky.addr+`",result="success"}`)

	for i := 0; i < 4; i++ {
		resp, err := client.Get(target.URL)
		if err != nil {
			t.Fatalf("request %d after rejoin: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d after rejoin status = %d, want 200", i, resp.StatusCode)
		}
	}
	// 加回后的节点应实际承载隧道流量（以服务端完成日志为证据）。
	record := waitForLog(t, flakyLogs, "tunnel completed")
	assertLogFields(t, record, map[string]func(any) error{
		"result": func(v any) error {
			if v != "ok" {
				return fmt.Errorf("result = %v", v)
			}
			return nil
		},
	})
}

func TestE2EUpstreamPoolClaimHit(t *testing.T) {
	h := startServer(t, "node-secret", nil, false)
	target := startTLSTarget(t)

	cfg := baseClientCfg([]config.Node{{Addr: h.addr, Password: "node-secret"}})
	cfg.Pool = config.Pool{MaxIdle: intPtr(2), IdleTTL: config.Duration(3 * time.Second)}
	cfg.Metrics.Listen = "127.0.0.1:0"
	app := startClient(t, cfg, nil)

	// 启动预热完成后应有 2 条空闲隧道。
	idleMetric := `upstream_pool_idle_connections{node="` + h.addr + `"}`
	waitForMetric(t, app.MetricsAddr(), idleMetric+" 2")

	// 首次请求应命中预热连接（领取计数 hit），而非新建握手。
	client := browser(t, "http://"+app.HTTPAddr(), 1)
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	waitForMetric(t, app.MetricsAddr(), `upstream_pool_claims_total{node="`+h.addr+`",result="hit"} 1`)

	// 领取后异步补齐，/stats 中应能看到空闲连接数恢复为 2。
	waitForMetric(t, app.MetricsAddr(), idleMetric+" 2")
	var stats struct {
		Upstreams []struct {
			Addr string `json:"addr"`
			Idle int    `json:"idle"`
		} `json:"upstreams"`
	}
	if code := getJSON(t, "http://"+app.MetricsAddr()+"/stats", &stats); code != http.StatusOK {
		t.Fatalf("/stats status = %d, want 200", code)
	}
	if len(stats.Upstreams) != 1 || stats.Upstreams[0].Addr != h.addr || stats.Upstreams[0].Idle != 2 {
		t.Fatalf("upstreams = %+v, want %s idle=2", stats.Upstreams, h.addr)
	}
}

func TestE2EShutdownDrainsInflightRequest(t *testing.T) {
	// 完整链路：client HTTP 入站 → 隧道 → server → echo 目标；
	// 关停后存量隧道必须能继续完成往返，新连接立即被拒绝。
	echoAddr := startEcho(t)
	h := startServer(t, "node-secret", nil, false)

	cfg := baseClientCfg([]config.Node{{Addr: h.addr, Password: "node-secret"}})
	app, err := clientapp.New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("clientapp.New: %v", err)
	}
	if err := app.Listen(); err != nil {
		t.Fatalf("clientapp.Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveErrCh := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		serveErrCh <- app.Serve(ctx)
		close(finished)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("client Serve did not stop")
			return
		}
		if err := <-serveErrCh; err != nil {
			t.Errorf("client Serve: %v", err)
		}
	})

	conn, err := net.Dial("tcp", app.HTTPAddr())
	if err != nil {
		t.Fatalf("dial client: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echoAddr, echoAddr); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT status = %q, want 200", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT header: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	// 发起关停：入站监听必须停止接受新连接。
	cancel()
	refused := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", app.HTTPAddr(), 300*time.Millisecond)
		if err != nil {
			refused = true
			break
		}
		_ = c.Close()
		time.Sleep(20 * time.Millisecond)
	}
	if !refused {
		t.Fatal("client still accepts new connections after shutdown")
	}

	// 存量隧道在关停后必须继续可用（drain 不丢请求）。
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte("e2e drain payload")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write over draining tunnel: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read over draining tunnel: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}

	_ = conn.Close()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("client Serve did not return after the in-flight tunnel closed")
	}
}

// rawTunnelConnect 经代理建立 CONNECT 隧道并读完响应头；非 200 时返回错误。
func rawTunnelConnect(proxyAddr, target string) (net.Conn, error) {
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		_ = conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if !strings.Contains(status, "200") {
		_ = conn.Close()
		return nil, fmt.Errorf("CONNECT status = %q", strings.TrimSpace(status))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		if line == "\r\n" {
			break
		}
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// waitTunnelConnect 轮询直到 CONNECT 成功（用于等待连接上限释放）。
func waitTunnelConnect(t *testing.T, proxyAddr, target string, timeout time.Duration) net.Conn {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := rawTunnelConnect(proxyAddr, target)
		if err == nil {
			return conn
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("CONNECT did not recover within %v: %v", timeout, lastErr)
	return nil
}

func TestE2EOverloadReturnsClearErrorAndRecovers(t *testing.T) {
	echoAddr := startEcho(t)
	h := startServer(t, "node-secret", nil, false)

	cfg := baseClientCfg([]config.Node{{Addr: h.addr, Password: "node-secret"}})
	cfg.Limits = config.Limits{MaxConnections: intPtr(1)}
	cfg.Metrics.Listen = "127.0.0.1:0"
	app := startClient(t, cfg, nil)

	// 隧道 1 占满唯一名额，并确认隧道确实在工作。
	conn1, err := rawTunnelConnect(app.HTTPAddr(), echoAddr)
	if err != nil {
		t.Fatalf("first tunnel: %v", err)
	}
	defer func() { _ = conn1.Close() }()
	_ = conn1.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn1.Write([]byte("hold")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn1, got); err != nil {
		t.Fatal(err)
	}

	// HTTP 入站第 2 个连接：连接级拒绝，直接回 503。
	c2, err := net.Dial("tcp", app.HTTPAddr())
	if err != nil {
		t.Fatalf("dial client http: %v", err)
	}
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	respLine, err := bufio.NewReader(c2).ReadString('\n')
	if err != nil {
		t.Fatalf("read overload response: %v", err)
	}
	if !strings.Contains(respLine, "503") {
		t.Fatalf("over-limit HTTP response = %q, want 503", strings.TrimSpace(respLine))
	}
	_ = c2.Close()

	// SOCKS5 入站：认证前没有专用过载码，回 0x05 0xFF 后关闭。
	c3, err := net.Dial("tcp", app.SOCKS5Addr())
	if err != nil {
		t.Fatalf("dial client socks5: %v", err)
	}
	_ = c3.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c3.Write([]byte{socks5.Version, 1, socks5.MethodNoAuth}); err != nil {
		t.Fatal(err)
	}
	var sel [2]byte
	if _, err := io.ReadFull(c3, sel[:]); err != nil {
		t.Fatalf("read socks5 overload reply: %v", err)
	}
	if sel[0] != socks5.Version || sel[1] != socks5.MethodNoAcceptable {
		t.Fatalf("socks5 overload reply = %v, want [0x05 0xFF]", sel)
	}
	_ = c3.Close()

	waitForMetric(t, app.MetricsAddr(), `connections_rejected_total{proto="http"} 1`)
	waitForMetric(t, app.MetricsAddr(), `connections_rejected_total{proto="socks5"} 1`)

	var stats struct {
		Limit struct {
			MaxConnections int    `json:"max_connections"`
			Current        int    `json:"current"`
			Rejected       uint64 `json:"rejected"`
		} `json:"limit"`
	}
	if code := getJSON(t, "http://"+app.MetricsAddr()+"/stats", &stats); code != http.StatusOK {
		t.Fatalf("/stats status = %d, want 200", code)
	}
	if stats.Limit.MaxConnections != 1 || stats.Limit.Current != 1 || stats.Limit.Rejected != 2 {
		t.Fatalf("limit = %+v, want max=1 current=1 rejected=2", stats.Limit)
	}

	// 释放名额后应恢复可用（超限不是熔断）。
	_ = conn1.Close()
	conn4 := waitTunnelConnect(t, app.HTTPAddr(), echoAddr, 3*time.Second)
	_ = conn4.Close()
}

func TestE2ETunnelOverloadRejectsAndRecovers(t *testing.T) {
	echoAddr := startEcho(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	h := startServerWith(t, "node-secret", nil, true, func(cfg *config.Server) {
		cfg.Limits = config.Limits{MaxConnections: intPtr(1)}
	})
	dial := func() (net.Conn, error) {
		return trojan.Dial(context.Background(), trojan.ClientConfig{
			ServerAddr: h.addr,
			Password:   "node-secret",
			TLSConfig:  &tls.Config{InsecureSkipVerify: true},
		}, host, uint16(port))
	}

	// 隧道 1 占满唯一名额，并确认转发可用。
	conn1, err := dial()
	if err != nil {
		t.Fatalf("first tunnel: %v", err)
	}
	defer func() { _ = conn1.Close() }()
	_ = conn1.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte("overload-first")
	if _, err := conn1.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn1, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}

	// 第二条隧道：名额已满，服务端 accept 后立即关闭，客户端握手必须失败。
	if conn2, err := dial(); err == nil {
		_ = conn2.Close()
		t.Fatal("second tunnel should be rejected while the limit is reached")
	}

	waitForMetric(t, h.metricsAddr, `connections_rejected_total{proto="tunnel"} 1`)
	var stats struct {
		Limit struct {
			MaxConnections int    `json:"max_connections"`
			Current        int    `json:"current"`
			Rejected       uint64 `json:"rejected"`
		} `json:"limit"`
	}
	if code := getJSON(t, "http://"+h.metricsAddr+"/stats", &stats); code != http.StatusOK {
		t.Fatalf("/stats status = %d, want 200", code)
	}
	if stats.Limit.MaxConnections != 1 || stats.Limit.Current != 1 || stats.Limit.Rejected != 1 {
		t.Fatalf("limit = %+v, want max=1 current=1 rejected=1", stats.Limit)
	}

	// 释放名额后新隧道应恢复可用。
	_ = conn1.Close()
	deadline := time.Now().Add(3 * time.Second)
	var conn3 net.Conn
	for time.Now().Before(deadline) {
		conn3, err = dial()
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("tunnel did not recover after release: %v", err)
	}
	_ = conn3.Close()
}

func TestE2ELogLevelEndpointAndDynamicFiltering(t *testing.T) {
	h := startServer(t, "node-secret", nil, false)
	// 使用真实的日志控制器 + 可观察 logger 组装客户端，覆盖“运行时切换”全链路。
	var logs lockedBuffer
	logger, logCtrl := logging.NewControlWithWriter(&logs, "info", "json")

	cfg := baseClientCfg([]config.Node{{Addr: h.addr, Password: "node-secret"}})
	cfg.Metrics.Listen = "127.0.0.1:0"
	app, err := clientapp.New(cfg, logger, logCtrl)
	if err != nil {
		t.Fatalf("clientapp.New: %v", err)
	}
	if err := app.Listen(); err != nil {
		t.Fatalf("clientapp.Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveErrCh := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		serveErrCh <- app.Serve(ctx)
		close(finished)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("client Serve did not stop")
			return
		}
		if err := <-serveErrCh; err != nil {
			t.Errorf("client Serve: %v", err)
		}
	})

	// 触发一条 debug 级日志：SOCKS5 非法协议版本（info 级别下应被抑制）。
	triggerDebugLog := func() {
		t.Helper()
		conn, err := net.Dial("tcp", app.SOCKS5Addr())
		if err != nil {
			t.Fatalf("dial socks5: %v", err)
		}
		_, _ = conn.Write([]byte{0x04, 0x01, 0x00}) // 非法版本，握手失败走 debug 日志
		_ = conn.Close()
	}

	triggerDebugLog()
	time.Sleep(150 * time.Millisecond)
	if strings.Contains(logs.String(), "socks5 handshake failed") {
		t.Fatal("debug log must be suppressed at info level")
	}

	// GET /log/level 返回当前级别。
	var levelResp struct {
		Level string `json:"level"`
	}
	if code := getJSON(t, "http://"+app.MetricsAddr()+"/log/level", &levelResp); code != http.StatusOK || levelResp.Level != "info" {
		t.Fatalf("GET /log/level = %d %+v, want info", code, levelResp)
	}

	// PUT 切到 debug：切换成功且随后 debug 日志可见。
	req, err := http.NewRequest(http.MethodPut, "http://"+app.MetricsAddr()+"/log/level?level=debug", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT /log/level: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"level":"debug"`) {
		t.Fatalf("PUT /log/level = %d %q", resp.StatusCode, body)
	}
	waitForLog(t, &logs, "log level changed")
	triggerDebugLog()
	waitForLog(t, &logs, "socks5 handshake failed")

	// 非法级别返回 400，级别保持不变。
	req, err = http.NewRequest(http.MethodPut, "http://"+app.MetricsAddr()+"/log/level?level=verbose", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid level = %d, want 400", resp.StatusCode)
	}
	if logCtrl.LevelVar().Level() != slog.LevelDebug {
		t.Fatalf("level changed by invalid request: %v", logCtrl.LevelVar().Level())
	}
}

// TestE2EDNSGatewayRoutesRemoteAndDirect 端到端验证 DNS 网关（路线图 3.1）：
// 代理名字的查询经出口节点远程解析（远端解析器应答，本地解析器零触达），
// 直连名字走本地解析器；两条路径的指标分别可见。
func TestE2EDNSGatewayRoutesRemoteAndDirect(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// “出口侧”解析器：逻辑上位于出口，经隧道可达（测试中同机 127.0.0.1）。
	remoteDNS, err := testutil.StartDNSServer(func(q []byte, _ string) []byte {
		return testutil.BuildReply(q, 0, []netip.Addr{netip.MustParseAddr("10.10.10.10")}, false)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remoteDNS.Close)

	// 本地解析器：只应服务直连名字；代理名字触达它即为 remote DNS 路径被破坏。
	localDNS, err := testutil.StartDNSServer(func(q []byte, _ string) []byte {
		return testutil.BuildReply(q, 0, []netip.Addr{netip.MustParseAddr("192.168.1.10")}, false)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(localDNS.Close)

	h := startServer(t, "node-secret", logger, false)

	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte("rules:\n  - action: direct\n    match: [\"*.lan\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := baseClientCfg([]config.Node{{Addr: h.addr, Password: "node-secret"}})
	cfg.Routing = config.Routing{Default: "proxy", RulesFile: rulesPath, PrivateDirect: boolPtr(false)}
	cfg.Metrics.Listen = "127.0.0.1:0"
	cfg.DNS = config.DNS{
		Listen:  "127.0.0.1:0",
		Remote:  remoteDNS.Addr,
		Local:   []string{localDNS.Addr},
		Timeout: config.Duration(3 * time.Second),
	}
	app := startClient(t, cfg, logger)

	// 代理名字：经出口节点远程解析，答案为远端解析器的记录。
	resp, err := testutil.QueryUDP(app.DNSAddr(), testutil.BuildAQuery("site.test", 0x0101), 5*time.Second)
	if err != nil {
		t.Fatalf("query site.test: %v", err)
	}
	if ips := testutil.DNSAnswerIPs(resp); len(ips) != 1 || ips[0].String() != "10.10.10.10" {
		t.Fatalf("site.test answer = %v, want [10.10.10.10]（应来自远端解析器）", ips)
	}
	if remoteDNS.TCPHits() != 1 {
		t.Fatalf("remote tcp hits = %d, want 1", remoteDNS.TCPHits())
	}
	if localDNS.UDPHits()+localDNS.TCPHits() != 0 {
		t.Fatalf("代理名字触达了本地解析器（udp=%d tcp=%d）：remote DNS 路径被破坏",
			localDNS.UDPHits(), localDNS.TCPHits())
	}

	// 直连名字：走本地解析器。
	resp2, err := testutil.QueryUDP(app.DNSAddr(), testutil.BuildAQuery("printer.lan", 0x0202), 5*time.Second)
	if err != nil {
		t.Fatalf("query printer.lan: %v", err)
	}
	if ips := testutil.DNSAnswerIPs(resp2); len(ips) != 1 || ips[0].String() != "192.168.1.10" {
		t.Fatalf("printer.lan answer = %v, want [192.168.1.10]（应来自本地解析器）", ips)
	}
	if localDNS.UDPHits() != 1 {
		t.Fatalf("local udp hits = %d, want 1", localDNS.UDPHits())
	}
	if remoteDNS.TCPHits() != 1 {
		t.Fatalf("remote tcp hits = %d, want 1（直连名字不得再走出口）", remoteDNS.TCPHits())
	}

	// 指标按路径可见。
	waitForMetric(t, app.MetricsAddr(), `dns_queries_total{result="ok",route="proxy"} 1`)
	waitForMetric(t, app.MetricsAddr(), `dns_queries_total{result="ok",route="direct"} 1`)
}
