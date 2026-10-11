// Package integration 提供黑盒集成测试：构建并启动真实的 proxy-server /
// proxy-client 二进制，全部交互只经过进程边界（网络请求、结构化日志、HTTP 端点），
// 覆盖「启动服务 → 发请求 → 验证分流 → 验证指标 → 优雅关停」全链路。
//
// 与 internal/... 下的进程内端到端用例不同，这里的用例验证的是最终交付物本身：
// 配置解析、启动与监听、请求转发、按规则分流、指标暴露与信号处理。
// 端口全部动态分配（配置里写 :0，从启动日志读取实际地址），不依赖固定端口。
package integration

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/testutil"
)

// binDir 是 TestMain 构建出的二进制目录，全部用例共享。
var binDir string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "proxy-integration-bin-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration: create temp dir: %v\n", err)
		os.Exit(1)
	}
	code := buildBinaries(dir)
	if code == 0 {
		binDir = dir
		code = m.Run()
	}
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// buildBinaries 构建被测二进制；成功返回 0，失败打印原因并返回 1。
func buildBinaries(dir string) int {
	root, err := moduleRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration: %v\n", err)
		return 1
	}
	for _, bin := range []struct{ name, pkg string }{
		{"proxy-server", "./cmd/server"},
		{"proxy-client", "./cmd/client"},
	} {
		out := filepath.Join(dir, bin.name)
		cmd := exec.Command("go", "build", "-o", out, bin.pkg)
		cmd.Dir = root
		if combined, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "integration: build %s: %v\n%s", bin.name, err, combined)
			return 1
		}
	}
	return 0
}

// moduleRoot 定位包含 go.mod 的仓库根目录（本文件位于 test/integration/）。
func moduleRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("runtime.Caller failed")
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(file)))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return "", fmt.Errorf("go.mod not found at %s: %w", root, err)
	}
	return root, nil
}

// TestBinariesEndToEndRoutingAndMetrics 是 3.7 集成测试主链路：
// 构建并启动真实二进制，经进程边界完成
// 启动服务 → 发请求（HTTP 转发 / HTTPS CONNECT / SOCKS5 / 原始 CONNECT）→
// 验证分流（指标、日志、服务端隧道计数）→ 验证指标（/metrics 三类核心序列）→
// SIGTERM 优雅关停。
//
// 分流验证的关键设计：两个目标站点都监听本机，但以不同主机形式访问——
// 127.0.0.1（IP 字面量）命中规则文件的 direct 规则；localhost（域名）不命中
// 规则、走默认 proxy，由出口侧解析后回连本机。直连请求完成后立即断言服务端
// 「成功隧道请求数 == 0」，从服务端侧独立证明该请求确实没有经过隧道。
// SOCKS5 与 CONNECT 两个请求还要求「读到 EOF」：目标先关闭时，FIN 必须
// 逐层传播到入站客户端（半关闭语义），否则会以读超时暴露。
func TestBinariesEndToEndRoutingAndMetrics(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test builds and runs the real binaries; skipped with -short")
	}

	dir := t.TempDir()
	certFile, keyFile, err := testutil.WriteTLSCertFiles(dir)
	if err != nil {
		t.Fatalf("write TLS cert: %v", err)
	}

	// 本地目标站点：directTarget 走直连；proxy*Target 必须经过隧道。
	directTarget := httptest.NewServer(targetHandler("direct-ok"))
	t.Cleanup(directTarget.Close)
	directTargetAddr := directTarget.Listener.Addr().String()
	proxyTLSTarget := startTargetOn(t, "127.0.0.1:0", "proxy-tls-ok", true)
	proxySOCKS5Target := startTargetOn(t, "127.0.0.1:0", "proxy-socks-ok", false)
	// 经代理访问时使用域名 localhost：不命中任何直连规则，客户端不解析，
	// 域名随隧道到服务端解析（remote DNS），最终仍连回本机目标站点。
	proxyTLSURL := "https://localhost:" + portOf(t, proxyTLSTarget.Listener.Addr().String())
	socksTargetAddr := "localhost:" + portOf(t, proxySOCKS5Target.Listener.Addr().String())

	// ---- 启动服务：proxy-server（远端出口）----
	serverConfig := writeFile(t, dir, "server.yaml", fmt.Sprintf(`
listen: "127.0.0.1:0"
tls:
  cert_file: %q
  key_file: %q
users:
  - username: node-user
    password: node-secret
metrics:
  listen: "127.0.0.1:0"
log:
  level: info
  format: json
`, certFile, keyFile))
	serverProc := startProcess(t, "proxy-server", filepath.Join(binDir, "proxy-server"), "-config", serverConfig)
	serverListen := waitForRecords(t, serverProc, "listening", 1, 10*time.Second)[0]
	tunnelAddr := strField(t, serverProc, serverListen, "tunnel")
	serverMetricsAddr := strField(t, serverProc, serverListen, "metrics")
	waitForStatusOK(t, serverMetricsAddr, 10*time.Second)

	// ---- 启动服务：proxy-client（本机入口）----
	rulesConfig := writeFile(t, dir, "rules.yaml", `default: proxy
rules:
  - action: direct
    match: ["127.0.0.1"]
`)
	clientConfig := writeFile(t, dir, "client.yaml", fmt.Sprintf(`
inbound:
  http: "127.0.0.1:0"
  socks5: "127.0.0.1:0"
  auth:
    - username: alice
      password: change-me
nodes:
  - addr: %q
    password: node-secret
tls:
  insecure_skip_verify: true
routing:
  default: proxy
  private_direct: false
  rules_file: %q
metrics:
  listen: "127.0.0.1:0"
log:
  level: info
  format: json
`, tunnelAddr, rulesConfig))
	clientProc := startProcess(t, "proxy-client", filepath.Join(binDir, "proxy-client"), "-config", clientConfig)
	clientListen := waitForRecords(t, clientProc, "listening", 1, 10*time.Second)[0]
	httpAddr := strField(t, clientProc, clientListen, "http")
	socks5Addr := strField(t, clientProc, clientListen, "socks5")
	clientMetricsAddr := strField(t, clientProc, clientListen, "metrics")
	waitForStatusOK(t, clientMetricsAddr, 10*time.Second)

	// 浏览器式 HTTP 客户端：经客户端 HTTP 入站（携带代理认证）。
	proxyURL, err := url.Parse("http://alice:change-me@" + httpAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	proxyClient := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // 目标站点为本地自签证书
			DisableKeepAlives: true,
		},
	}

	// ---- 发请求 1：直连分流（命中 rules_file 的 direct 规则）----
	expectBody(t, proxyClient, "http://"+directTargetAddr+"/direct", "direct-ok")
	waitForMetricSum(t, clientMetricsAddr, "requests_total",
		map[string]string{"proto": "http", "route": "direct", "result": "ok"}, 1)
	// 直连不触碰隧道：服务端此刻不应有任何成功的隧道请求。
	if got := sumSamples(metricSamples(t, fetchBody(t, "http://"+serverMetricsAddr+"/metrics"), "requests_total"),
		map[string]string{"proto": "tunnel", "result": "ok"}); got != 0 {
		t.Fatalf("直连请求不应经过隧道，但服务端成功隧道请求数 = %v", got)
	}

	// ---- 发请求 2：代理分流（HTTPS CONNECT → Trojan 隧道）----
	expectBody(t, proxyClient, proxyTLSURL, "proxy-tls-ok")
	waitForMetricSum(t, clientMetricsAddr, "requests_total",
		map[string]string{"proto": "http", "route": "proxy", "result": "ok"}, 1)
	waitForMetricSum(t, serverMetricsAddr, "requests_total",
		map[string]string{"proto": "tunnel", "result": "ok"}, 1)

	// ---- 发请求 3：SOCKS5 入站 + 代理分流（用户名密码认证）----
	// 读到 EOF（而非依赖 Content-Length）才能证明 FIN 沿全链路传播：
	// 目标先关闭时，任何一层丢掉半关闭，这里都会以读超时暴露。
	conn := socks5Connect(t, socks5Addr, "alice", "change-me", socksTargetAddr)
	defer func() { _ = conn.Close() }()
	if _, err := fmt.Fprintf(conn, "GET /socks HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", socksTargetAddr); err != nil {
		t.Fatalf("socks5 write request: %v", err)
	}
	if got := readUntilEOF(t, conn, "socks5"); !strings.Contains(got, "proxy-socks-ok") {
		t.Fatalf("socks5 response = %q, want contain %q", got, "proxy-socks-ok")
	}
	// 读侧已见 EOF；随后关闭本端让转发收尾（指标在收尾时记录）。
	_ = conn.Close()
	waitForMetricSum(t, clientMetricsAddr, "requests_total",
		map[string]string{"proto": "socks5", "route": "proxy", "result": "ok"}, 1)
	waitForMetricSum(t, serverMetricsAddr, "requests_total",
		map[string]string{"proto": "tunnel", "result": "ok"}, 2)

	// ---- 发请求 4：HTTP CONNECT 入站读到 EOF（同样验证半关闭传播）----
	connectConn := rawConnect(t, httpAddr, "alice", "change-me", socksTargetAddr)
	defer func() { _ = connectConn.Close() }()
	if _, err := fmt.Fprintf(connectConn, "GET /connect HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", socksTargetAddr); err != nil {
		t.Fatalf("CONNECT write request: %v", err)
	}
	if got := readUntilEOF(t, connectConn, "CONNECT"); !strings.Contains(got, "proxy-socks-ok") {
		t.Fatalf("CONNECT response = %q, want contain %q", got, "proxy-socks-ok")
	}
	_ = connectConn.Close()
	waitForMetricSum(t, clientMetricsAddr, "requests_total",
		map[string]string{"proto": "http", "route": "proxy", "result": "ok"}, 2)
	waitForMetricSum(t, serverMetricsAddr, "requests_total",
		map[string]string{"proto": "tunnel", "result": "ok"}, 3)

	// ---- 验证分流：客户端结构化日志逐请求记录 route / upstream / target ----
	reqLogs := waitForRecords(t, clientProc, "request completed", 4, 5*time.Second)

	directLog := findRecord(t, reqLogs, "http/direct", func(rec map[string]any) bool {
		return rec["proto"] == "http" && rec["route"] == "direct"
	})
	if got := strField(t, clientProc, directLog, "target"); got != directTargetAddr {
		t.Errorf("直连请求 target = %q, want %q", got, directTargetAddr)
	}
	if got := strField(t, clientProc, directLog, "upstream"); got != "direct" {
		t.Errorf("直连请求 upstream = %q, want direct", got)
	}
	checkRequestLogFields(t, clientProc, directLog)

	connectLog := findRecord(t, reqLogs, "http/proxy(https)", func(rec map[string]any) bool {
		return rec["proto"] == "http" && rec["route"] == "proxy" &&
			rec["target"] == "localhost:"+portOf(t, proxyTLSTarget.Listener.Addr().String())
	})
	if got := strField(t, clientProc, connectLog, "upstream"); got != "pool" && got != tunnelAddr {
		t.Errorf("CONNECT 请求 upstream = %q, want %q 或 pool", got, tunnelAddr)
	}
	checkRequestLogFields(t, clientProc, connectLog)

	connectPlainLog := findRecord(t, reqLogs, "http/proxy(plain)", func(rec map[string]any) bool {
		return rec["proto"] == "http" && rec["route"] == "proxy" && rec["target"] == socksTargetAddr
	})
	if got := strField(t, clientProc, connectPlainLog, "upstream"); got != "pool" && got != tunnelAddr {
		t.Errorf("CONNECT(plain) 请求 upstream = %q, want %q 或 pool", got, tunnelAddr)
	}
	checkRequestLogFields(t, clientProc, connectPlainLog)

	socksLog := findRecord(t, reqLogs, "socks5/proxy", func(rec map[string]any) bool {
		return rec["proto"] == "socks5" && rec["route"] == "proxy"
	})
	if got := strField(t, clientProc, socksLog, "target"); got != socksTargetAddr {
		t.Errorf("SOCKS5 请求 target = %q, want %q", got, socksTargetAddr)
	}
	if got := strField(t, clientProc, socksLog, "upstream"); got != "pool" && got != tunnelAddr {
		t.Errorf("SOCKS5 请求 upstream = %q, want %q 或 pool", got, tunnelAddr)
	}
	checkRequestLogFields(t, clientProc, socksLog)

	// ---- 验证指标：/metrics 暴露三类核心序列 ----
	clientMetrics := fetchBody(t, "http://"+clientMetricsAddr+"/metrics")
	for _, want := range []string{
		"request_duration_seconds_bucket",
		"request_duration_seconds_count",
		`active_connections{proto="http"}`,
		`active_connections{proto="socks5"}`,
	} {
		if !strings.Contains(clientMetrics, want) {
			t.Errorf("客户端 /metrics 缺少 %q", want)
		}
	}
	serverMetrics := fetchBody(t, "http://"+serverMetricsAddr+"/metrics")
	for _, want := range []string{
		"request_duration_seconds_count",
		`active_connections{proto="tunnel"}`,
	} {
		if !strings.Contains(serverMetrics, want) {
			t.Errorf("服务端 /metrics 缺少 %q", want)
		}
	}

	// ---- 优雅关停：SIGTERM 退出码 0，且留下收尾日志 ----
	if err := clientProc.terminate(t, 20*time.Second); err != nil {
		t.Fatalf("proxy-client 退出: %v", err)
	}
	if len(records(clientProc.logs, "shutdown complete")) == 0 {
		t.Errorf("proxy-client 缺少 shutdown complete 日志:\n%s", clientProc.logs.String())
	}
	if err := serverProc.terminate(t, 20*time.Second); err != nil {
		t.Fatalf("proxy-server 退出: %v", err)
	}
	if len(records(serverProc.logs, "shutdown complete")) == 0 {
		t.Errorf("proxy-server 缺少 shutdown complete 日志:\n%s", serverProc.logs.String())
	}
}

// process 封装一个被测二进制进程：日志持续收集，退出统一收尸。
type process struct {
	name string
	cmd  *exec.Cmd
	logs *syncBuffer

	waitOnce sync.Once
	waitErr  error
	exited   chan struct{}
}

// startProcess 启动二进制并收集 stdout/stderr（全部日志写 stderr）。
// 测试结束时若进程仍在运行，会被强制清理，避免泄漏。
func startProcess(t *testing.T, name, bin string, args ...string) *process {
	t.Helper()
	p := &process{name: name, logs: &syncBuffer{}, exited: make(chan struct{})}
	p.cmd = exec.Command(bin, args...)
	p.cmd.Stdout = p.logs
	p.cmd.Stderr = p.logs
	if err := p.cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	// 后台回收：进程退出即关闭 exited，terminate 与兜底清理据此判断。
	go func() { _ = p.wait() }()
	t.Cleanup(func() {
		select {
		case <-p.exited:
			return
		default:
		}
		_ = p.cmd.Process.Kill()
		_ = p.wait()
	})
	return p
}

func (p *process) wait() error {
	p.waitOnce.Do(func() {
		p.waitErr = p.cmd.Wait()
		close(p.exited)
	})
	return p.waitErr
}

// terminate 发送 SIGTERM 并等待退出，返回等待错误（nil = 退出码 0，即优雅关停）。
func (p *process) terminate(t *testing.T, timeout time.Duration) error {
	t.Helper()
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal %s: %v", p.name, err)
	}
	select {
	case <-p.exited:
		return p.wait()
	case <-time.After(timeout):
		t.Fatalf("%s did not exit within %s；日志:\n%s", p.name, timeout, p.logs.String())
		return nil
	}
}

// syncBuffer 是并发安全的日志缓冲（子进程写、测试读）。
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

// records 解析缓冲中 msg 字段匹配的全部 JSON 日志行；不完整行自动跳过。
func records(buf *syncBuffer, msg string) []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(buf.String(), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

// waitForRecords 轮询等待 msg 记录达到 want 条。
func waitForRecords(t *testing.T, p *process, msg string, want int, timeout time.Duration) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var got []map[string]any
	for time.Now().Before(deadline) {
		got = records(p.logs, msg)
		if len(got) >= want {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s: %d 条 msg=%q 记录 < %d；日志:\n%s", p.name, len(got), msg, want, p.logs.String())
	return nil
}

// findRecord 在记录集合中查找首个匹配项。
func findRecord(t *testing.T, recs []map[string]any, what string, match func(map[string]any) bool) map[string]any {
	t.Helper()
	for _, rec := range recs {
		if match(rec) {
			return rec
		}
	}
	t.Fatalf("request completed 日志中缺少 %s 记录: %v", what, recs)
	return nil
}

// strField 读取记录中的非空字符串字段。
func strField(t *testing.T, p *process, rec map[string]any, key string) string {
	t.Helper()
	v, ok := rec[key].(string)
	if !ok || v == "" {
		t.Fatalf("%s: 字段 %q 缺失或为空: %v", p.name, key, rec)
	}
	return v
}

// checkRequestLogFields 校验完成日志的公共字段（1.6 号需求：可追溯）。
func checkRequestLogFields(t *testing.T, p *process, rec map[string]any) {
	t.Helper()
	if got := strField(t, p, rec, "request_id"); len(got) != 16 {
		t.Errorf("request_id = %q, want 16 位十六进制", got)
	}
	if got := strField(t, p, rec, "client_ip"); got != "127.0.0.1" {
		t.Errorf("client_ip = %q, want 127.0.0.1", got)
	}
	if got := strField(t, p, rec, "duration"); got == "" {
		t.Errorf("duration 为空: %v", rec)
	}
	if _, ok := rec["duration_ms"].(float64); !ok {
		t.Errorf("duration_ms 缺失或类型错误: %v", rec)
	}
	if got := rec["result"]; got != "ok" {
		t.Errorf("result = %v, want ok", got)
	}
}

// targetHandler 返回固定内容的 HTTP 目标站点。
func targetHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	})
}

// startTargetOn 在指定地址启动目标站点；tlsOn 为 true 时使用 TLS。
func startTargetOn(t *testing.T, addr, body string, tlsOn bool) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen %s: %v", addr, err)
	}
	srv := httptest.NewUnstartedServer(targetHandler(body))
	_ = srv.Listener.Close()
	srv.Listener = ln
	if tlsOn {
		srv.StartTLS()
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	return srv
}

// expectBody 经代理发起请求并校验响应体。
func expectBody(t *testing.T, client *http.Client, url, want string) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s via proxy: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("GET %s: read body: %v", url, err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != want {
		t.Fatalf("GET %s = %d %q, want 200 %q", url, resp.StatusCode, body, want)
	}
}

// socks5Connect 在 SOCKS5 入站上建立到目标地址的一次 CONNECT
// （RFC 1928 + RFC 1929 用户名密码认证），手工编码以保持黑盒边界。
// targetAddr 的 host 既可以是 IPv4 字面量，也可以是域名（按 RFC 1928 编码）。
func socks5Connect(t *testing.T, proxyAddr, username, password, targetAddr string) net.Conn {
	t.Helper()
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		t.Fatalf("split target %q: %v", targetAddr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("parse target port %q: %v", portStr, err)
	}
	target, err := socks5EncodeTarget(host, uint16(port))
	if err != nil {
		t.Fatalf("encode target %q: %v", targetAddr, err)
	}

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("socks5 dial %s: %v", proxyAddr, err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// 问候：只提供用户名/密码一种方法。
	if _, err := conn.Write([]byte{0x05, 1, 0x02}); err != nil {
		t.Fatalf("socks5 greeting: %v", err)
	}
	var sel [2]byte
	if _, err := io.ReadFull(conn, sel[:]); err != nil {
		t.Fatalf("socks5 method selection: %v", err)
	}
	if sel != [2]byte{0x05, 0x02} {
		t.Fatalf("socks5 method selection = %v, want [5 2]", sel)
	}
	// RFC 1929 认证。
	auth := []byte{0x01, byte(len(username))}
	auth = append(auth, username...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, password...)
	if _, err := conn.Write(auth); err != nil {
		t.Fatalf("socks5 auth write: %v", err)
	}
	var authReply [2]byte
	if _, err := io.ReadFull(conn, authReply[:]); err != nil {
		t.Fatalf("socks5 auth reply: %v", err)
	}
	if authReply[1] != 0x00 {
		t.Fatalf("socks5 auth status = %d, want 0", authReply[1])
	}
	// CONNECT 请求。
	req := append([]byte{0x05, 0x01, 0x00}, target...)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("socks5 connect write: %v", err)
	}
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		t.Fatalf("socks5 connect reply: %v", err)
	}
	if head[1] != 0x00 {
		t.Fatalf("socks5 connect reply = %d, want success", head[1])
	}
	// 读掉绑定地址（IPv4 目标必然回 IPv4 编码）。
	if head[3] != 0x01 {
		t.Fatalf("socks5 bind ATYP = %d, want 1 (IPv4)", head[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, 4+2)); err != nil {
		t.Fatalf("socks5 bind addr: %v", err)
	}
	_ = conn.SetDeadline(time.Time{})
	ok = true
	return conn
}

// rawConnect 在 HTTP 入站上发起一次 CONNECT（含代理认证），
// 返回已进入隧道状态的原始连接；手工编码以保持黑盒边界。
func rawConnect(t *testing.T, proxyAddr, username, password, targetAddr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy %s: %v", proxyAddr, err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
		targetAddr, targetAddr, auth)
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("CONNECT write: %v", err)
	}
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("CONNECT response: %v", err)
	}
	if !strings.Contains(statusLine, " 200 ") {
		t.Fatalf("CONNECT status = %q, want 200", strings.TrimSpace(statusLine))
	}
	for { // 读掉响应头其余部分。
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("CONNECT headers: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	_ = conn.SetDeadline(time.Time{})
	ok = true
	return conn
}

// readUntilEOF 读到 EOF 并返回全部数据；超时单独报错，便于定位
// “半关闭（FIN/close_notify）未沿链路传播”这类缺陷。
func readUntilEOF(t *testing.T, conn net.Conn, what string) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("%s 读取在收到 EOF 前失败（i/o timeout 通常意味着半关闭未传播）: %v", what, err)
	}
	return string(data)
}

// socks5EncodeTarget 按 RFC 1928 编码目标地址（IPv4 字面量或域名）。
func socks5EncodeTarget(host string, port uint16) ([]byte, error) {
	var addr []byte
	if ip := net.ParseIP(host).To4(); ip != nil {
		addr = append([]byte{0x01}, ip...)
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("host %q 长度非法", host)
		}
		addr = append([]byte{0x03, byte(len(host))}, host...)
	}
	return append(addr, byte(port>>8), byte(port)), nil
}

// metricSample 是 Prometheus 文本格式中的一条样本。
type metricSample struct {
	labels map[string]string
	value  float64
}

// metricSamples 解析文本并返回序列名匹配 name 的全部样本。
func metricSamples(t *testing.T, text, name string) []metricSample {
	t.Helper()
	var out []metricSample
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		series, rest, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		seriesName, labels, ok := parseSeries(series)
		if !ok || seriesName != name {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(rest), 64)
		if err != nil {
			t.Fatalf("parse metric value in %q: %v", line, err)
		}
		out = append(out, metricSample{labels: labels, value: v})
	}
	return out
}

// parseSeries 解析 `name{k="v",...}`；本测试断言只覆盖取值简单的标签。
func parseSeries(s string) (string, map[string]string, bool) {
	i := strings.IndexByte(s, '{')
	if i < 0 {
		return s, map[string]string{}, true
	}
	if !strings.HasSuffix(s, "}") {
		return "", nil, false
	}
	labels := map[string]string{}
	for _, pair := range strings.Split(s[i+1:len(s)-1], ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			return "", nil, false
		}
		labels[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
	}
	return s[:i], labels, true
}

// sumSamples 汇总标签全部匹配 match 的样本值。
func sumSamples(samples []metricSample, match map[string]string) float64 {
	var sum float64
	for _, s := range samples {
		ok := true
		for k, v := range match {
			if s.labels[k] != v {
				ok = false
				break
			}
		}
		if ok {
			sum += s.value
		}
	}
	return sum
}

// waitForMetricSum 轮询 /metrics 直到名称与标签匹配的样本之和达到 want。
// 指标写入发生在请求收尾，与抓取之间存在天然时序差。
func waitForMetricSum(t *testing.T, metricsAddr, name string, match map[string]string, want float64) float64 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var got float64
	for time.Now().Before(deadline) {
		got = sumSamples(metricSamples(t, fetchBody(t, "http://"+metricsAddr+"/metrics"), name), match)
		if got >= want {
			return got
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("metric %s%v on %s = %v, want >= %v", name, match, metricsAddr, got, want)
	return got
}

// fetchBody GET 指定 URL 并要求 2xx。
func fetchBody(t *testing.T, url string) string {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("GET %s: read body: %v", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d, body %s", url, resp.StatusCode, body)
	}
	return string(body)
}

// waitForStatusOK 轮询 /health 直到 200 且 status 为 ok。
func waitForStatusOK(t *testing.T, metricsAddr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + metricsAddr + "/health")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			last = string(body)
			if resp.StatusCode == http.StatusOK && strings.Contains(last, `"status":"ok"`) {
				return
			}
		} else {
			last = err.Error()
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("/health on %s 在 %s 内未返回 ok；最后一次: %s", metricsAddr, timeout, last)
}

// writeFile 把内容写入测试临时目录并返回完整路径。
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// portOf 返回 host:port 中的端口部分。
func portOf(t *testing.T, hostPort string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatalf("split %q: %v", hostPort, err)
	}
	return port
}
