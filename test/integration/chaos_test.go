package integration

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/testutil"
)

// TestChaosKilledUpstreamRemovedAndRejoins 是 3.8「混沌测试（最小版）」：
// 对真实二进制做故障注入——SIGKILL 一个上游节点进程（崩溃式故障），
// 验证「自动摘除 → 流量转移 → 同址重启 → 自动加回」全链路：
//
//  1. 基线：双节点交替承载请求（客户端日志 upstream 覆盖两个节点）；
//  2. 混沌：SIGKILL 节点 A 后立即继续发请求——窗口期与摘除后请求必须
//     全部成功且由节点 B 承载（被动切换 + 硬摘除）；
//  3. 摘除证据：/stats 显示 A removed:true 且连续探测失败 ≥2、warn 日志、
//     upstream_healthy{node=A}=0；
//  4. 恢复：同址重启 A → 连续成功探测后自动加回（info 日志、指标回 1），
//     流量重新覆盖两个节点（A 的服务端完成计数为证）。
func TestChaosKilledUpstreamRemovedAndRejoins(t *testing.T) {
	if testing.Short() {
		t.Skip("chaos test builds and runs the real binaries; skipped with -short")
	}

	dir := t.TempDir()
	certFile, keyFile, err := testutil.WriteTLSCertFiles(dir)
	if err != nil {
		t.Fatal(err)
	}

	// 固定地址：节点 A 需要「同址重启」才能自动加回。
	// 从临时端口段之外取地址，避免端口在测试中途被并行测试/出站连接抢占。
	nodeAAddr := freeFixedPort(t)
	nodeBAddr := freeFixedPort(t)
	nodeAPassword := "chaos-a-secret"
	nodeBPassword := "chaos-b-secret"

	serverConfig := func(name, addr, password string) string {
		return writeFile(t, dir, name, fmt.Sprintf(`
log:
  level: info
  format: json
api:
  listen: "127.0.0.1:0"
inbounds:
  - type: trojan
    listen: %q
    params:
      cert-file: %q
      key-file: %q
      users:
        - username: node-user
          password: %s
`, addr, certFile, keyFile, password))
	}
	cfgA := serverConfig("server-a.yaml", nodeAAddr, nodeAPassword)
	cfgB := serverConfig("server-b.yaml", nodeBAddr, nodeBPassword)

	// startServer 启动一个节点并返回进程与其 metrics 地址。
	startServer := func(name, configPath, addr string) (*process, string) {
		p := startProcess(t, name, filepath.Join(binDir, "proxy-server"), "-config", configPath)
		rec := waitForRecords(t, p, "listening", 1, 10*time.Second)[0]
		if got := strField(t, p, rec, "tunnel"); got != addr {
			t.Fatalf("%s tunnel addr = %q, want %q", name, got, addr)
		}
		return p, strField(t, p, rec, "metrics")
	}

	serverA, metricsA := startServer("proxy-server-A", cfgA, nodeAAddr)
	_, metricsB := startServer("proxy-server-B", cfgB, nodeBAddr)
	waitForStatusOK(t, metricsA, 10*time.Second)
	waitForStatusOK(t, metricsB, 10*time.Second)

	// ---- 启动客户端（双节点 + 短周期健康检查，让用例在秒级完成）----
	// 目标站点用 localhost 域名访问：走默认 proxy（出口侧解析后回连本机），
	// 与 3.7 集成测试相同的技巧。
	target := startTargetOn(t, "127.0.0.1:0", "chaos-ok", true)
	targetURL := "https://localhost:" + portOf(t, target.Listener.Addr().String())

	clientConfig := writeFile(t, dir, "client.yaml", fmt.Sprintf(`
log:
  level: info
  format: json
api:
  listen: "127.0.0.1:0"
inbounds:
  - type: http
    listen: "127.0.0.1:0"
    auth:
      users:
        - username: alice
          password: change-me
outbound:
  nodes:
    - name: node-a
      protocol: trojan
      params:
        addr: %q
        password: %s
        insecure-skip-verify: true
    - name: node-b
      protocol: trojan
      params:
        addr: %q
        password: %s
        insecure-skip-verify: true
  pool:
    health:
      interval: 200ms
      timeout: 300ms
      failures: 2
      successes: 2
routing:
  private-direct: false
`, nodeAAddr, nodeAPassword, nodeBAddr, nodeBPassword))
	clientProc := startProcess(t, "proxy-client", filepath.Join(binDir, "proxy-client"), "-config", clientConfig)
	clientListen := waitForRecords(t, clientProc, "listening", 1, 10*time.Second)[0]
	httpAddr := strField(t, clientProc, clientListen, "http")
	clientMetricsAddr := strField(t, clientProc, clientListen, "metrics")
	waitForStatusOK(t, clientMetricsAddr, 10*time.Second)

	proxyURL, err := url.Parse("http://alice:change-me@" + httpAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	proxyClient := newProxyClient(t, proxyURL)

	doRequests := func(n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			expectBody(t, proxyClient, targetURL, "chaos-ok")
		}
	}

	// ---- 阶段 1：基线——双节点轮询交替承载 ----
	doRequests(6)
	base := waitForRecords(t, clientProc, "request completed", 6, 5*time.Second)
	assertUpstreamsCover(t, base[:6], nodeAAddr, nodeBAddr)
	waitForMetricSum(t, metricsA, "requests_total",
		map[string]string{"proto": "tunnel", "result": "ok"}, 1)
	waitForMetricSum(t, metricsB, "requests_total",
		map[string]string{"proto": "tunnel", "result": "ok"}, 1)

	// ---- 阶段 2：混沌——SIGKILL 节点 A（崩溃式故障）----
	serverA.killNow()

	// 窗口期立即发请求：A 拨号失败后被动切换到 B，请求应全部成功。
	doRequests(3)
	// 连续探测失败达阈值后应硬摘除（短周期下 ~0.5s 内）。
	upA := waitUpstream(t, clientMetricsAddr, nodeAAddr, 10*time.Second, func(up upstreamStat) bool {
		return up.Removed
	})
	if upA.ProbeFails < 2 {
		t.Errorf("摘除时 probe_fails = %d, want >= 2", upA.ProbeFails)
	}
	if recs := waitForRecords(t, clientProc, "exit node removed by active health check", 1, 5*time.Second); recs[0]["node"] != nodeAAddr {
		t.Errorf("摘除日志 node = %v, want %s", recs[0]["node"], nodeAAddr)
	}
	if got := sumSamples(metricSamples(t, fetchBody(t, "http://"+clientMetricsAddr+"/metrics"), "upstream_healthy"),
		map[string]string{"node": nodeAAddr}); got != 0 {
		t.Errorf("upstream_healthy{node=A} = %v, want 0（已摘除）", got)
	}

	// 摘除后（A 未重启）再发请求：不允许再拨号 A，全部由 B 承载。
	doRequests(6)
	all := waitForRecords(t, clientProc, "request completed", 15, 5*time.Second)
	afterKill := all[6:15]
	for i, rec := range afterKill {
		if got := rec["upstream"]; got != nodeBAddr {
			t.Errorf("故障后第 %d 条请求 upstream = %v, want %s", i, got, nodeBAddr)
		}
		if got := rec["result"]; got != "ok" {
			t.Errorf("故障后第 %d 条请求 result = %v, want ok", i, got)
		}
	}
	if sumSamples(metricSamples(t, fetchBody(t, "http://"+clientMetricsAddr+"/metrics"), "upstream_healthy"),
		map[string]string{"node": nodeBAddr}) != 1 {
		t.Errorf("upstream_healthy{node=B} != 1（B 应保持健康）")
	}
	waitForStatusOK(t, clientMetricsAddr, 3*time.Second) // 仍有健康节点，/health 保持 ok

	// ---- 阶段 3：恢复——同址重启 A → 连续成功探测后自动加回 ----
	_, metricsA = startServer("proxy-server-A-restarted", cfgA, nodeAAddr)
	upA = waitUpstream(t, clientMetricsAddr, nodeAAddr, 10*time.Second, func(up upstreamStat) bool {
		return !up.Removed
	})
	if upA.ProbeFails != 0 {
		t.Errorf("加回时 probe_fails = %d, want 0", upA.ProbeFails)
	}
	if recs := waitForRecords(t, clientProc, "exit node rejoined after passing health checks", 1, 5*time.Second); recs[0]["node"] != nodeAAddr {
		t.Errorf("加回日志 node = %v, want %s", recs[0]["node"], nodeAAddr)
	}
	waitForMetricSum(t, clientMetricsAddr, "upstream_healthy", map[string]string{"node": nodeAAddr}, 1)

	// 加回后的流量重新覆盖两个节点；A 实际承载隧道流量（新进程的完成计数为证）。
	doRequests(6)
	post := waitForRecords(t, clientProc, "request completed", 21, 5*time.Second)
	assertUpstreamsCover(t, post[15:21], nodeAAddr, nodeBAddr)
	waitForMetricSum(t, metricsA, "requests_total",
		map[string]string{"proto": "tunnel", "result": "ok"}, 1)
}

// nextFixedPort 是 freeFixedPort 的分配游标：单调递增保证同一次测试进程内的
// 多次调用拿到互不相同的端口。
var nextFixedPort = 20000

// freeFixedPort 从固定高段（20000–29999）分配一个空闲的 127.0.0.1 监听地址。
//
// 混沌用例要求节点「同址重启」，不能用 :0：它拿到的端口通常落在临时端口
// 范围内，测试随后拨号/探测产生的出站连接或并行测试包的新监听都可能把它
// 当作本地端口占用，重启时 bind 失败（main 分支 CI 实际发生过一次）。
func freeFixedPort(t *testing.T) string {
	t.Helper()
	for ; nextFixedPort < 30000; nextFixedPort++ {
		addr := fmt.Sprintf("127.0.0.1:%d", nextFixedPort)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			continue
		}
		_ = ln.Close()
		nextFixedPort++
		return addr
	}
	t.Fatalf("20000–29999 段内无空闲端口")
	return ""
}

// killNow 立即 SIGKILL 并回收进程（模拟上游崩溃，区别于优雅关停）。
func (p *process) killNow() {
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	_ = p.wait()
}

// upstreamStat 是 /stats 中单个上游节点的状态快照（取断言所需字段）。
type upstreamStat struct {
	Addr       string `json:"addr"`
	Healthy    bool   `json:"healthy"`
	Removed    bool   `json:"removed"`
	ProbeFails int    `json:"probe_fails"`
}

// fetchUpstreams 抓取客户端 /stats 的 upstreams 列表。
func fetchUpstreams(t *testing.T, metricsAddr string) []upstreamStat {
	t.Helper()
	var snap struct {
		Upstreams []upstreamStat `json:"upstreams"`
	}
	if err := json.Unmarshal([]byte(fetchBody(t, "http://"+metricsAddr+"/stats")), &snap); err != nil {
		t.Fatalf("parse /stats: %v", err)
	}
	return snap.Upstreams
}

// waitUpstream 轮询 /stats 直到指定节点满足条件，返回其状态。
func waitUpstream(t *testing.T, metricsAddr, addr string, timeout time.Duration, want func(upstreamStat) bool) upstreamStat {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last upstreamStat
	found := false
	for time.Now().Before(deadline) {
		for _, up := range fetchUpstreams(t, metricsAddr) {
			if up.Addr == addr {
				last, found = up, true
				if want(up) {
					return up
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("upstream %s 未在 %s 内满足条件（最后状态 %+v, found=%v）", addr, timeout, last, found)
	return last
}

// assertUpstreamsCover 断言记录集合的 upstream 字段至少覆盖全部给定节点。
func assertUpstreamsCover(t *testing.T, recs []map[string]any, addrs ...string) {
	t.Helper()
	seen := map[string]bool{}
	for _, rec := range recs {
		if u, ok := rec["upstream"].(string); ok {
			seen[u] = true
		}
	}
	for _, addr := range addrs {
		if !seen[addr] {
			t.Errorf("请求未覆盖节点 %s（upstreams=%v）", addr, seen)
		}
	}
}

// newProxyClient 构造经 HTTP 入站的浏览器式客户端（携带代理认证）。
func newProxyClient(t *testing.T, proxyURL *url.URL) *http.Client {
	t.Helper()
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}
}
