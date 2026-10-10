package clientapp_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/clientapp"
	"github.com/OopsOo0ps/proxy/internal/config"
)

// startPlainTarget 启动一个返回固定内容的 HTTP 目标站点（非 TLS）。
func startPlainTarget(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("target-ok"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// fetchThroughProxy 经客户端 HTTP 入站以指定凭据请求目标，返回响应。
func fetchThroughProxy(t *testing.T, app *clientapp.App, target, user, pass string) *http.Response {
	t.Helper()
	client := browser(t, fmt.Sprintf("http://%s:%s@%s", user, pass, app.HTTPAddr()), 1)
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	return resp
}

// readBody 读取并关闭响应体。
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestReloadSwapsInboundAuth 验证热加载后入站凭据原子替换：
// 新凭据立即生效，旧凭据立即失效，且请求链路（经出口节点）全程可用。
func TestReloadSwapsInboundAuth(t *testing.T) {
	h := startServer(t, "node-secret", nil, false)
	target := startPlainTarget(t)

	cfg := baseClientCfg([]config.Node{{Addr: h.addr, Password: "node-secret"}})
	cfg.Inbound.Auth = []config.User{{Username: "alice", Password: "pw-alice"}}
	app := startClient(t, cfg, nil)

	resp := fetchThroughProxy(t, app, target.URL, "alice", "pw-alice")
	if body := readBody(t, resp); resp.StatusCode != http.StatusOK || body != "target-ok" {
		t.Fatalf("initial credentials: status=%d body=%q", resp.StatusCode, body)
	}

	next := *cfg
	next.Inbound.Auth = []config.User{{Username: "bob", Password: "pw-bob"}}
	if err := app.Reload(&next); err != nil {
		t.Fatalf("reload: %v", err)
	}

	resp = fetchThroughProxy(t, app, target.URL, "bob", "pw-bob")
	if body := readBody(t, resp); resp.StatusCode != http.StatusOK || body != "target-ok" {
		t.Fatalf("new credentials after reload: status=%d body=%q", resp.StatusCode, body)
	}
	resp = fetchThroughProxy(t, app, target.URL, "alice", "pw-alice")
	if body := readBody(t, resp); resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("old credentials after reload: status=%d body=%q, want 407", resp.StatusCode, body)
	}

	// 同一份快照同样作用于 SOCKS5 入站。
	u, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portString, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := socks5Dial(t, app.SOCKS5Addr(), "bob", "pw-bob", host, uint16(port))
	if err != nil {
		t.Fatalf("socks5 with new credentials after reload: %v", err)
	}
	_ = conn.Close()
	if _, err := socks5Dial(t, app.SOCKS5Addr(), "alice", "pw-alice", host, uint16(port)); err == nil {
		t.Fatal("socks5 old credentials after reload must fail")
	}
}

// TestReloadSwapsExitNodes 验证热加载替换出口节点：旧节点离线后，
// 一次成功的重载就能把流量迁移到新节点，无需重启进程。
func TestReloadSwapsExitNodes(t *testing.T) {
	oldNode := startServer(t, "old-secret", nil, false)
	newNode := startServer(t, "new-secret", nil, false)
	target := startPlainTarget(t)

	cfg := baseClientCfg([]config.Node{{Addr: oldNode.addr, Password: "old-secret"}})
	app := startClient(t, cfg, nil)

	resp := fetchThroughProxy(t, app, target.URL, "u", "p")
	if body := readBody(t, resp); resp.StatusCode != http.StatusOK || body != "target-ok" {
		t.Fatalf("initial node: status=%d body=%q", resp.StatusCode, body)
	}

	// 旧节点下线：请求应失败（502）。
	oldNode.stop()
	resp = fetchThroughProxy(t, app, target.URL, "u", "p")
	if body := readBody(t, resp); resp.StatusCode < 500 {
		t.Fatalf("with only a dead node: status=%d body=%q, want >=500", resp.StatusCode, body)
	}

	// 重载替换为存活节点：流量恢复。
	next := *cfg
	next.Nodes = []config.Node{{Addr: newNode.addr, Password: "new-secret"}}
	next.Pool.MaxIdle = intPtr(1)
	if err := app.Reload(&next); err != nil {
		t.Fatalf("reload: %v", err)
	}
	resp = fetchThroughProxy(t, app, target.URL, "u", "p")
	if body := readBody(t, resp); resp.StatusCode != http.StatusOK || body != "target-ok" {
		t.Fatalf("after node swap: status=%d body=%q", resp.StatusCode, body)
	}
}

// TestReloadAppliesHealthCheckConfig 验证 health_check 属热加载项：
// 关闭主动探测后节点池重建，死节点不再被摘除，旧池的探测循环同步停止。
func TestReloadAppliesHealthCheckConfig(t *testing.T) {
	stable := startServer(t, "stable-secret", nil, false)
	deadAddr := freeTCPAddr(t) // 无监听者
	nodes := []config.Node{
		{Addr: stable.addr, Password: "stable-secret"},
		{Addr: deadAddr, Password: "dead-secret"},
	}
	target := startPlainTarget(t)

	cfg := baseClientCfg(nodes)
	cfg.Inbound.Auth = []config.User{{Username: "alice", Password: "pw"}}
	cfg.Metrics.Listen = "127.0.0.1:0"
	cfg.HealthCheck = config.HealthCheck{
		Interval:  durationPtr(50 * time.Millisecond),
		Timeout:   config.Duration(200 * time.Millisecond),
		Failures:  intPtr(1),
		Successes: intPtr(1),
	}
	app := startClient(t, cfg, nil)

	// 初始：探测迅速摘除死节点。
	waitUpstream(t, app.MetricsAddr(), deadAddr, func(up upstreamStats) bool { return up.Removed })
	waitForMetric(t, app.MetricsAddr(), `upstream_healthy{node="`+deadAddr+`"} 0`)
	failures := metricSeriesValue(t, app.MetricsAddr(), `upstream_health_probes_total{node="`+deadAddr+`",result="failure"}`)
	if failures < 1 {
		t.Fatalf("probe failures = %d, want >= 1", failures)
	}

	// 热加载关闭主动探测：节点池重建，死节点恢复“未摘除”初始状态。
	next := *cfg
	next.HealthCheck = config.HealthCheck{Interval: durationPtr(0)}
	if err := app.Reload(&next); err != nil {
		t.Fatalf("reload: %v", err)
	}
	waitUpstream(t, app.MetricsAddr(), deadAddr, func(up upstreamStats) bool { return !up.Removed })

	// 基线在 Reload 返回后取：validate-then-swap 语义下旧配置在切换前持续
	// 生效，旧探测循环的最后一批结果可能落在重载期间（Reload 返回之前）；
	// Reload 内部的 Close 会等待探测循环（含在途探测）退出，因此从返回那一
	// 刻起计数不再增长才是本用例要断言的性质。
	baseline := metricSeriesValue(t, app.MetricsAddr(), `upstream_health_probes_total{node="`+deadAddr+`",result="failure"}`)

	// 观察窗口内不应再次被摘除（主动探测已关闭）。
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		up := waitUpstream(t, app.MetricsAddr(), deadAddr, func(upstreamStats) bool { return true })
		if up.Removed {
			t.Fatalf("dead node should stay unremoved with probing disabled, got %+v", up)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 旧池探测循环已停止：失败计数在观察窗口内不再增长。
	got := metricSeriesValue(t, app.MetricsAddr(), `upstream_health_probes_total{node="`+deadAddr+`",result="failure"}`)
	if got != baseline {
		t.Fatalf("probe failures grew from %d to %d after disabling probes", baseline, got)
	}

	// 存活节点仍可正常服务。
	resp := fetchThroughProxy(t, app, target.URL, "alice", "pw")
	if body := readBody(t, resp); resp.StatusCode != http.StatusOK || body != "target-ok" {
		t.Fatalf("after reload: status=%d body=%q", resp.StatusCode, body)
	}
}

// TestReloadFailureKeepsOldConfig 验证“配置错误不炸线上”：
// 解析校验失败（模拟 main 的加载路径）、构建失败（规则文件缺失）、
// 监听地址变更（需要重启）都不会改变运行中的配置，服务持续可用。
func TestReloadFailureKeepsOldConfig(t *testing.T) {
	h := startServer(t, "node-secret", nil, false)
	target := startPlainTarget(t)

	cfg := baseClientCfg([]config.Node{{Addr: h.addr, Password: "node-secret"}})
	cfg.Inbound.Auth = []config.User{{Username: "alice", Password: "pw-alice"}}
	app := startClient(t, cfg, nil)

	dir := t.TempDir()

	// 1) 文件解析 / 校验失败：LoadClient 报错，应用完全不被触碰（main 只记录日志）。
	badPath := filepath.Join(dir, "client.yaml")
	if err := os.WriteFile(badPath, []byte("inbound: { http: \"127.0.0.1:8080\" }\nunknown_field: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.LoadClient(badPath); err == nil {
		t.Fatal("config with unknown field must fail to load")
	}

	// 2) 构建失败：规则文件缺失（同时改动了认证），整份配置不得部分生效。
	next := *cfg
	next.Routing.RulesFile = filepath.Join(dir, "missing-rules.yaml")
	next.Inbound.Auth = []config.User{{Username: "bob", Password: "pw-bob"}}
	if err := app.Reload(&next); err == nil {
		t.Fatal("reload with missing rules file must fail")
	}

	// 3) 监听地址变更：明确拒绝（需要重启）。
	moved := *cfg
	moved.Inbound.HTTP = "127.0.0.1:18080"
	if err := app.Reload(&moved); err == nil || !strings.Contains(err.Error(), "restart required") {
		t.Fatalf("listen change must be rejected with restart hint, got %v", err)
	}

	// 旧配置仍然原样服务：旧凭据可用、新凭据（从未生效）被拒。
	resp := fetchThroughProxy(t, app, target.URL, "alice", "pw-alice")
	if body := readBody(t, resp); resp.StatusCode != http.StatusOK || body != "target-ok" {
		t.Fatalf("after failed reloads: status=%d body=%q", resp.StatusCode, body)
	}
	resp = fetchThroughProxy(t, app, target.URL, "bob", "pw-bob")
	if body := readBody(t, resp); resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("failed reload leaked new credentials: status=%d body=%q", resp.StatusCode, body)
	}
}
