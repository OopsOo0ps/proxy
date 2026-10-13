package clientapp_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/config"
)

const (
	remoteRulesDirectLoopback = "rules:\n  - action: direct\n    match: [\"127.0.0.1\"]\n"
	remoteRulesProxyLoopback  = "rules:\n  - action: proxy\n    match: [\"127.0.0.1\"]\n"
)

// startRulesServer 启动按原子值返回内容的规则服务器，可在测试中随时切换。
func startRulesServer(t *testing.T, body *atomic.Value) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body.Load().(string))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// startStickyTarget 启动目标站点：首个响应保持 keep-alive（在代理转发路径上留下
// 一条可被复用的空闲连接，暴露“规则变化后仍复用旧路由连接”的问题）；之后的
// 响应带 Connection: close——经隧道的请求在响应结束时立即关闭隧道，使节点侧
// 的隧道完成日志可以即时作为“确实经过出口”的证据。
func startStickyTarget(t *testing.T) *httptest.Server {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) > 1 {
			w.Header().Set("Connection", "close")
		}
		_, _ = w.Write([]byte("target-ok"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// countLog 统计日志缓冲中出现子串的行数（每行一条 JSON 记录）。
func countLog(buf *lockedBuffer, substr string) int {
	n := 0
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, substr) {
			n++
		}
	}
	return n
}

func waitLogCount(t *testing.T, buf *lockedBuffer, substr string, want int, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if countLog(buf, substr) >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s: log %q count = %d, want >= %d in:\n%s", msg, substr, countLog(buf, substr), want, buf.String())
}

// waitNodeTunnels 等待出口节点完成指定数量的隧道转发（nodeLogs 为服务端日志）。
// 它是“请求确实走了出口”的硬证据：仅当客户端重新建连并经隧道才会出现。
func waitNodeTunnels(t *testing.T, nodeLogs *lockedBuffer, want int, msg string) {
	t.Helper()
	const tunnel = `"msg":"tunnel completed"`
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if countLog(nodeLogs, tunnel) >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s: node tunnel count = %d, want >= %d in:\n%s", msg, countLog(nodeLogs, tunnel), want, nodeLogs.String())
}

// TestE2ERulesRemoteRefreshFlipsRoute 验证远程规则按周期刷新并原子生效：
// 初始规则让回环目标直连；远程内容改成走代理后，一个新刷新周期内
// 后续请求改用出口节点，全程请求成功。
func TestE2ERulesRemoteRefreshFlipsRoute(t *testing.T) {
	var body atomic.Value
	body.Store(remoteRulesDirectLoopback)
	rulesSrv := startRulesServer(t, &body)

	nodeLogs := &lockedBuffer{}
	nodeLogger := slog.New(slog.NewJSONHandler(nodeLogs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	node := startServer(t, "node-secret", nodeLogger, false)
	target := startStickyTarget(t)

	clientLogs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(clientLogs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := baseClientCfg([]config.Node{trojanNode(t, "node-1", node.addr, "node-secret")})
	cfg.Routing.Rulesets = []config.Ruleset{{
		Name:     "remote",
		URL:      rulesSrv.URL,
		Interval: durationPtr(100 * time.Millisecond),
	}}
	cfg.API.Listen = "127.0.0.1:0"
	app := startClient(t, cfg, logger)

	// 阶段一：规则命中直连（upstream=direct）。
	resp := fetchThroughProxy(t, app, target.URL, "u", "p")
	if got := readBody(t, resp); resp.StatusCode != http.StatusOK || got != "target-ok" {
		t.Fatalf("initial request: status=%d body=%q", resp.StatusCode, got)
	}
	waitLogCount(t, clientLogs, `"upstream":"direct"`, 1, "direct route not observed")

	// 阶段二：远程内容改为 proxy，等待刷新后路由翻转为出口节点。
	body.Store(remoteRulesProxyLoopback)
	waitForMetric(t, app.MetricsAddr(), `ruleset_refreshes_total{result="success"} 2`)
	resp = fetchThroughProxy(t, app, target.URL, "u", "p")
	if got := readBody(t, resp); resp.StatusCode != http.StatusOK || got != "target-ok" {
		t.Fatalf("request after refresh: status=%d body=%q", resp.StatusCode, got)
	}
	waitLogCount(t, clientLogs, `"route":"proxy"`, 1, "proxy route not observed after refresh")
	waitLogCount(t, clientLogs, `"upstream":"`+node.addr+`"`, 1, "flipped request reused the old-route connection")
	waitNodeTunnels(t, nodeLogs, 1, "flipped request served over a stale direct connection")

	// /stats 暴露规则源状态。
	var stats struct {
		Ruleset struct {
			Source      string `json:"source"`
			Target      string `json:"target"`
			Loaded      bool   `json:"loaded"`
			Rules       int    `json:"rules"`
			LastSuccess string `json:"last_success"`
		} `json:"ruleset"`
	}
	if code := getJSON(t, "http://"+app.MetricsAddr()+"/stats", &stats); code != http.StatusOK {
		t.Fatalf("/stats status = %d", code)
	}
	if stats.Ruleset.Source != "url" || stats.Ruleset.Target != rulesSrv.URL ||
		!stats.Ruleset.Loaded || stats.Ruleset.Rules != 1 || stats.Ruleset.LastSuccess == "" {
		t.Fatalf("unexpected /stats ruleset: %+v", stats.Ruleset)
	}
}

// TestE2ERulesRemoteFailureKeepsRules 验证刷新失败（非法内容 / 服务端错误）
// 保持现有规则继续服务，并在源恢复后自动收敛到新内容。
func TestE2ERulesRemoteFailureKeepsRules(t *testing.T) {
	var body atomic.Value
	body.Store(remoteRulesDirectLoopback)
	rulesSrv := startRulesServer(t, &body)

	nodeLogs := &lockedBuffer{}
	nodeLogger := slog.New(slog.NewJSONHandler(nodeLogs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	node := startServer(t, "node-secret", nodeLogger, false)
	target := startStickyTarget(t)

	clientLogs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(clientLogs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := baseClientCfg([]config.Node{trojanNode(t, "node-1", node.addr, "node-secret")})
	cfg.Routing.Rulesets = []config.Ruleset{{
		Name:     "remote",
		URL:      rulesSrv.URL,
		Interval: durationPtr(50 * time.Millisecond),
	}}
	cfg.API.Listen = "127.0.0.1:0"
	app := startClient(t, cfg, logger)

	resp := fetchThroughProxy(t, app, target.URL, "u", "p")
	if got := readBody(t, resp); resp.StatusCode != http.StatusOK || got != "target-ok" {
		t.Fatalf("initial request: status=%d body=%q", resp.StatusCode, got)
	}
	waitLogCount(t, clientLogs, `"upstream":"direct"`, 1, "direct route not observed")

	// 非法内容：刷新失败计数，规则保持直连。第二次请求复用首条请求留下的
	// 直连上游连接（不触发新拨号），日志按“池选择未定”词汇记录 upstream=pool
	// ——请求未走出口节点即为规则未被破坏的证据（见下方 node tunnel 计数）。
	body.Store("rules: [:::")
	waitForMetric(t, app.MetricsAddr(), `ruleset_refreshes_total{result="error"} 1`)
	resp = fetchThroughProxy(t, app, target.URL, "u", "p")
	if got := readBody(t, resp); resp.StatusCode != http.StatusOK || got != "target-ok" {
		t.Fatalf("request during bad rules: status=%d body=%q", resp.StatusCode, got)
	}
	waitLogCount(t, clientLogs, `"upstream":"pool"`, 1, "second request did not reuse the pooled upstream")

	// 源恢复为新内容：自动收敛为走代理。
	body.Store(remoteRulesProxyLoopback)
	waitForMetric(t, app.MetricsAddr(), `ruleset_refreshes_total{result="success"} 2`)
	resp = fetchThroughProxy(t, app, target.URL, "u", "p")
	if got := readBody(t, resp); resp.StatusCode != http.StatusOK || got != "target-ok" {
		t.Fatalf("request after recovery: status=%d body=%q", resp.StatusCode, got)
	}
	waitLogCount(t, clientLogs, `"route":"proxy"`, 1, "proxy route not observed after recovery")
	waitLogCount(t, clientLogs, `"upstream":"`+node.addr+`"`, 1, "recovered request reused the old-route connection")
	waitNodeTunnels(t, nodeLogs, 1, "recovered request served over a stale direct connection")
}

// TestE2ERulesSighupRechecksURL 验证 SIGHUP 热加载会让 URL 规则源立即重拉：
// 成功时新内容立即生效；拉取失败时重载仍然成功且保持现有规则。
func TestE2ERulesSighupRechecksURL(t *testing.T) {
	var body atomic.Value
	body.Store(remoteRulesDirectLoopback)
	rulesSrv := startRulesServer(t, &body)

	nodeLogs := &lockedBuffer{}
	nodeLogger := slog.New(slog.NewJSONHandler(nodeLogs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	node := startServer(t, "node-secret", nodeLogger, false)
	target := startStickyTarget(t)

	clientLogs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(clientLogs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := baseClientCfg([]config.Node{trojanNode(t, "node-1", node.addr, "node-secret")})
	cfg.Routing.Rulesets = []config.Ruleset{{
		Name:     "remote",
		URL:      rulesSrv.URL,
		Interval: durationPtr(30 * time.Minute), // 周期刷新不参与本测试
	}}
	app := startClient(t, cfg, logger)

	resp := fetchThroughProxy(t, app, target.URL, "u", "p")
	if got := readBody(t, resp); resp.StatusCode != http.StatusOK || got != "target-ok" {
		t.Fatalf("initial request: status=%d body=%q", resp.StatusCode, got)
	}
	waitLogCount(t, clientLogs, `"upstream":"direct"`, 1, "direct route not observed")

	// 远程内容变化 + SIGHUP：立即重拉并生效，无需等待刷新周期。
	body.Store(remoteRulesProxyLoopback)
	next := *cfg
	if err := app.Reload(&next); err != nil {
		t.Fatalf("reload: %v", err)
	}
	resp = fetchThroughProxy(t, app, target.URL, "u", "p")
	if got := readBody(t, resp); resp.StatusCode != http.StatusOK || got != "target-ok" {
		t.Fatalf("request after sighup: status=%d body=%q", resp.StatusCode, got)
	}
	waitLogCount(t, clientLogs, `"route":"proxy"`, 1, "new rules not applied on sighup")
	waitLogCount(t, clientLogs, `"upstream":"`+node.addr+`"`, 1, "sighup request reused the old-route connection")
	waitNodeTunnels(t, nodeLogs, 1, "sighup request served over a stale direct connection")

	// 规则服务不可用 + SIGHUP：重载成功但保持现有规则（容错语义）。
	rulesSrv.Close()
	next = *cfg
	if err := app.Reload(&next); err != nil {
		t.Fatalf("reload with unreachable rules URL must stay lenient: %v", err)
	}
	resp = fetchThroughProxy(t, app, target.URL, "u", "p")
	if got := readBody(t, resp); resp.StatusCode != http.StatusOK || got != "target-ok" {
		t.Fatalf("request after failed recheck: status=%d body=%q", resp.StatusCode, got)
	}
	waitLogCount(t, clientLogs, `"route":"proxy"`, 2, "rules lost after failed recheck")
	waitLogCount(t, clientLogs, `"upstream":"`+node.addr+`"`, 2, "second proxied request did not go through the node")
	waitNodeTunnels(t, nodeLogs, 2, "second proxied request did not complete through the node")
}
