package clientapp_test

import (
	"context"
	"errors"
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
	"syscall"
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

// —— 重载的瞬时端口抢占重试（纯测试装置，不改变任何重载语义）——
//
// 病灶：switchTo 切换阶段「先关旧监听、再绑新监听」，端口 0 的入站按旧
// 已解析端口重绑。全量套件（go test ./...）并行运行多个包的测试二进制，
// 刚释放的临时端口可能在这一关-绑窗口内被其他进程的 :0 监听抢占，重载
// 于是带着一次性的 EADDRINUSE 失败（表现为
// "clientapp: bind new configuration: clientapp: listen socks5 127.0.0.1:0:
// listen tcp 127.0.0.1:NNNNN: bind: address already in use"）。
// 这是测试环境噪声而非产品缺陷：失败重载的回滚路径已让旧配置继续服务，
// 把重载原样再执行一遍即可换到未被抢占的端口。

// reloadBindAttempts 是单次重载针对瞬时端口抢占的最大尝试次数（含首次）。
const reloadBindAttempts = 3

// isTransientBindRace 判定 err 是否为上述瞬时端口抢占（EADDRINUSE）：
// errors.Is 为主（错误链全程 %w），字符串兜底覆盖经 %v 中转的包装路径。
func isTransientBindRace(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) ||
		strings.Contains(err.Error(), "address already in use")
}

// retryTransientBindRace 对 reload 做有界重试：仅当错误是瞬时端口抢占时
// 重试，其余错误原样透传——由调用方按既有断言处置（该报错的报错、该
// 断言的断言），绝不掩盖真实的重载失败（构建错误、entitlement 拒绝、
// 回滚失败等一律原样上抛）。
func retryTransientBindRace(t *testing.T, reload func() error) error {
	t.Helper()
	var err error
	for attempt := 1; attempt <= reloadBindAttempts; attempt++ {
		err = reload()
		if err == nil || !isTransientBindRace(err) {
			return err
		}
		t.Logf("reload hit a transient ephemeral-port bind race (attempt %d/%d): %v",
			attempt, reloadBindAttempts, err)
	}
	return err
}

// reloadWithPortRetry 等价于 app.ReloadFile(cfgPath, levelOverride)，仅对
// 瞬时端口抢占自动重试（见 retryTransientBindRace）。
func reloadWithPortRetry(t *testing.T, app *clientapp.App, cfgPath, levelOverride string) error {
	t.Helper()
	return retryTransientBindRace(t, func() error { return app.ReloadFile(cfgPath, levelOverride) })
}

// TestReloadSwapsInboundAuth 验证热加载后入站凭据原子替换：
// 新凭据立即生效，旧凭据立即失效，且请求链路（经出口节点）全程可用。
// 两个入站均为端口 0（自动分配）：重载沿用已解析端口（同端口重载成功）。
func TestReloadSwapsInboundAuth(t *testing.T) {
	h := startServer(t, "node-secret", nil, false)
	target := startPlainTarget(t)

	cfg := withAuth(baseClientCfg([]config.Node{trojanNode(t, "node-1", h.addr, "node-secret")}), "alice", "pw-alice")
	app := startClient(t, cfg, nil)
	httpAddrBefore := app.HTTPAddr()

	resp := fetchThroughProxy(t, app, target.URL, "alice", "pw-alice")
	if body := readBody(t, resp); resp.StatusCode != http.StatusOK || body != "target-ok" {
		t.Fatalf("initial credentials: status=%d body=%q", resp.StatusCode, body)
	}

	next := cloneCfg(cfg)
	for i := range next.Inbounds {
		next.Inbounds[i].Auth = &config.AuthConfig{Users: []config.User{{Username: "bob", Password: "pw-bob"}}}
	}
	if err := retryTransientBindRace(t, func() error { return app.Reload(next) }); err != nil {
		t.Fatalf("reload: %v", err)
	}
	// 同端口重载：监听地址保持不变（端口 0 的配置沿用已解析端口）。
	if got := app.HTTPAddr(); got != httpAddrBefore {
		t.Fatalf("same-port reload moved the listener: %s -> %s", httpAddrBefore, got)
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

	cfg := baseClientCfg([]config.Node{trojanNode(t, "old", oldNode.addr, "old-secret")})
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
	next := cloneCfg(cfg)
	next.Outbound.Nodes = []config.Node{trojanNode(t, "new", newNode.addr, "new-secret")}
	next.Outbound.Pool.Prewarm.Size = intPtr(1)
	if err := retryTransientBindRace(t, func() error { return app.Reload(next) }); err != nil {
		t.Fatalf("reload: %v", err)
	}
	resp = fetchThroughProxy(t, app, target.URL, "u", "p")
	if body := readBody(t, resp); resp.StatusCode != http.StatusOK || body != "target-ok" {
		t.Fatalf("after node swap: status=%d body=%q", resp.StatusCode, body)
	}
}

// TestReloadAppliesHealthCheckConfig 验证 health 配置属热加载项：
// 关闭主动探测后节点池重建，死节点不再被摘除，旧池的探测循环同步停止。
func TestReloadAppliesHealthCheckConfig(t *testing.T) {
	stable := startServer(t, "stable-secret", nil, false)
	deadAddr := freeTCPAddr(t) // 无监听者
	target := startPlainTarget(t)

	cfg := withAuth(baseClientCfg([]config.Node{
		trojanNode(t, "stable", stable.addr, "stable-secret"),
		trojanNode(t, "dead", deadAddr, "dead-secret"),
	}), "alice", "pw")
	cfg.API.Listen = "127.0.0.1:0"
	cfg.Outbound.Pool.Health = config.HealthConfig{
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
	next := cloneCfg(cfg)
	next.Outbound.Pool.Health = config.HealthConfig{Interval: durationPtr(0)}
	if err := retryTransientBindRace(t, func() error { return app.Reload(next) }); err != nil {
		t.Fatalf("reload: %v", err)
	}
	waitUpstream(t, app.MetricsAddr(), deadAddr, func(up upstreamStats) bool { return !up.Removed })

	// 基线在 Reload 返回后取：validate-then-swap 语义下旧配置在切换前持续
	// 生效，旧探测循环的最后一批结果可能落在重载期间（Reload 返回之前）；
	// Reload 内部的资源释放会等待探测循环（含在途探测）退出，因此从返回
	// 那一刻起计数不再增长才是本用例要断言的性质。
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

// TestReloadKeepsReusedPoolHealthLoopRunning 验证热加载复用组件的后台循环
// 不停摆：Reload 只改日志级别（节点池指纹不变 → 池被复用，指针复用已有
// TestReloadReusesOrRebuildsUpstreamPools 覆盖），复用实例的健康探测循环
// 必须继续按周期探测——后台资源绑定应用级 ctx，寿命 = 实例寿命，由 Close
// 终结，不随代际结束而停止。
func TestReloadKeepsReusedPoolHealthLoopRunning(t *testing.T) {
	stable := startServer(t, "stable-secret", nil, false)

	cfg := baseClientCfg([]config.Node{trojanNode(t, "stable", stable.addr, "stable-secret")})
	cfg.API.Listen = "127.0.0.1:0"
	cfg.Outbound.Pool = config.PoolConfig{
		Prewarm: config.PrewarmConfig{Size: intPtr(1), TTL: config.Duration(30 * time.Second)},
		Health: config.HealthConfig{
			Interval:  durationPtr(100 * time.Millisecond),
			Timeout:   config.Duration(300 * time.Millisecond),
			Failures:  intPtr(2),
			Successes: intPtr(2),
		},
	}
	app := startClient(t, cfg, nil)

	// 探测循环已运转：稳定节点的成功探测计数开始增长。
	probeSeries := `upstream_health_probes_total{node="` + stable.addr + `",result="success"}`
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if metricSeriesValue(t, app.MetricsAddr(), probeSeries) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if metricSeriesValue(t, app.MetricsAddr(), probeSeries) == 0 {
		t.Fatal("health probe loop did not start")
	}

	// Reload 只改日志级别：不得触碰 health/pool/nodes（保证指纹不变 → 池复用）。
	next := cloneCfg(cfg)
	next.Log.Level = "info"
	if err := retryTransientBindRace(t, func() error { return app.Reload(next) }); err != nil {
		t.Fatalf("reload: %v", err)
	}

	// 基线在 Reload 返回后取：validate-then-swap 语义下旧配置在切换前持续
	// 生效，切换瞬间最后一轮探测结果可能仍落在 Reload 返回之前。
	baseline := metricSeriesValue(t, app.MetricsAddr(), probeSeries)

	// ≥1s 观察窗口内两次采样，计数必须严格增长：复用实例的探测循环
	// 绑定应用级 ctx，不随旧代际取消而停摆。
	time.Sleep(400 * time.Millisecond)
	first := metricSeriesValue(t, app.MetricsAddr(), probeSeries)
	time.Sleep(700 * time.Millisecond)
	second := metricSeriesValue(t, app.MetricsAddr(), probeSeries)
	if second <= first {
		t.Fatalf("探测循环在热加载后停摆：baseline=%d first=%d second=%d（窗口内计数应严格增长）",
			baseline, first, second)
	}
}

// TestReloadFailureKeepsOldConfig 验证“配置错误不炸线上”：
// 解析校验失败（模拟 main 的加载路径）与构建失败（规则文件缺失）
// 都不会改变运行中的配置，服务持续可用。
func TestReloadFailureKeepsOldConfig(t *testing.T) {
	h := startServer(t, "node-secret", nil, false)
	target := startPlainTarget(t)

	cfg := withAuth(baseClientCfg([]config.Node{trojanNode(t, "node-1", h.addr, "node-secret")}), "alice", "pw-alice")
	app := startClient(t, cfg, nil)

	dir := t.TempDir()

	// 1) 文件解析 / 校验失败：Load 报错，应用完全不被触碰（main 只记录日志）。
	badPath := filepath.Join(dir, "client.yaml")
	if err := os.WriteFile(badPath, []byte("unknown_field: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(badPath, clientapp.KnownProtocols); err == nil {
		t.Fatal("config with unknown field must fail to load")
	}

	// 2) 构建失败：规则文件缺失（同时改动了认证），整份配置不得部分生效。
	next := cloneCfg(cfg)
	next.Routing.Rulesets = []config.Ruleset{{Name: "missing", Type: "file", Path: filepath.Join(dir, "missing-rules.yaml")}}
	for i := range next.Inbounds {
		next.Inbounds[i].Auth = &config.AuthConfig{Users: []config.User{{Username: "bob", Password: "pw-bob"}}}
	}
	if err := app.Reload(next); err == nil {
		t.Fatal("reload with missing rules file must fail")
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

// TestReloadRebindsMovedListener 验证重载支持监听变更（§8.2：快照重建是
// 默认路径，"需重启字段"不存在）：入站监听地址在重载后原子迁移——新端口
// 立即服务，旧端口停止接受；运维端点地址不受影响。
func TestReloadRebindsMovedListener(t *testing.T) {
	h := startServer(t, "node-secret", nil, false)
	target := startPlainTarget(t)

	cfg := baseClientCfg([]config.Node{trojanNode(t, "node-1", h.addr, "node-secret")})
	app := startClient(t, cfg, nil)
	oldHTTP := app.HTTPAddr()

	// 新监听地址：显式空闲端口。
	newAddr := "127.0.0.1:" + portOf(freeTCPAddr(t))
	next := cloneCfg(cfg)
	next.Inbounds[0].Listen = newAddr
	if err := retryTransientBindRace(t, func() error { return app.Reload(next) }); err != nil {
		t.Fatalf("reload with moved listener: %v", err)
	}
	if got := app.HTTPAddr(); got != newAddr {
		t.Fatalf("listener did not move: addr = %q, want %q", got, newAddr)
	}

	// 旧端口停止服务，新端口正常转发。
	if conn, err := net.DialTimeout("tcp", oldHTTP, 300*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("old listener must stop accepting after the reload")
	}
	resp := fetchThroughProxy(t, app, target.URL, "u", "p")
	if body := readBody(t, resp); resp.StatusCode != http.StatusOK || body != "target-ok" {
		t.Fatalf("request via new listener: status=%d body=%q", resp.StatusCode, body)
	}
}

// TestReloadRejectsDuringShutdown 验证关停期拒绝重载（§8.2）：
// 排空已开始时收到重载请求，明确拒绝且不启动半死的新运行时。
func TestReloadRejectsDuringShutdown(t *testing.T) {
	h := startServer(t, "node-secret", nil, false)
	cfg := baseClientCfg([]config.Node{trojanNode(t, "node-1", h.addr, "node-secret")})
	app, err := clientapp.New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("clientapp.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})

	// 触发关停（排空开始），随后重载必须被拒绝。
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		err := app.Reload(cloneCfg(cfg))
		if err != nil {
			if !strings.Contains(err.Error(), "shutting down; reload ignored") {
				t.Fatalf("reload during shutdown: got %v", err)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("reload during shutdown must be rejected")
}

// portOf 提取 host:port 地址的端口段。
func portOf(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return port
}
