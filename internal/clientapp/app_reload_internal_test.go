package clientapp

import (
	"context"
	"errors"
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

	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/connlimit"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/logging"
	"gopkg.in/yaml.v3"
)

// trojanNodeOf 构造测试用出口节点（协议参数以 yaml.Node 形态承载，
// 与严格解码路径一致）。
func trojanNodeOf(t *testing.T, name, addr, password string) config.Node {
	t.Helper()
	var doc yaml.Node
	body := "addr: " + strconv.Quote(addr) + "\npassword: " + strconv.Quote(password) + "\n"
	if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	return config.Node{Name: name, Protocol: config.ProtocolTrojan, Params: *doc.Content[0]}
}

func boolPtr(v bool) *bool { return &v }

func intPtr(v int) *int { return &v }

// baseReloadCfg 构造一个无需真实网络即可构建运行时的客户端配置。
func baseReloadCfg(t *testing.T, rulesPath string) *config.Config {
	t.Helper()
	cfg := &config.Config{
		Inbounds: []config.Inbound{{Type: config.TypeHTTP, Listen: "127.0.0.1:0"}},
		Outbound: &config.Outbound{Nodes: []config.Node{trojanNodeOf(t, "node-1", "node1.example.com:443", "pw-1")}},
		Timeouts: config.Timeouts{
			Dial:      config.Duration(3 * time.Second),
			Handshake: config.Duration(3 * time.Second),
			Idle:      config.Duration(30 * time.Second),
			Shutdown:  config.Duration(3 * time.Second),
		},
		Log: config.Log{Level: "info", Format: "json"},
	}
	if rulesPath != "" {
		cfg.Routing = &config.Routing{PrivateDirect: boolPtr(false)}
		cfg.Routing.Rulesets = []config.Ruleset{{Name: "local", Type: "file", Path: rulesPath}}
	} else {
		cfg.Routing = &config.Routing{PrivateDirect: boolPtr(false)}
	}
	return cfg
}

// scrapeAppMetrics 直接从应用的指标处理器抓取文本（无需监听端口）。
func scrapeAppMetrics(t *testing.T, app *App) string {
	t.Helper()
	rec := httptest.NewRecorder()
	app.b.metrics.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rec.Body.String()
}

// reloadFileYAML 是 ReloadFile 用例的配置文档（新 schema）。
func reloadFileYAML(rulesPath string) string {
	return `inbounds:
  - type: http
    listen: "127.0.0.1:0"
outbound:
  nodes:
    - name: node-1
      protocol: trojan
      params: { addr: "node1.example.com:443", password: "pw-1" }
routing:
  rulesets: [{ name: local, type: file, path: "` + rulesPath + `" }]
timeouts: { dial: 3s, handshake: 3s, idle: 30s, shutdown: 3s }
log: { level: info, format: json }
`
}

// TestReloadFileCountsEveryAttempt 验证 ReloadFile 对所有失败点计数：
// 解析 / 校验失败（还没走到构建阶段）也计入 config_reloads_total，
// 成功与失败各计一次，不多不少。
func TestReloadFileCountsEveryAttempt(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	app, err := New(baseReloadCfg(t, rulesPath), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "client.yaml")
	goodYAML := reloadFileYAML(rulesPath)
	if err := os.WriteFile(cfgPath, []byte("unknown_field: 1\n"+goodYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := app.ReloadFile(cfgPath, ""); err == nil {
		t.Fatal("config with unknown field must fail to reload")
	}
	if body := scrapeAppMetrics(t, app); !strings.Contains(body, `config_reloads_total{result="error"} 1`) {
		t.Fatalf("parse failure not counted:\n%s", grepLines(body, "config_reloads_total"))
	}

	if err := os.WriteFile(cfgPath, []byte(goodYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := app.ReloadFile(cfgPath, ""); err != nil {
		t.Fatalf("reload: %v", err)
	}
	body := scrapeAppMetrics(t, app)
	if !strings.Contains(body, `config_reloads_total{result="success"} 1`) {
		t.Fatalf("success not counted:\n%s", grepLines(body, "config_reloads_total"))
	}
	if !strings.Contains(body, `config_reloads_total{result="error"} 1`) {
		t.Fatalf("error count changed after success:\n%s", grepLines(body, "config_reloads_total"))
	}
}

// grepLines 返回文本中包含 substr 的行（用于测试失败时的可读输出）。
func grepLines(body, substr string) string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, substr) {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// TestReloadRereadsRulesFile 验证规则文件在每次重载时重读：
// 同一路径下内容变化（不改配置字段）也能生效。
func TestReloadRereadsRulesFile(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte("rules:\n  - action: direct\n    match: [\"*.example.org\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	app, err := New(baseReloadCfg(t, rulesPath), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := app.live.Load().table.Decide("a.example.org"); got != core.RouteDirect {
		t.Fatalf("initial rules: decide = %v, want direct", got)
	}

	// 同一文件路径、内容变化：重载后新规则生效（配置结构体完全未变）。
	if err := os.WriteFile(rulesPath, []byte("rules:\n  - action: direct\n    match: [\"*.example.net\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	next := baseReloadCfg(t, rulesPath)
	if err := retryTransientBindRace(t, func() error { return app.Reload(next) }); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := app.live.Load().table.Decide("a.example.net"); got != core.RouteDirect {
		t.Fatalf("updated rules: decide = %v, want direct", got)
	}
	if got := app.live.Load().table.Decide("a.example.org"); got != core.RouteProxy {
		t.Fatalf("updated rules leaked old match: decide = %v, want proxy", got)
	}
}

// TestReloadFailureLeavesEverythingUntouched 验证失败的构建零副作用：
// 认证、路由、连接上限在失败重载后与失败前完全一致。
func TestReloadFailureLeavesEverythingUntouched(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte("rules:\n  - action: direct\n    match: [\"*.example.org\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	app, err := New(baseReloadCfg(t, rulesPath), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := app.live.Load().Inbounds[0].auth; got != nil {
		t.Fatal("test config should have no inbound auth")
	}
	limitBefore := app.b.limiter.Max()

	next := baseReloadCfg(t, filepath.Join(dir, "missing-rules.yaml"))
	next.Inbounds[0].Auth = &config.AuthConfig{Users: []config.User{{Username: "bob", Password: "pw-bob"}}}
	next.Limits.MaxConnections = intPtr(7)
	if err := app.Reload(next); err == nil {
		t.Fatal("reload with missing rules file must fail")
	}

	// 全部保持旧值：认证未被替换、路由规则未变、连接上限未变。
	if got := app.live.Load().Inbounds[0].auth; got != nil {
		t.Fatalf("failed reload leaked new auth store: %v", got)
	}
	if got := app.live.Load().table.Decide("a.example.org"); got != core.RouteDirect {
		t.Fatalf("failed reload changed routing: decide = %v, want direct", got)
	}
	if got := app.b.limiter.Max(); got != limitBefore {
		t.Fatalf("failed reload changed connection limit: max = %d, want %d", got, limitBefore)
	}
}

// TestReloadAppliesLimitsAndLogConfig 验证连接上限与日志级别/格式随重载生效。
func TestReloadAppliesLimitsAndLogConfig(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	app, err := New(baseReloadCfg(t, rulesPath), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	var buf strings.Builder
	logger, logCtrl := logging.NewControlWithWriter(&buf, "info", "json")
	app.b.logger = logger
	app.b.logCtrl = logCtrl

	next := baseReloadCfg(t, rulesPath)
	next.Limits.MaxConnections = intPtr(3)
	next.Log.Level = "debug"
	if err := retryTransientBindRace(t, func() error { return app.Reload(next) }); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := app.b.limiter.Max(); got != 3 {
		t.Fatalf("limit after reload = %d, want 3", got)
	}
	if got := logCtrl.LevelVar().Level().String(); got != "DEBUG" {
		t.Fatalf("log level after reload = %s, want DEBUG", got)
	}
	if !strings.Contains(buf.String(), "configuration reloaded") {
		t.Fatalf("reload success log missing: %q", buf.String())
	}

	// 重载也接受 0（不限制）。
	unlimited := baseReloadCfg(t, rulesPath)
	unlimited.Limits.MaxConnections = intPtr(0)
	if err := retryTransientBindRace(t, func() error { return app.Reload(unlimited) }); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := app.b.limiter.Max(); got != 0 {
		t.Fatalf("limit after unlimited reload = %d, want 0", got)
	}
}

// TestReloadReusesOrRebuildsUpstreamPools 按指纹语义验证复用边界：
// 非上游变更（日志 / 连接上限）复用节点池（预热池是其内部机制，随节点池
// 一并复用）；上游变更（超时）重建。
func TestReloadReusesOrRebuildsUpstreamPools(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	app, err := New(baseReloadCfg(t, rulesPath), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt := app.live.Load()
	if rt.pool == nil {
		t.Fatal("test setup: node pool must be built")
	}

	// 非上游变更：指纹一致，池指针必须复用。
	hot := *rt.cfg
	hot.Log.Level = "debug"
	hot.Limits.MaxConnections = intPtr(2048)
	if err := retryTransientBindRace(t, func() error { return app.Reload(&hot) }); err != nil {
		t.Fatalf("reload (non-upstream): %v", err)
	}
	rt2 := app.live.Load()
	if rt2.pool != rt.pool {
		t.Fatal("非上游变更必须复用节点池（指纹应一致）")
	}

	// 上游变更：指纹变化，池必须重建。
	cold := *rt2.cfg
	cold.Timeouts.Dial = config.Duration(9 * time.Second)
	if err := retryTransientBindRace(t, func() error { return app.Reload(&cold) }); err != nil {
		t.Fatalf("reload (upstream): %v", err)
	}
	rt3 := app.live.Load()
	if rt3.pool == rt2.pool {
		t.Fatal("上游变更必须重建节点池（指纹应变化）")
	}
}

// TestReloadRebuildsPoolOnNodeWeightChange 验证节点 weight 参与 UpstreamFingerprint：
// 仅改 weight（其余上游配置不变）即视为上游变更，热加载必须重建节点池。
func TestReloadRebuildsPoolOnNodeWeightChange(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	app, err := New(baseReloadCfg(t, rulesPath), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt := app.live.Load()
	if rt.pool == nil {
		t.Fatal("test setup: node pool must be built")
	}

	// 仅变更节点 weight：Outbound 是共享指针，需克隆后再改，避免污染旧快照。
	weighted := *rt.cfg
	ob := *weighted.Outbound
	ob.Nodes = append([]config.Node(nil), ob.Nodes...)
	ob.Nodes[0].Weight = 7
	weighted.Outbound = &ob
	if err := retryTransientBindRace(t, func() error { return app.Reload(&weighted) }); err != nil {
		t.Fatalf("reload (weight change): %v", err)
	}
	rt2 := app.live.Load()
	if rt2.pool == rt.pool {
		t.Fatal("weight 变更必须重建节点池（weight 应参与出口指纹）")
	}
}

// —— 瞬时端口抢占重试（与外部测试包 reload_test.go 的 retryTransientBindRace
// 同源：同目录的 clientapp / clientapp_test 两个测试包无法共享未导出助手，
// 故保留一份精简副本）。病灶与透传语义见彼处的完整注释——switchTo 的
// 「关旧监听 → 绑新监听」窗口内，旧端口可能被并行套件里其他进程的 :0
// 监听抢占，产生一次性的 EADDRINUSE；重试一遍重载即可换端口。仅对
// EADDRINUSE 重试，其余错误原样透传，不掩盖真实的重载失败。注意：
// TestReloadFileCountsEveryAttempt 故意不套重试——它断言重载计数的
// 「恰一次」口径，重试会污染 config_reloads_total。

// reloadBindAttempts 是单次重载针对瞬时端口抢占的最大尝试次数（含首次）。
const reloadBindAttempts = 3

// isTransientBindRace 判定 err 是否为瞬时端口抢占（EADDRINUSE）。
func isTransientBindRace(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) ||
		strings.Contains(err.Error(), "address already in use")
}

// retryTransientBindRace 对 reload 做有界重试：仅当错误是瞬时端口抢占时
// 重试，其余错误原样透传（由调用方按既有断言处置）。
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

// —— switchTo 阶段绑定失败 → 回滚（restore）路径 ——

// rollbackCfg 构造显式端口的 HTTP 入站配置（回滚重绑按显式地址恢复原端口）：
// 无出口节点，私网直连保持缺省开启——环回目标经代理可直达本地 httptest 站点。
func rollbackCfg(httpListen string) *config.Config {
	return &config.Config{
		Inbounds: []config.Inbound{{Type: config.TypeHTTP, Listen: httpListen}},
		Routing:  &config.Routing{},
		Timeouts: config.Timeouts{
			Dial:      config.Duration(3 * time.Second),
			Handshake: config.Duration(3 * time.Second),
			Idle:      config.Duration(30 * time.Second),
			Shutdown:  config.Duration(3 * time.Second),
		},
	}
}

// freeLoopbackAddr 返回一个当前空闲的环回地址（探测监听随即释放）。
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// holdLoopbackListener 绑定并持有占用一个环回地址的监听（制造绑定冲突，
// 由测试全程持有，不依赖竞态窗口）。
func holdLoopbackListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

// startServingApp 启动 Serve 循环并等待其上线（serving 置位：此后 Reload
// 失败时 restore 会以新代际恢复服务）。返回 Serve 的退出错误通道。
func startServingApp(t *testing.T, app *App) <-chan error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	exited := make(chan struct{})
	go func() {
		served <- app.Serve(ctx)
		close(exited)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
		}
	})
	deadline := time.Now().Add(2 * time.Second)
	for !app.Serving() {
		if time.Now().After(deadline) {
			t.Fatal("app did not start serving")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return served
}

// proxyGet 经 HTTP 代理入站以绝对地址 GET 请求 target。
func proxyGet(t *testing.T, proxyAddr, target string) *http.Response {
	t.Helper()
	u, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// TestReloadSwitchBindFailureRollsBackOldListeners 验证回滚成功路径：
// 新配置的入站监听与测试持有的端口冲突 → switchTo 绑新失败 → restore 重建
// 旧监听：旧端点仍正常服务、Reload 返回错误、运行时未切换。
func TestReloadSwitchBindFailureRollsBackOldListeners(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("rollback-ok"))
	}))
	t.Cleanup(target.Close)

	oldAddr := freeLoopbackAddr(t)
	cfg := rollbackCfg(oldAddr)
	app, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	served := startServingApp(t, app)

	// 切换阶段绑定失败：新监听端口被测试全程持有（确定性冲突）。
	next := rollbackCfg(holdLoopbackListener(t))
	if err := app.Reload(next); err == nil {
		t.Fatal("reload with conflicting listener must fail")
	} else if !strings.Contains(err.Error(), "bind new configuration") {
		t.Fatalf("reload error should report the switch-stage bind failure: %v", err)
	}

	// 旧监听被恢复：地址不变，运行时未切换（cfg 指针一致）。
	if got := app.HTTPAddr(); got != oldAddr {
		t.Fatalf("old listener not restored: addr = %q, want %q", got, oldAddr)
	}
	if rt := app.live.Load(); rt.cfg != cfg {
		t.Fatal("runtime switched despite failed reload")
	}

	// Serve 未被一次回滚成功的失败重载终止。
	select {
	case err := <-served:
		t.Fatalf("Serve exited on a rolled-back reload: %v", err)
	case <-time.After(250 * time.Millisecond):
	}

	// 旧端点仍正常服务：经代理请求环回目标（私网直连，无需出口节点）。
	resp := proxyGet(t, app.HTTPAddr(), target.URL)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "rollback-ok" {
		t.Fatalf("old endpoint after rollback: status=%d body=%q", resp.StatusCode, body)
	}
}

// TestReloadRollbackKeepsEphemeralPorts 验证回滚端口稳定（open-items #2）：
// :0 入站在失败重载的回滚重绑后保持原监听地址——restore 以 cur 自身已解析
// 地址为提示重绑（Bind(cur, cur)），与 switchTo 成功路径的同端口语义一致
// （固定端口行为由 TestReloadSwitchBindFailureRollsBackOldListeners 覆盖）。
// 刻意制造确定性的切换阶段绑定失败（新配置把 http 入站指向被持有的固定
// 端口），因此不走瞬时端口抢占重试 helper。
func TestReloadRollbackKeepsEphemeralPorts(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("rollback-ok"))
	}))
	t.Cleanup(target.Close)

	// 两个 :0 入站（http + socks5）：初始绑定各自获得临时端口。
	cfg := rollbackCfg("127.0.0.1:0")
	cfg.Inbounds = append(cfg.Inbounds, config.Inbound{Type: config.TypeSOCKS5, Listen: "127.0.0.1:0"})
	app, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	served := startServingApp(t, app)
	httpBefore, socksBefore := app.HTTPAddr(), app.SOCKS5Addr()
	if httpBefore == "" || socksBefore == "" {
		t.Fatalf("inbounds not bound: http=%q socks5=%q", httpBefore, socksBefore)
	}

	// 新配置把 http 入站指向被测试全程持有的固定端口（确定性冲突），socks5
	// 保持 :0：绑新在 http 处失败进入 restore，两个 :0 入站都按旧地址重绑。
	next := rollbackCfg(holdLoopbackListener(t))
	next.Inbounds = append(next.Inbounds, config.Inbound{Type: config.TypeSOCKS5, Listen: "127.0.0.1:0"})
	if err := app.Reload(next); err == nil {
		t.Fatal("reload with conflicting listener must fail")
	} else if !strings.Contains(err.Error(), "bind new configuration") || strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("reload error should be a switch-stage bind failure with a successful rollback: %v", err)
	}

	// 端口稳定：两个 :0 入站的监听地址与重载前完全一致；运行时未切换。
	if got := app.HTTPAddr(); got != httpBefore {
		t.Fatalf("rollback moved the :0 http listener: %s -> %s", httpBefore, got)
	}
	if got := app.SOCKS5Addr(); got != socksBefore {
		t.Fatalf("rollback moved the :0 socks5 listener: %s -> %s", socksBefore, got)
	}
	if rt := app.live.Load(); rt.cfg != cfg {
		t.Fatal("runtime switched despite failed reload")
	}

	// Serve 未被一次回滚成功的失败重载终止。
	select {
	case err := <-served:
		t.Fatalf("Serve exited on a rolled-back reload: %v", err)
	case <-time.After(250 * time.Millisecond):
	}

	// 服务在原端口继续：经恢复的 http 监听请求环回目标（私网直连）。
	resp := proxyGet(t, app.HTTPAddr(), target.URL)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "rollback-ok" {
		t.Fatalf("old endpoint after rollback: status=%d body=%q", resp.StatusCode, body)
	}
}

// TestReloadRollbackFailureFailsClosed 验证回滚失败 → fail-closed：
// 注入 restore 的绑定失败（旧监听无法重建）后，Reload 返回错误且 Serve
// 退出并上报该错误——进程不以零监听状态静默存活，交由进程管理器重启。
// 构造方式：bind 闭包只被重载重绑路径调用，正常运行不经它，因此把旧运行时
// 入站的 bind 换成必定失败的实现即可确定性地令 restore 失败（无竞态窗口）。
func TestReloadRollbackFailureFailsClosed(t *testing.T) {
	cfg := rollbackCfg(freeLoopbackAddr(t))
	app, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	served := startServingApp(t, app)

	// 注入点：旧运行时入站的重绑闭包直接失败。
	cur := app.live.Load()
	cur.Inbounds[0].bind = func(*connlimit.Limiter, string) (inboundBound, error) {
		return inboundBound{}, errors.New("injected: restore bind failure")
	}

	// 绑新同样失败（端口被测试持有）：进入 restore，而 restore 注入失败。
	next := rollbackCfg(holdLoopbackListener(t))
	if err := app.Reload(next); err == nil || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("reload must report the rollback failure: %v", err)
	}

	// fail-closed：Serve 退出且错误上报（fail → appCancel → firstErr）。
	select {
	case serr := <-served:
		if serr == nil || !strings.Contains(serr.Error(), "rollback") {
			t.Fatalf("Serve error should surface the rollback failure: %v", serr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not exit after failed rollback; process would linger with zero listeners")
	}
}
