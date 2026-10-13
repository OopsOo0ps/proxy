package clientapp

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/config"
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
	if err := app.Reload(next); err != nil {
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
	if err := app.Reload(next); err != nil {
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
	if err := app.Reload(unlimited); err != nil {
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
	if err := app.Reload(&hot); err != nil {
		t.Fatalf("reload (non-upstream): %v", err)
	}
	rt2 := app.live.Load()
	if rt2.pool != rt.pool {
		t.Fatal("非上游变更必须复用节点池（指纹应一致）")
	}

	// 上游变更：指纹变化，池必须重建。
	cold := *rt2.cfg
	cold.Timeouts.Dial = config.Duration(9 * time.Second)
	if err := app.Reload(&cold); err != nil {
		t.Fatalf("reload (upstream): %v", err)
	}
	rt3 := app.live.Load()
	if rt3.pool == rt2.pool {
		t.Fatal("上游变更必须重建节点池（指纹应变化）")
	}
}
