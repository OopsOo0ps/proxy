package clientapp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/logging"
	"github.com/OopsOo0ps/proxy/internal/routing"
)

// baseReloadCfg 构造一个无需真实网络即可构建运行时的客户端配置。
func baseReloadCfg(t *testing.T, rulesPath string) *config.Client {
	t.Helper()
	return &config.Client{
		Inbound: config.Inbound{HTTP: "127.0.0.1:0"},
		Nodes:   []config.Node{{Addr: "node1.example.com:443", Password: "pw-1"}},
		Routing: config.Routing{Default: "proxy", RulesFile: rulesPath, PrivateDirect: boolPtr(false)},
		Timeouts: config.Timeouts{
			Dial:      config.Duration(3 * time.Second),
			Handshake: config.Duration(3 * time.Second),
			Idle:      config.Duration(30 * time.Second),
			Shutdown:  config.Duration(3 * time.Second),
		},
		Log: config.Log{Level: "info", Format: "json"},
	}
}

func boolPtr(v bool) *bool { return &v }

func intPtr(v int) *int { return &v }

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
	if got := app.policy.load().router.Decide("a.example.org"); got != routing.Direct {
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
	if got := app.policy.load().router.Decide("a.example.net"); got != routing.Direct {
		t.Fatalf("updated rules: decide = %v, want direct", got)
	}
	if got := app.policy.load().router.Decide("a.example.org"); got != routing.Proxy {
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
	if app.policy.load().auth != nil {
		t.Fatal("test config should have no inbound auth")
	}
	limitBefore := app.limiter.Max()

	next := baseReloadCfg(t, filepath.Join(dir, "missing-rules.yaml"))
	next.Inbound.Auth = []config.User{{Username: "bob", Password: "pw-bob"}}
	next.Limits.MaxConnections = intPtr(7)
	if err := app.Reload(next); err == nil {
		t.Fatal("reload with missing rules file must fail")
	}

	// 全部保持旧值：认证未被替换、路由规则未变、连接上限未变。
	if got := app.policy.load().auth; got != nil {
		t.Fatalf("failed reload leaked new auth store: %v", got)
	}
	if got := app.policy.load().router.Decide("a.example.org"); got != routing.Direct {
		t.Fatalf("failed reload changed routing: decide = %v, want direct", got)
	}
	if got := app.limiter.Max(); got != limitBefore {
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
	app.logger = logger
	app.logCtrl = logCtrl

	next := baseReloadCfg(t, rulesPath)
	next.Limits.MaxConnections = intPtr(3)
	next.Log.Level = "debug"
	if err := app.Reload(next); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := app.limiter.Max(); got != 3 {
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
	if got := app.limiter.Max(); got != 0 {
		t.Fatalf("limit after unlimited reload = %d, want 0", got)
	}
}
