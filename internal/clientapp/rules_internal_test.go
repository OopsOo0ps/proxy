package clientapp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/OopsOo0ps/proxy/internal/core"
)

func writeRules(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestReloadReusesRulesProviderWhenSourceUnchanged 验证规则源配置未变时重载
// 复用同一 Provider（不重建、不重启刷新循环），并立即重读文件内容生效。
func TestReloadReusesRulesProviderWhenSourceUnchanged(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	writeRules(t, rulesPath, "rules:\n  - action: direct\n    match: [\"*.example.org\"]\n")
	app, err := New(baseReloadCfg(t, rulesPath), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	before := app.live.Load().providers[0]

	writeRules(t, rulesPath, "rules:\n  - action: direct\n    match: [\"*.example.net\"]\n")
	next := baseReloadCfg(t, rulesPath)
	if err := retryTransientBindRace(t, func() error { return app.Reload(next) }); err != nil {
		t.Fatalf("reload: %v", err)
	}
	after := app.live.Load().providers[0]
	if after != before {
		t.Fatal("rules provider must be reused when the source is unchanged")
	}
	if got := after.Decide("a.example.net"); got != core.RouteDirect {
		t.Fatalf("new file content not applied: decide = %v", got)
	}
	if got := after.Decide("a.example.org"); got != core.RouteProxy {
		t.Fatalf("old rules leaked: decide = %v", got)
	}
}

// TestReloadSwitchesRulesProviderWhenSourceChanges 验证规则源配置变化时重建
// Provider（旧规则不再生效，新源立即加载）。
func TestReloadSwitchesRulesProviderWhenSourceChanges(t *testing.T) {
	dir := t.TempDir()
	rulesA := filepath.Join(dir, "a.yaml")
	rulesB := filepath.Join(dir, "b.yaml")
	writeRules(t, rulesA, "rules:\n  - action: direct\n    match: [\"*.example.org\"]\n")
	writeRules(t, rulesB, "rules:\n  - action: direct\n    match: [\"*.example.net\"]\n")
	app, err := New(baseReloadCfg(t, rulesA), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	before := app.live.Load().providers[0]

	next := baseReloadCfg(t, rulesB)
	if err := retryTransientBindRace(t, func() error { return app.Reload(next) }); err != nil {
		t.Fatalf("reload: %v", err)
	}
	after := app.live.Load().providers[0]
	if after == before {
		t.Fatal("rules provider must be rebuilt when the source changes")
	}
	if after.Spec().Target != rulesB {
		t.Fatalf("spec target = %q, want %q", after.Spec().Target, rulesB)
	}
	if got := after.Decide("a.example.net"); got != core.RouteDirect {
		t.Fatalf("new source rules not applied: decide = %v", got)
	}
	if got := after.Decide("a.example.org"); got != core.RouteProxy {
		t.Fatalf("old source rules leaked: decide = %v", got)
	}
}

// TestRuntimeStatsIncludesRuleset 验证 /stats 快照包含规则源状态。
func TestRuntimeStatsIncludesRuleset(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	writeRules(t, rulesPath, "rules:\n  - action: direct\n    match: [\"*.example.org\"]\n")
	app, err := New(baseReloadCfg(t, rulesPath), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt := app.b.runtimeStats()
	if rt.Ruleset == nil {
		t.Fatal("stats must include the ruleset section when a source is configured")
	}
	if rt.Ruleset.Source != "file" || rt.Ruleset.Target != rulesPath ||
		!rt.Ruleset.Loaded || rt.Ruleset.Rules != 1 || rt.Ruleset.LastSuccess == "" {
		t.Fatalf("unexpected ruleset stats: %+v", rt.Ruleset)
	}
}

// TestRuntimeStatsOmitsRulesetWithoutSource 验证未配置规则源时不输出 ruleset 段。
func TestRuntimeStatsOmitsRulesetWithoutSource(t *testing.T) {
	app, err := New(baseReloadCfg(t, ""), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rt := app.b.runtimeStats(); rt.Ruleset != nil {
		t.Fatalf("ruleset section must be omitted without a source: %+v", rt.Ruleset)
	}
}

// TestBuildRejectsUnknownProtocols 钉住两个分派点的 fail-fast 语义：
// 未知入站类型与未知出口协议在组装期报用户可读错误（解析期拦截在 config）。
func TestBuildRejectsUnknownProtocols(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	writeRules(t, rulesPath, "")

	badInbound := baseReloadCfg(t, rulesPath)
	badInbound.Inbounds[0].Type = "quic"
	if _, err := Build(badInbound, BuildOptions{}); err == nil || !strings_Contains(err.Error(), "unknown inbound type") {
		t.Fatalf("unknown inbound type must fail at build, got %v", err)
	}

	badNode := baseReloadCfg(t, rulesPath)
	badNode.Outbound.Nodes[0].Protocol = "shadowsocks"
	if _, err := Build(badNode, BuildOptions{}); err == nil || !strings_Contains(err.Error(), "unknown outbound protocol") {
		t.Fatalf("unknown outbound protocol must fail at build, got %v", err)
	}
}

// strings_Contains 是测试内的子串判断（避免仅为此导入 strings）。
func strings_Contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
