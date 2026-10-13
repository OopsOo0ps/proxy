package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/routing"
)

// 规则文档解析（YAML 形态的 routing.Rules）测试在此包：config 是全仓唯一
// 的 yaml 属主，文档格式兼容 configs/example-rules.yaml；routing 只消费
// 纯结构，其匹配语义测试在 routing 包。

func TestParseRules(t *testing.T) {
	rules, err := ParseRules([]byte(`
rules:
  - action: direct
    match:
      - "example.cn"
      - "*.corp.example.com"
      - "10.0.0.0/8"
      - "192.168.1.1"
      - "2001:db8::/32"
      - "localhost"
  - action: proxy
    match:
      - "*.blocked.example.com"
`))
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	if rules.Default != nil {
		t.Fatalf("default = %v, want nil (文档未指定)", rules.Default)
	}
	if len(rules.Rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(rules.Rules))
	}
	if rules.Rules[0].Action != core.RouteDirect || len(rules.Rules[0].Match) != 6 {
		t.Fatalf("rule[0] = %+v", rules.Rules[0])
	}
	if rules.Rules[1].Action != core.RouteProxy || len(rules.Rules[1].Match) != 1 {
		t.Fatalf("rule[1] = %+v", rules.Rules[1])
	}

	// 解析结果必须能被 routing 引擎编译并按序匹配。
	e, err := routing.NewEngine(rules, routing.Options{Default: core.RouteProxy})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if got := e.Decide("a.corp.example.com"); got != core.RouteDirect {
		t.Fatalf("Decide = %v, want direct", got)
	}
	if got := e.Decide("x.blocked.example.com"); got != core.RouteProxy {
		t.Fatalf("Decide = %v, want proxy", got)
	}
}

func TestParseRulesDefaultOverridesOptions(t *testing.T) {
	rules, err := ParseRules([]byte(`
default: direct
rules:
  - action: proxy
    match: ["*.example.com"]
`))
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	if rules.Default == nil || *rules.Default != core.RouteDirect {
		t.Fatalf("default = %v, want direct", rules.Default)
	}
}

func TestParseRulesRejects(t *testing.T) {
	cases := map[string]string{
		"unknown top field":  "track: true\n",
		"unknown rule field": "rules:\n  - action: direct\n    match: [\"a.com\"]\n    note: x\n",
		"bad action":         "rules:\n  - action: tunnel\n    match: [\"a.com\"]\n",
		"empty match":        "rules:\n  - action: direct\n    match: []\n",
		"bad default":        "default: nope\n",
		"bad wildcard":       "rules:\n  - action: direct\n    match: [\"*.\"]\n",
		"bad cidr":           "rules:\n  - action: direct\n    match: [\"10.0.0.0/33\"]\n",
		"space in entry":     "rules:\n  - action: direct\n    match: [\"a b\"]\n",
		"bad domain char":    "rules:\n  - action: direct\n    match: [\"ho*st\"]\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRules([]byte(doc)); err == nil {
				t.Fatalf("expected parse error for %s", name)
			}
		})
	}
}

func TestParseRulesEmptyFile(t *testing.T) {
	rules, err := ParseRules(nil)
	if err != nil {
		t.Fatalf("ParseRules(nil): %v", err)
	}
	if len(rules.Rules) != 0 || rules.Default != nil {
		t.Fatalf("empty rules should have no content: %+v", rules)
	}
}

// TestShippedExampleRulesParse 防示例漂移：仓库自带的规则文件必须始终可解析
// 并被引擎编译（文件格式变更即失败）。
func TestShippedExampleRulesParse(t *testing.T) {
	data, err := os.ReadFile("../../configs/example-rules.yaml")
	if err != nil {
		t.Fatalf("read example rules: %v", err)
	}
	rules, err := ParseRules(data)
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	if _, err := routing.NewEngine(rules, routing.Options{Default: core.RouteProxy}); err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
}

// TestParseRulesRoundTripsFileContent 钉住“规则文件格式保持兼容”：
// 既有格式（default + rules 列表，match 为字符串数组）解析结果与历史行为一致。
func TestParseRulesRoundTripsFileContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	content := "default: proxy\nrules:\n  - action: direct\n    match: [\"*.cn\"]\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := ParseRules(data)
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	if rules.Default == nil || *rules.Default != core.RouteProxy {
		t.Fatalf("default = %v, want proxy", rules.Default)
	}
	if len(rules.Rules) != 1 || rules.Rules[0].Action != core.RouteDirect {
		t.Fatalf("unexpected rules: %+v", rules.Rules)
	}
}
