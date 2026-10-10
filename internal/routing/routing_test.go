package routing

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustEngine(t *testing.T, rules *Rules, opts Options) *Engine {
	t.Helper()
	e, err := NewEngine(rules, opts)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func directRules(t *testing.T) *Rules {
	t.Helper()
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
	return rules
}

func TestDecideMatching(t *testing.T) {
	e := mustEngine(t, directRules(t), Options{Default: Proxy})
	cases := map[string]Action{
		"example.cn":              Direct, // 精确域名
		"www.example.cn":          Proxy,  // 精确域名不匹配子域
		"www.corp.example.com":    Direct, // 通配子域
		"a.b.corp.example.com":    Direct, // 多级子域
		"corp.example.com":        Proxy,  // 通配不匹配裸域
		"xcorp.example.com":       Proxy,  // 后缀必须按标签边界
		"10.1.2.3":                Direct, // CIDR 内
		"11.1.2.3":                Proxy,  // CIDR 外
		"192.168.1.1":             Direct, // 精确 IP
		"192.168.1.2":             Proxy,
		"2001:db8::1":             Direct, // IPv6 CIDR
		"2001:db9::1":             Proxy,
		"localhost":               Direct,
		"www.blocked.example.com": Proxy, // 命中 proxy 规则
		"other.example.com":       Proxy, // 默认动作
	}
	for host, want := range cases {
		if got := e.Decide(host); got != want {
			t.Errorf("Decide(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestDecideNormalization(t *testing.T) {
	e := mustEngine(t, directRules(t), Options{Default: Proxy})
	for _, host := range []string{"EXAMPLE.CN", "example.cn.", " Example.CN "} {
		if got := e.Decide(host); got != Direct {
			t.Errorf("Decide(%q) = %v, want direct", host, got)
		}
	}
	if got := e.Decide(""); got != Proxy {
		t.Errorf("Decide(empty) = %v, want default proxy", got)
	}
}

func TestDecideFirstMatchWins(t *testing.T) {
	rules, err := ParseRules([]byte(`
rules:
  - action: proxy
    match: ["*.example.com"]
  - action: direct
    match: ["*.example.com"]
`))
	if err != nil {
		t.Fatal(err)
	}
	e := mustEngine(t, rules, Options{Default: Direct})
	if got := e.Decide("a.example.com"); got != Proxy {
		t.Fatalf("first matching rule should win, got %v", got)
	}
}

func TestRulesFileDefaultOverridesOptions(t *testing.T) {
	rules, err := ParseRules([]byte(`
default: direct
rules:
  - action: proxy
    match: ["*.example.com"]
`))
	if err != nil {
		t.Fatal(err)
	}
	e := mustEngine(t, rules, Options{Default: Proxy})
	if got := e.Decide("unmatched.host"); got != Direct {
		t.Fatalf("rules default should override options default, got %v", got)
	}
	if got := e.Decide("a.example.com"); got != Proxy {
		t.Fatalf("rule should still apply, got %v", got)
	}
}

func TestPrivateDirectBuiltin(t *testing.T) {
	e := mustEngine(t, nil, Options{Default: Proxy, PrivateDirect: true})
	for _, host := range []string{
		"127.0.0.1", "10.0.0.5", "192.168.31.7", "172.16.0.1",
		"::1", "fe80::1", "fc00::1", "0.0.0.0", "224.0.0.1", "localhost",
	} {
		if got := e.Decide(host); got != Direct {
			t.Errorf("Decide(%q) = %v, want direct (private)", host, got)
		}
	}
	if got := e.Decide("8.8.8.8"); got != Proxy {
		t.Errorf("public IP should follow default, got %v", got)
	}
}

func TestPrivateDirectDisabled(t *testing.T) {
	e := mustEngine(t, nil, Options{Default: Proxy, PrivateDirect: false})
	if got := e.Decide("127.0.0.1"); got != Proxy {
		t.Fatalf("Decide(127.0.0.1) = %v, want proxy when private_direct disabled", got)
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
	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRules([]byte(yaml)); err == nil {
				t.Fatalf("expected parse error for %s", name)
			}
		})
	}
}

func TestNewEngineRejectsBadMatcher(t *testing.T) {
	rules, err := ParseRules([]byte("rules:\n  - action: direct\n    match: [\"10.0.0.0/33\"]\n"))
	if err != nil {
		// 解析阶段就可能因未知结构失败，这里只要求最终不可用。
		return
	}
	if _, err := NewEngine(rules, Options{}); err == nil {
		t.Fatal("expected compile error for bad CIDR")
	}
}

func TestLoadRulesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	content := "default: proxy\nrules:\n  - action: direct\n    match: [\"*.cn\"]\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadRulesFile(path)
	if err != nil {
		t.Fatalf("LoadRulesFile: %v", err)
	}
	if rules.Default == nil || *rules.Default != Proxy {
		t.Fatalf("default = %v, want proxy", rules.Default)
	}
	if len(rules.Rules) != 1 || rules.Rules[0].Action != Direct {
		t.Fatalf("unexpected rules: %+v", rules.Rules)
	}

	if _, err := LoadRulesFile(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("expected error for missing file")
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

func TestParseAction(t *testing.T) {
	if a, err := ParseAction("Direct"); err != nil || a != Direct {
		t.Fatalf("ParseAction(Direct) = (%v, %v)", a, err)
	}
	if a, err := ParseAction("proxy"); err != nil || a != Proxy {
		t.Fatalf("ParseAction(proxy) = (%v, %v)", a, err)
	}
	if _, err := ParseAction("other"); err == nil {
		t.Fatal("expected error for unknown action")
	}
	if !strings.Contains(Direct.String(), "direct") || !strings.Contains(Proxy.String(), "proxy") {
		t.Fatal("action String() mismatch")
	}
}

func TestShippedExampleRulesParse(t *testing.T) {
	rules, err := LoadRulesFile("../../configs/example-rules.yaml")
	if err != nil {
		t.Fatalf("LoadRulesFile: %v", err)
	}
	if _, err := NewEngine(rules, Options{Default: Proxy}); err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
}

// BenchmarkDecide 测量分流决策热路径。规则集模拟常见形态：
// 一组直连规则（域名 / 通配 / 网段）+ 默认 proxy + 内建私网直连。
func BenchmarkDecide(b *testing.B) {
	rules := &Rules{Rules: []Rule{
		{Action: Direct, Match: []string{"localhost", "*.internal.example.com", "10.0.0.0/8", "192.168.0.0/16", "1.2.3.4"}},
		{Action: Proxy, Match: []string{"*.google.com", "*.github.com"}},
	}}
	e, err := NewEngine(rules, Options{Default: Proxy, PrivateDirect: true})
	if err != nil {
		b.Fatalf("NewEngine: %v", err)
	}

	cases := []struct {
		name string
		host string
		want Action
	}{
		{"direct-rule", "api.internal.example.com", Direct},
		{"proxy-rule", "api.github.com", Proxy},
		{"private-direct", "192.168.1.10", Direct},
		{"default", "example.org", Proxy},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if got := e.Decide(tc.host); got != tc.want {
					b.Fatalf("Decide(%q) = %v, want %v", tc.host, got, tc.want)
				}
			}
		})
	}
}
