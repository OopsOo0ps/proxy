package routing

import (
	"strings"
	"testing"

	"github.com/OopsOo0ps/proxy/internal/core"
)

func mustEngine(t *testing.T, rules *Rules, opts Options) *Engine {
	t.Helper()
	e, err := NewEngine(rules, opts)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

// directRules 构造一组覆盖全部条目形态的规则（纯结构；规则文档解析归 config）。
func directRules() *Rules {
	return &Rules{Rules: []Rule{
		{Action: core.RouteDirect, Match: []string{
			"example.cn", "*.corp.example.com", "10.0.0.0/8", "192.168.1.1", "2001:db8::/32", "localhost",
		}},
		{Action: core.RouteProxy, Match: []string{"*.blocked.example.com"}},
	}}
}

func TestDecideMatching(t *testing.T) {
	e := mustEngine(t, directRules(), Options{Default: core.RouteProxy})
	cases := map[string]core.RouteAction{
		"example.cn":              core.RouteDirect, // 精确域名
		"www.example.cn":          core.RouteProxy,  // 精确域名不匹配子域
		"www.corp.example.com":    core.RouteDirect, // 通配子域
		"a.b.corp.example.com":    core.RouteDirect, // 多级子域
		"corp.example.com":        core.RouteProxy,  // 通配不匹配裸域
		"xcorp.example.com":       core.RouteProxy,  // 后缀必须按标签边界
		"10.1.2.3":                core.RouteDirect, // CIDR 内
		"11.1.2.3":                core.RouteProxy,  // CIDR 外
		"192.168.1.1":             core.RouteDirect, // 精确 IP
		"192.168.1.2":             core.RouteProxy,
		"2001:db8::1":             core.RouteDirect, // IPv6 CIDR
		"2001:db9::1":             core.RouteProxy,
		"localhost":               core.RouteDirect,
		"www.blocked.example.com": core.RouteProxy, // 命中 proxy 规则
		"other.example.com":       core.RouteProxy, // 默认动作
	}
	for host, want := range cases {
		if got := e.Decide(host); got != want {
			t.Errorf("Decide(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestDecideNormalization(t *testing.T) {
	e := mustEngine(t, directRules(), Options{Default: core.RouteProxy})
	for _, host := range []string{"EXAMPLE.CN", "example.cn.", " Example.CN "} {
		if got := e.Decide(host); got != core.RouteDirect {
			t.Errorf("Decide(%q) = %v, want direct", host, got)
		}
	}
	if got := e.Decide(""); got != core.RouteProxy {
		t.Errorf("Decide(empty) = %v, want default proxy", got)
	}
}

func TestDecideFirstMatchWins(t *testing.T) {
	rules := &Rules{Rules: []Rule{
		{Action: core.RouteProxy, Match: []string{"*.example.com"}},
		{Action: core.RouteDirect, Match: []string{"*.example.com"}},
	}}
	e := mustEngine(t, rules, Options{Default: core.RouteDirect})
	if got := e.Decide("a.example.com"); got != core.RouteProxy {
		t.Fatalf("first matching rule should win, got %v", got)
	}
}

func TestRulesDefaultOverridesOptions(t *testing.T) {
	def := core.RouteDirect
	rules := &Rules{
		Default: &def,
		Rules:   []Rule{{Action: core.RouteProxy, Match: []string{"*.example.com"}}},
	}
	e := mustEngine(t, rules, Options{Default: core.RouteProxy})
	if got := e.Decide("unmatched.host"); got != core.RouteDirect {
		t.Fatalf("rules default should override options default, got %v", got)
	}
	if got := e.Decide("a.example.com"); got != core.RouteProxy {
		t.Fatalf("rule should still apply, got %v", got)
	}
}

func TestPrivateDirectBuiltin(t *testing.T) {
	e := mustEngine(t, nil, Options{Default: core.RouteProxy, PrivateDirect: true})
	for _, host := range []string{
		"127.0.0.1", "10.0.0.5", "192.168.31.7", "172.16.0.1",
		"::1", "fe80::1", "fc00::1", "0.0.0.0", "224.0.0.1", "localhost",
	} {
		if got := e.Decide(host); got != core.RouteDirect {
			t.Errorf("Decide(%q) = %v, want direct (private)", host, got)
		}
	}
	if got := e.Decide("8.8.8.8"); got != core.RouteProxy {
		t.Errorf("public IP should follow default, got %v", got)
	}
}

func TestPrivateDirectDisabled(t *testing.T) {
	e := mustEngine(t, nil, Options{Default: core.RouteProxy, PrivateDirect: false})
	if got := e.Decide("127.0.0.1"); got != core.RouteProxy {
		t.Fatalf("Decide(127.0.0.1) = %v, want proxy when private_direct disabled", got)
	}
}

func TestNewEngineRejectsBadMatcher(t *testing.T) {
	rules := &Rules{Rules: []Rule{{Action: core.RouteDirect, Match: []string{"10.0.0.0/33"}}}}
	if _, err := NewEngine(rules, Options{}); err == nil {
		t.Fatal("expected compile error for bad CIDR")
	}
}

func TestCheckEntry(t *testing.T) {
	for _, bad := range []string{"", "a b", "*.", "10.0.0.0/33", "ho*st", "a..b"} {
		if err := CheckEntry(bad); err == nil {
			t.Errorf("CheckEntry(%q) should fail", bad)
		}
	}
	for _, good := range []string{"example.com", "*.example.com", "10.0.0.0/8", "2001:db8::/32", "1.2.3.4"} {
		if err := CheckEntry(good); err != nil {
			t.Errorf("CheckEntry(%q): %v", good, err)
		}
	}
}

func TestParseAction(t *testing.T) {
	if a, err := ParseAction("Direct"); err != nil || a != core.RouteDirect {
		t.Fatalf("ParseAction(Direct) = (%v, %v)", a, err)
	}
	if a, err := ParseAction("proxy"); err != nil || a != core.RouteProxy {
		t.Fatalf("ParseAction(proxy) = (%v, %v)", a, err)
	}
	if _, err := ParseAction("other"); err == nil {
		t.Fatal("expected error for unknown action")
	}
	if !strings.Contains(core.RouteDirect.String(), "direct") || !strings.Contains(core.RouteProxy.String(), "proxy") {
		t.Fatal("action String() mismatch")
	}
	if core.RouteReject.String() != "reject" {
		t.Fatalf("RouteReject.String() = %q, want reject", core.RouteReject.String())
	}
}

// BenchmarkDecide 测量分流决策热路径。规则集模拟常见形态：
// 一组直连规则（域名 / 通配 / 网段）+ 默认 proxy + 内建私网直连。
func BenchmarkDecide(b *testing.B) {
	rules := &Rules{Rules: []Rule{
		{Action: core.RouteDirect, Match: []string{"localhost", "*.internal.example.com", "10.0.0.0/8", "192.168.0.0/16", "1.2.3.4"}},
		{Action: core.RouteProxy, Match: []string{"*.google.com", "*.github.com"}},
	}}
	e, err := NewEngine(rules, Options{Default: core.RouteProxy, PrivateDirect: true})
	if err != nil {
		b.Fatalf("NewEngine: %v", err)
	}

	cases := []struct {
		name string
		host string
		want core.RouteAction
	}{
		{"direct-rule", "api.internal.example.com", core.RouteDirect},
		{"proxy-rule", "api.github.com", core.RouteProxy},
		{"private-direct", "192.168.1.10", core.RouteDirect},
		{"default", "example.org", core.RouteProxy},
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
