package core

import (
	"testing"

	"github.com/OopsOo0ps/proxy/internal/routing"
)

// TestTargetString 锁定 Target 的 host:port 形状：IPv6 字面量自动加方括号。
func TestTargetString(t *testing.T) {
	cases := []struct {
		target Target
		want   string
	}{
		{Target{Host: "example.com", Port: 443}, "example.com:443"},
		{Target{Host: "127.0.0.1", Port: 8080}, "127.0.0.1:8080"},
		{Target{Host: "::1", Port: 8443}, "[::1]:8443"},
	}
	for _, tc := range cases {
		if got := tc.target.String(); got != tc.want {
			t.Fatalf("String(%v) = %q, want %q", tc.target, got, tc.want)
		}
	}
}

// TestRouteLabel 锁定 upstream 日志词汇：命中节点地址优先，
// 未知名返回 "pool"（连接复用场景），直连返回 "direct"。
func TestRouteLabel(t *testing.T) {
	cases := []struct {
		route Route
		want  string
	}{
		{Route{Action: routing.Direct}, "direct"},
		{Route{Action: routing.Proxy, Upstream: ""}, "pool"},
		{Route{Action: routing.Proxy, Upstream: "node1.example.com:443"}, "node1.example.com:443"},
		// 地址优先于动作：直连时 Upstream 恒为空，此处仅锁定实现语义。
		{Route{Action: routing.Direct, Upstream: "node2.example.com:443"}, "node2.example.com:443"},
	}
	for _, tc := range cases {
		if got := tc.route.Label(); got != tc.want {
			t.Fatalf("Label(%+v) = %q, want %q", tc.route, got, tc.want)
		}
	}
}
