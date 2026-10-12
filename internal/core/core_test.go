package core

import (
	"testing"
	"time"

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

// TestTelemetryVocabulary 锁定遥测标签词汇：metrics 适配层与 /metrics 的
// 消费方都依赖这些取值，漂移即破坏兼容（词汇随 Telemetry 契约归 core）。
func TestTelemetryVocabulary(t *testing.T) {
	cases := map[string]string{
		ProtoHTTP:      "http",
		ProtoSOCKS5:    "socks5",
		ProtoTunnel:    "tunnel",
		RouteDirect:    "direct",
		RouteProxy:     "proxy",
		RouteNone:      "none",
		ResultOK:       "ok",
		ResultAuthFail: "auth_fail",
		ResultDialFail: "dial_fail",
		ResultError:    "error",
	}
	for got, want := range cases {
		if got != want {
			t.Fatalf("telemetry vocabulary constant = %q, want %q", got, want)
		}
	}
	// route 词汇与 routing.Action 的字符串写法保持一致（请求指标按
	// Action.String() 记 route 标签）。
	if got, want := routing.Direct.String(), RouteDirect; got != want {
		t.Fatalf("routing.Direct.String() = %q, want %q", got, want)
	}
	if got, want := routing.Proxy.String(), RouteProxy; got != want {
		t.Fatalf("routing.Proxy.String() = %q, want %q", got, want)
	}
}

// TestNopTelemetry 锁定 Nop 缺省实现：非 nil 且全部方法可安全空调用，
// 组件 Options 缺省接入后测试无需构造任何观测后端。
func TestNopTelemetry(t *testing.T) {
	if NopTelemetry == nil {
		t.Fatal("NopTelemetry must not be nil")
	}
	NopTelemetry.RequestDone(ProtoHTTP, RouteProxy, ResultOK, time.Second)
	NopTelemetry.ConnOpened(ProtoSOCKS5)
	NopTelemetry.ConnClosed(ProtoTunnel)
	NopTelemetry.ConnRejected(ProtoTunnel)
}
