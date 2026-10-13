package core

import (
	"testing"
	"time"
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

// TestRouteActionString 锁定动作的观测写法：metrics 标签与日志的 route
// 字段从 Route.Action 派生，取值漂移即破坏 /metrics 兼容。
func TestRouteActionString(t *testing.T) {
	cases := map[RouteAction]string{
		RouteDirect: "direct",
		RouteProxy:  "proxy",
		RouteReject: "reject",
	}
	for action, want := range cases {
		if got := action.String(); got != want {
			t.Fatalf("RouteAction(%d).String() = %q, want %q", action, got, want)
		}
	}
}

// TestTelemetryVocabulary 锁定遥测标签词汇：metrics 适配层与 /metrics 的
// 消费方都依赖这些取值，漂移即破坏兼容（词汇随 Telemetry 契约归 core）。
func TestTelemetryVocabulary(t *testing.T) {
	cases := map[string]string{
		ProtoHTTP:      "http",
		ProtoSOCKS5:    "socks5",
		ProtoDNS:       "dns",
		ProtoTunnel:    "tunnel",
		ResultOK:       "ok",
		ResultDenied:   "denied",
		ResultDialFail: "dial_fail",
		ResultError:    "error",
		ResultOverload: "overloaded",
	}
	for got, want := range cases {
		if got != want {
			t.Fatalf("telemetry vocabulary constant = %q, want %q", got, want)
		}
	}
}

// TestNopTelemetry 锁定 Nop 缺省实现：非 nil 且全部方法可安全空调用，
// 组件 Options 缺省接入后测试无需构造任何观测后端。
func TestNopTelemetry(t *testing.T) {
	if NopTelemetry == nil {
		t.Fatal("NopTelemetry must not be nil")
	}
	NopTelemetry.ConnOpened(ProtoSOCKS5)
	NopTelemetry.ConnRejected(ProtoTunnel, ResultOverload)
	NopTelemetry.ConnDone(ConnAttrs{
		Proto:     ProtoHTTP,
		Target:    Target{Host: "example.com", Port: 443},
		Route:     Route{Action: RouteProxy, Label: "node1:443"},
		Result:    ResultOK,
		Duration:  time.Second,
		BytesUp:   11,
		BytesDown: 22,
	})
}
