package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/connpool"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/dnsgw"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// clientProtos 是 clientapp 组装根会传入的入站集合（三入站全启用）。
func clientProtos() []string {
	return []string{core.ProtoHTTP, core.ProtoSOCKS5, core.ProtoTunnel}
}

// attrsOf 是构造 ConnAttrs 的便捷函数（零值补默认结果）。
func attrsOf(proto string, route core.Route, result string, d time.Duration) core.ConnAttrs {
	return core.ConnAttrs{Proto: proto, Route: route, Result: result, Duration: d}
}

func TestConnDoneRequestsAndGauge(t *testing.T) {
	m := New(clientProtos())
	// active 口径：active = ConnOpened − (ConnDone+ConnRejected)。
	m.ConnOpened(core.ProtoHTTP)
	m.ConnOpened(core.ProtoHTTP)
	if got := testutil.ToFloat64(m.active.WithLabelValues(core.ProtoHTTP)); got != 2 {
		t.Fatalf("active_connections{http} = %v, want 2", got)
	}
	m.ConnDone(attrsOf(core.ProtoHTTP, core.Route{Action: core.RouteProxy}, core.ResultOK, 25*time.Millisecond))
	m.ConnDone(attrsOf(core.ProtoHTTP, core.Route{Action: core.RouteProxy}, core.ResultOK, 75*time.Millisecond))
	m.ConnOpened(core.ProtoSOCKS5)
	m.ConnDone(attrsOf(core.ProtoSOCKS5, core.Route{Action: core.RouteDirect}, core.ResultDialFail, 5*time.Millisecond))
	m.ConnOpened(core.ProtoSOCKS5)
	m.ConnRejected(core.ProtoSOCKS5, core.ResultOverload)

	proxy := core.RouteProxy.String()
	direct := core.RouteDirect.String()
	if got := testutil.ToFloat64(m.requests.WithLabelValues(core.ProtoHTTP, proxy, core.ResultOK)); got != 2 {
		t.Fatalf("requests_total{http,proxy,ok} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.requests.WithLabelValues(core.ProtoSOCKS5, direct, core.ResultDialFail)); got != 1 {
		t.Fatalf("requests_total{socks5,direct,dial_fail} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.active.WithLabelValues(core.ProtoHTTP)); got != 0 {
		t.Fatalf("active_connections{http} after 2×ConnDone = %v, want 0", got)
	}
	if got := testutil.ToFloat64(m.active.WithLabelValues(core.ProtoSOCKS5)); got != 0 {
		t.Fatalf("active_connections{socks5} after ConnOpened+ConnRejected = %v, want 0", got)
	}
	if got := testutil.ToFloat64(m.rejected.WithLabelValues(core.ProtoSOCKS5)); got != 1 {
		t.Fatalf("connections_rejected_total{socks5} = %v, want 1", got)
	}
}

// TestConnRejectedCounter 钉住拒绝口径：拒绝计入 connections_rejected_total
// （标签 proto；拒绝原因不扩维），且不产生 requests_total 记录——未发生
// 拨号的终态不会把零值 Route 伪造成真实路径。
func TestConnRejectedCounter(t *testing.T) {
	m := New(clientProtos())
	m.ConnOpened(core.ProtoSOCKS5)
	m.ConnRejected(core.ProtoSOCKS5, core.ResultDenied)

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `connections_rejected_total{proto="socks5"} 1`) {
		t.Fatalf("/metrics missing rejected counter:\n%s", body)
	}
	if strings.Contains(body, `requests_total{proto="socks5"`) && !strings.Contains(body, `requests_total{proto="socks5",result="error",route="direct"} 0`) {
		t.Fatalf("rejected connections must not be counted as requests:\n%s", body)
	}
}

// TestConnDoneRouteRejectShape 钉住路由拒绝的观测形状：Route 是权威判定，
// 计入 requests_total{route="reject", result="denied"}。
func TestConnDoneRouteRejectShape(t *testing.T) {
	m := New(clientProtos())
	m.ConnDone(attrsOf(core.ProtoHTTP, core.Route{Action: core.RouteReject}, core.ResultDenied, time.Millisecond))

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	want := `requests_total{proto="http",result="denied",route="reject"} 1`
	if !strings.Contains(body, want) {
		t.Fatalf("/metrics missing %q:\n%s", want, body)
	}
}

// TestConnDonePoolLabelShape 钉住“池选择未定”的观测形状（上游连接复用等
// 单条请求路径不可判定的场景）：入站以 Route{Proxy, "pool"} 标记，
// route 维度记 "pool"，绝不落入 direct / proxy 的虚假计数。
func TestConnDonePoolLabelShape(t *testing.T) {
	m := New(clientProtos())
	m.ConnDone(attrsOf(core.ProtoHTTP, core.Route{Action: core.RouteProxy, Label: "pool"}, core.ResultOK, time.Millisecond))

	if RouteLabel(core.Route{}) != "direct" {
		t.Fatal("zero Route (fresh direct dial) must be observed as direct")
	}
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	want := `requests_total{proto="http",result="ok",route="pool"} 1`
	if !strings.Contains(body, want) {
		t.Fatalf("/metrics missing %q:\n%s", want, body)
	}
	if got := testutil.ToFloat64(m.requests.WithLabelValues(core.ProtoHTTP, "direct", core.ResultOK)); got != 0 {
		t.Fatalf("undetermined route leaked into direct: %v", got)
	}
	if got := testutil.ToFloat64(m.requests.WithLabelValues(core.ProtoHTTP, "proxy", core.ResultOK)); got != 0 {
		t.Fatalf("undetermined route leaked into proxy: %v", got)
	}
}

func TestHandlerExposesRequiredMetricNames(t *testing.T) {
	m := New(clientProtos())
	m.ConnDone(attrsOf(core.ProtoTunnel, core.Route{Action: core.RouteDirect}, core.ResultOK, 10*time.Millisecond))
	m.ConnOpened(core.ProtoTunnel)
	defer m.ConnDone(attrsOf(core.ProtoTunnel, core.Route{Action: core.RouteDirect}, core.ResultOK, time.Millisecond))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	m.Handler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, name := range []string{"requests_total", "request_duration_seconds", "active_connections"} {
		if !strings.Contains(body, name) {
			t.Fatalf("/metrics output missing %q:\n%s", name, body)
		}
	}
	if !strings.Contains(body, "text/plain") && !strings.Contains(rec.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("unexpected content type: %q", rec.Header().Get("Content-Type"))
	}
}

func TestHandlerExposesNamesWithoutTraffic(t *testing.T) {
	// 无任何流量时也应看到三个核心指标名（预初始化）。
	rec := httptest.NewRecorder()
	New(clientProtos()).Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	for _, name := range []string{"requests_total", "request_duration_seconds", "active_connections"} {
		if !strings.Contains(body, name) {
			t.Fatalf("zero-traffic /metrics missing %q", name)
		}
	}
}

func TestNilMetricsSafe(t *testing.T) {
	var m *Metrics
	m.ConnDone(attrsOf(core.ProtoHTTP, core.Route{Action: core.RouteDirect}, core.ResultOK, time.Second))
	m.ConnOpened(core.ProtoHTTP)
	m.ConnRejected(core.ProtoHTTP, core.ResultDenied)
	m.QueryDone(core.RouteDirect.String(), core.ResultOK, time.Second)
	m.ProbeResult("n1", true)
	m.HealthChanged("n1", false)
	if m.Handler() == nil {
		t.Fatal("nil metrics Handler should not be nil")
	}
	if m.ActiveByProto() != nil {
		t.Fatal("nil metrics ActiveByProto should return nil")
	}
}

func TestProbeResultMetrics(t *testing.T) {
	m := New(clientProtos())
	m.ProbeResult("n1", true)
	m.ProbeResult("n1", false)
	m.ProbeResult("n1", false)
	m.HealthChanged("n1", false)
	m.HealthChanged("n2", true)

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		`upstream_health_probes_total{node="n1",result="success"} 1`,
		`upstream_health_probes_total{node="n1",result="failure"} 2`,
		`upstream_healthy{node="n1"} 0`,
		`upstream_healthy{node="n2"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/metrics missing %q:\n%s", want, body)
		}
	}
}

func TestActiveByProtoSnapshot(t *testing.T) {
	m := New(clientProtos())
	m.ConnOpened(core.ProtoHTTP)
	m.ConnOpened(core.ProtoHTTP)
	m.ConnOpened(core.ProtoSOCKS5)

	snap := m.ActiveByProto()
	if snap[core.ProtoHTTP] != 2 {
		t.Fatalf("http = %d, want 2", snap[core.ProtoHTTP])
	}
	if snap[core.ProtoSOCKS5] != 1 {
		t.Fatalf("socks5 = %d, want 1", snap[core.ProtoSOCKS5])
	}
	if snap[core.ProtoTunnel] != 0 {
		t.Fatalf("tunnel = %d, want 0", snap[core.ProtoTunnel])
	}

	m.ConnDone(attrsOf(core.ProtoHTTP, core.Route{Action: core.RouteProxy}, core.ResultOK, time.Millisecond))
	if got := m.ActiveByProto()[core.ProtoHTTP]; got != 1 {
		t.Fatalf("after done http = %d, want 1", got)
	}
}

// TestQueryDoneRoutes 钉住 DNS 查询口径：direct/proxy 记查询与耗时，
// 非法查询路由维度留空且不计耗时。
func TestQueryDoneRoutes(t *testing.T) {
	m := New([]string{core.ProtoDNS})
	m.QueryDone(core.RouteProxy.String(), core.ResultOK, 10*time.Millisecond)
	m.QueryDone(core.RouteDirect.String(), core.ResultOK, 20*time.Millisecond)
	m.QueryDone("", dnsgw.ResultInvalid, 5*time.Millisecond)
	// UDP 查询闸超限丢弃：route 留空、result=overloaded。
	m.QueryDone("", core.ResultOverload, 0)

	if got := testutil.ToFloat64(m.dnsQueries.WithLabelValues(core.RouteProxy.String(), core.ResultOK)); got != 1 {
		t.Fatalf("dns_queries_total{proxy,ok} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.dnsQueries.WithLabelValues("", dnsgw.ResultInvalid)); got != 1 {
		t.Fatalf("dns_queries_total{\"\",invalid} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.dnsQueries.WithLabelValues("", core.ResultOverload)); got != 1 {
		t.Fatalf("dns_queries_total{\"\",overloaded} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.dnsQueries.WithLabelValues("", core.ResultError)); got != 0 {
		t.Fatalf("dns_queries_total{\"\",error} = %v, want 0（preInitialize 预建序列不得被污染）", got)
	}
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `dns_query_duration_seconds_sum{route="proxy"}`) {
		t.Fatalf("/metrics missing proxy dns duration:\n%s", body)
	}
	if strings.Contains(body, `dns_query_duration_seconds_sum{route=""}`) {
		t.Fatalf("invalid queries must not be timed:\n%s", body)
	}
	// preInitialize 预建 reject/denied 精确序列（恒成对出现，不全叉积），
	// 未发生拒绝时值保持 0，启动后 /metrics 无序列空洞。
	if !strings.Contains(body, `dns_queries_total{result="denied",route="reject"} 0`) {
		t.Fatalf("/metrics missing preinitialized reject/denied series:\n%s", body)
	}
}

func TestPoolMetrics(t *testing.T) {
	m := New(clientProtos())
	m.ClaimResult("n1", connpool.ClaimHit)
	m.ClaimResult("n1", connpool.ClaimHit)
	m.ClaimResult("n1", connpool.ClaimMiss)
	m.ClaimResult("n2", connpool.ClaimStale)
	m.IdleSet("n1", 2)
	m.WarmFailed("n2")

	if got := testutil.ToFloat64(m.poolClaims.WithLabelValues("n1", connpool.ClaimHit)); got != 2 {
		t.Fatalf("claims{n1,hit} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.poolClaims.WithLabelValues("n1", connpool.ClaimMiss)); got != 1 {
		t.Fatalf("claims{n1,miss} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.poolClaims.WithLabelValues("n2", connpool.ClaimStale)); got != 1 {
		t.Fatalf("claims{n2,stale} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.poolIdle.WithLabelValues("n1")); got != 2 {
		t.Fatalf("idle{n1} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.poolWarmFails.WithLabelValues("n2")); got != 1 {
		t.Fatalf("warm_failures{n2} = %v, want 1", got)
	}

	// nil 接收者不应 panic。
	var nilMetrics *Metrics
	nilMetrics.ClaimResult("n1", connpool.ClaimHit)
	nilMetrics.IdleSet("n1", 0)
	nilMetrics.WarmFailed("n1")
}
