package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/connpool"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRequestDoneAndConnGauge(t *testing.T) {
	m := New()
	m.RequestDone(core.ProtoHTTP, core.RouteProxy, core.ResultOK, 25*time.Millisecond)
	m.RequestDone(core.ProtoHTTP, core.RouteProxy, core.ResultOK, 75*time.Millisecond)
	m.RequestDone(core.ProtoSOCKS5, core.RouteDirect, core.ResultDialFail, 5*time.Millisecond)

	if got := testutil.ToFloat64(m.requests.WithLabelValues(core.ProtoHTTP, core.RouteProxy, core.ResultOK)); got != 2 {
		t.Fatalf("requests_total{http,proxy,ok} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.requests.WithLabelValues(core.ProtoSOCKS5, core.RouteDirect, core.ResultDialFail)); got != 1 {
		t.Fatalf("requests_total{socks5,direct,dial_fail} = %v, want 1", got)
	}

	m.ConnOpened(core.ProtoHTTP)
	m.ConnOpened(core.ProtoHTTP)
	if got := testutil.ToFloat64(m.active.WithLabelValues(core.ProtoHTTP)); got != 2 {
		t.Fatalf("active_connections{http} = %v, want 2", got)
	}
	m.ConnClosed(core.ProtoHTTP)
	if got := testutil.ToFloat64(m.active.WithLabelValues(core.ProtoHTTP)); got != 1 {
		t.Fatalf("active_connections{http} = %v, want 1", got)
	}

}

func TestHandlerExposesRequiredMetricNames(t *testing.T) {
	m := New()
	m.RequestDone(core.ProtoTunnel, core.RouteDirect, core.ResultOK, 10*time.Millisecond)
	m.ConnOpened(core.ProtoTunnel)
	defer m.ConnClosed(core.ProtoTunnel)

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
	New().Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	for _, name := range []string{"requests_total", "request_duration_seconds", "active_connections"} {
		if !strings.Contains(body, name) {
			t.Fatalf("zero-traffic /metrics missing %q", name)
		}
	}
}

func TestNilMetricsSafe(t *testing.T) {
	var m *Metrics
	m.RequestDone(core.ProtoHTTP, core.RouteDirect, core.ResultOK, time.Second)
	m.ConnOpened(core.ProtoHTTP)
	m.ConnClosed(core.ProtoHTTP)
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
	m := New()
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
	m := New()
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

	m.ConnClosed(core.ProtoHTTP)
	if got := m.ActiveByProto()[core.ProtoHTTP]; got != 1 {
		t.Fatalf("after close http = %d, want 1", got)
	}
}

func TestPoolMetrics(t *testing.T) {
	m := New()
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
