package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestObserveAndConnGauge(t *testing.T) {
	m := New()
	m.Observe(ProtoHTTP, RouteProxy, ResultOK, 25*time.Millisecond)
	m.Observe(ProtoHTTP, RouteProxy, ResultOK, 75*time.Millisecond)
	m.Observe(ProtoSOCKS5, RouteDirect, ResultDialFail, 5*time.Millisecond)

	if got := testutil.ToFloat64(m.requests.WithLabelValues(ProtoHTTP, RouteProxy, ResultOK)); got != 2 {
		t.Fatalf("requests_total{http,proxy,ok} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.requests.WithLabelValues(ProtoSOCKS5, RouteDirect, ResultDialFail)); got != 1 {
		t.Fatalf("requests_total{socks5,direct,dial_fail} = %v, want 1", got)
	}

	m.ConnOpened(ProtoHTTP)
	m.ConnOpened(ProtoHTTP)
	if got := testutil.ToFloat64(m.active.WithLabelValues(ProtoHTTP)); got != 2 {
		t.Fatalf("active_connections{http} = %v, want 2", got)
	}
	m.ConnClosed(ProtoHTTP)
	if got := testutil.ToFloat64(m.active.WithLabelValues(ProtoHTTP)); got != 1 {
		t.Fatalf("active_connections{http} = %v, want 1", got)
	}

}

func TestHandlerExposesRequiredMetricNames(t *testing.T) {
	m := New()
	m.Observe(ProtoTunnel, RouteDirect, ResultOK, 10*time.Millisecond)
	m.ConnOpened(ProtoTunnel)
	defer m.ConnClosed(ProtoTunnel)

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
	m.Observe(ProtoHTTP, RouteDirect, ResultOK, time.Second)
	m.ConnOpened(ProtoHTTP)
	m.ConnClosed(ProtoHTTP)
	m.HealthProbe("n1", true)
	m.SetUpstreamHealthy("n1", false)
	if m.Handler() == nil {
		t.Fatal("nil metrics Handler should not be nil")
	}
	if m.ActiveByProto() != nil {
		t.Fatal("nil metrics ActiveByProto should return nil")
	}
}

func TestHealthProbeMetrics(t *testing.T) {
	m := New()
	m.HealthProbe("n1", true)
	m.HealthProbe("n1", false)
	m.HealthProbe("n1", false)
	m.SetUpstreamHealthy("n1", false)
	m.SetUpstreamHealthy("n2", true)

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
	m.ConnOpened(ProtoHTTP)
	m.ConnOpened(ProtoHTTP)
	m.ConnOpened(ProtoSOCKS5)

	snap := m.ActiveByProto()
	if snap[ProtoHTTP] != 2 {
		t.Fatalf("http = %d, want 2", snap[ProtoHTTP])
	}
	if snap[ProtoSOCKS5] != 1 {
		t.Fatalf("socks5 = %d, want 1", snap[ProtoSOCKS5])
	}
	if snap[ProtoTunnel] != 0 {
		t.Fatalf("tunnel = %d, want 0", snap[ProtoTunnel])
	}

	m.ConnClosed(ProtoHTTP)
	if got := m.ActiveByProto()[ProtoHTTP]; got != 1 {
		t.Fatalf("after close http = %d, want 1", got)
	}
}

func TestPoolMetrics(t *testing.T) {
	m := New()
	m.PoolClaim(PoolClaimHit, "n1")
	m.PoolClaim(PoolClaimHit, "n1")
	m.PoolClaim(PoolClaimMiss, "n1")
	m.PoolClaim(PoolClaimStale, "n2")
	m.SetPoolIdle("n1", 2)
	m.PoolWarmFailed("n2")

	if got := testutil.ToFloat64(m.poolClaims.WithLabelValues("n1", PoolClaimHit)); got != 2 {
		t.Fatalf("claims{n1,hit} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.poolClaims.WithLabelValues("n1", PoolClaimMiss)); got != 1 {
		t.Fatalf("claims{n1,miss} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.poolClaims.WithLabelValues("n2", PoolClaimStale)); got != 1 {
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
	nilMetrics.PoolClaim(PoolClaimHit, "n1")
	nilMetrics.SetPoolIdle("n1", 0)
	nilMetrics.PoolWarmFailed("n1")
}
