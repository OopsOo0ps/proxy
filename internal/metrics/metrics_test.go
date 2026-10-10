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
	if m.Handler() == nil {
		t.Fatal("nil metrics Handler should not be nil")
	}
}
