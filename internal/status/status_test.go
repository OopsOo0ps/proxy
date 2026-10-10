package status

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// decode 把响应体解码到 v。
func decode(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
}

func TestHealthOK(t *testing.T) {
	s := New(Options{Version: "v9.9.9", Start: time.Now().Add(-90 * time.Second)})
	rec := httptest.NewRecorder()
	s.Health().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}

	var resp healthResponse
	decode(t, rec, &resp)
	if resp.Status != "ok" {
		t.Fatalf("status field = %q, want ok", resp.Status)
	}
	if resp.Uptime < 90 || resp.Uptime > 91 {
		t.Fatalf("uptime = %v, want ~90 秒", resp.Uptime)
	}
	if resp.Reason != "" {
		t.Fatalf("reason = %q, want 空", resp.Reason)
	}
}

func TestHealthDependencyFailure(t *testing.T) {
	s := New(Options{
		Checks: []func() error{
			func() error { return nil },
			func() error { return errors.New("no healthy exit nodes available") },
		},
	})
	rec := httptest.NewRecorder()
	s.Health().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	var resp healthResponse
	decode(t, rec, &resp)
	if resp.Status != "unavailable" {
		t.Fatalf("status field = %q, want unavailable", resp.Status)
	}
	if resp.Reason != "no healthy exit nodes available" {
		t.Fatalf("reason = %q", resp.Reason)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	s := New(Options{})
	for _, h := range []struct {
		name    string
		handler http.Handler
	}{
		{"health", s.Health()},
		{"stats", s.Stats()},
	} {
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/"+h.name, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: status = %d, want 405", h.name, rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow != http.MethodGet {
			t.Fatalf("%s: Allow = %q, want GET", h.name, allow)
		}
	}
}

func TestStatsSnapshot(t *testing.T) {
	s := New(Options{
		Version: "v1.2.3",
		Start:   time.Now().Add(-5 * time.Second),
		Runtime: func() Runtime {
			return Runtime{
				Connections: Connections{HTTP: 2, SOCKS5: 1, Total: 3},
				Upstreams: []Upstream{
					{Addr: "node1.example.com:443", Healthy: true},
					{Addr: "node2.example.com:443", Healthy: false, Fails: 2, CooldownRemaining: 12.5, Removed: true, ProbeFails: 3},
				},
			}
		},
	})
	rec := httptest.NewRecorder()
	s.Stats().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp statsResponse
	decode(t, rec, &resp)
	if resp.Version != "v1.2.3" {
		t.Fatalf("version = %q", resp.Version)
	}
	if resp.Uptime < 5 || resp.Uptime > 6 {
		t.Fatalf("uptime = %v, want ~5 秒", resp.Uptime)
	}
	if resp.Connections.HTTP != 2 || resp.Connections.SOCKS5 != 1 || resp.Connections.Total != 3 {
		t.Fatalf("connections = %+v", resp.Connections)
	}
	if resp.Connections.Tunnel != 0 {
		t.Fatalf("tunnel = %d, want 0", resp.Connections.Tunnel)
	}
	if len(resp.Upstreams) != 2 {
		t.Fatalf("upstreams = %+v", resp.Upstreams)
	}
	if up := resp.Upstreams[1]; up.Healthy || up.Fails != 2 || up.CooldownRemaining != 12.5 || !up.Removed || up.ProbeFails != 3 {
		t.Fatalf("upstream[1] = %+v", up)
	}
	if resp.Memory.Goroutines <= 0 {
		t.Fatalf("goroutines = %d, want > 0", resp.Memory.Goroutines)
	}
	if resp.Memory.SysBytes == 0 {
		t.Fatal("sys_bytes 应为非零")
	}
}

func TestStatsOmitsUpstreamsWhenAbsent(t *testing.T) {
	// 服务端无节点池：不输出 upstreams 字段，connections 只有 total。
	s := New(Options{Version: "dev"})
	rec := httptest.NewRecorder()
	s.Stats().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))

	body := rec.Body.String()
	if strings.Contains(body, "upstreams") {
		t.Fatalf("无节点池时不应输出 upstreams：%s", body)
	}
	if !strings.Contains(body, `"total":0`) {
		t.Fatalf("connections.total 缺失：%s", body)
	}
}

func TestNilStatusReturnsNotFound(t *testing.T) {
	var s *Status
	for _, handler := range []http.Handler{s.Health(), s.Stats()} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("nil Status: status = %d, want 404", rec.Code)
		}
	}
}

func TestSecondsRounding(t *testing.T) {
	if got := Seconds(1500 * time.Millisecond); got != 1.5 {
		t.Fatalf("Seconds(1.5s) = %v, want 1.5", got)
	}
	if got := Seconds(1500*time.Millisecond + 400*time.Microsecond); got != 1.5 {
		t.Fatalf("毫秒以下应四舍五入：%v", got)
	}
}
