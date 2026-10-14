package httpproxy

import (
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/throttle"
)

// TestServerAuthFailureBackoffPerIP 验证认证失败按 IP 指数退避：连续失败
// 延迟增长（有界睡眠在 407 之前），认证成功后重置。
func TestServerAuthFailureBackoffPerIP(t *testing.T) {
	echoAddr := startEcho(t)
	store, err := auth.NewStore([]auth.User{{Username: "alice", Password: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Auth:   store,
		Dialer: echoDialer(t),
		// 短 base 便于测试：首次失败 ~50ms，第二次 ~100ms。
		Throttle: throttle.NewIPThrottle(50*time.Millisecond, 500*time.Millisecond, 1024),
	}
	proxyAddr := startProxy(t, srv)

	deny := func() time.Duration {
		start := time.Now()
		resp := rawConnect(t, proxyAddr, echoAddr, "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:wrong")))
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("status = %d, want 407", resp.StatusCode)
		}
		return time.Since(start)
	}

	e1 := deny()
	e2 := deny()
	// 首次失败至少延迟 base（407 语义不变，仅时序后移）。
	if e1 < 40*time.Millisecond {
		t.Fatalf("first denial took %v, want >= base(~50ms)", e1)
	}
	// 连续失败：延迟指数增长。
	if e2-e1 < 40*time.Millisecond {
		t.Fatalf("second denial grew only %v (e1=%v e2=%v), want exponential growth", e2-e1, e1, e2)
	}

	// 认证成功：清除记录，退避从头计。
	if resp := rawConnect(t, proxyAddr, echoAddr, "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:secret"))); resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated connect status = %d, want 200", resp.StatusCode)
	}

	e3 := deny()
	if e3 >= e2 {
		t.Fatalf("denial after success took %v (e2=%v), want reset to base", e3, e2)
	}
}
