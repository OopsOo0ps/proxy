package socks5

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/throttle"
)

// TestServerAuthFailureBackoffPerIP 验证认证失败按 IP 指数退避：连续失败
// 延迟增长（有界睡眠在拒绝响应之前），认证成功后重置。
func TestServerAuthFailureBackoffPerIP(t *testing.T) {
	store, err := auth.NewStore([]auth.User{{Username: "alice", Password: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	host := "127.0.0.1"
	echoAddr := startEcho(t)
	_, portStr, _ := net.SplitHostPort(echoAddr)
	port := mustPort(t, portStr)

	srv := &Server{
		Auth: store,
		Dialer: &stubDialer{dial: func(ctx context.Context, t core.Target) (net.Conn, error) {
			return net.Dial("tcp", t.String())
		}},
		// 短 base 便于测试：首次失败 ~50ms，第二次 ~100ms。
		Throttle: throttle.NewIPThrottle(50*time.Millisecond, 500*time.Millisecond, 1024),
	}
	proxyAddr := startServer(t, srv)

	deny := func() time.Duration {
		start := time.Now()
		conn, _, err := socks5Connect(t, proxyAddr, "alice", "wrong", host, port)
		if err != nil && !errors.Is(err, errAuthFailed) {
			t.Fatalf("expected auth failure, got %v", err)
		}
		_ = conn.Close()
		return time.Since(start)
	}

	e1 := deny()
	e2 := deny()
	// 首次失败至少延迟 base（协议拒绝语义不变，仅时序后移）。
	if e1 < 40*time.Millisecond {
		t.Fatalf("first denial took %v, want >= base(~50ms)", e1)
	}
	// 连续失败：延迟指数增长。
	if e2-e1 < 40*time.Millisecond {
		t.Fatalf("second denial grew only %v (e1=%v e2=%v), want exponential growth", e2-e1, e1, e2)
	}

	// 认证成功：清除记录，退避从头计。
	conn, rep, err := socks5Connect(t, proxyAddr, "alice", "secret", host, port)
	if err != nil {
		t.Fatalf("connect with auth: %v", err)
	}
	_ = conn.Close()
	if rep != ReplySuccess {
		t.Fatalf("reply = %#x, want success", rep)
	}

	e3 := deny()
	if e3 >= e2 {
		t.Fatalf("denial after success took %v (e2=%v), want reset to base", e3, e2)
	}
}
