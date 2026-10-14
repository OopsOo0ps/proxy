package trojan

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/throttle"
)

// TestServerAuthFailureBackoffPerIP 验证隧道认证失败按 IP 指数退避：连续
// 失败延迟增长（有界睡眠在伪装页之前），认证成功后重置。
func TestServerAuthFailureBackoffPerIP(t *testing.T) {
	echoAddr := startEcho(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port, _ := strconv.ParseUint(portStr, 10, 16)

	store, err := auth.NewStore([]auth.User{{Username: "alice", Password: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Verifier: store,
		Dial: dialerOf(func(ctx context.Context, addr string) (net.Conn, error) {
			return net.Dial("tcp", addr)
		}),
		// 短 base 便于测试：首次失败 ~50ms，第二次 ~100ms。
		Throttle: throttle.NewIPThrottle(50*time.Millisecond, 500*time.Millisecond, 1024),
	}
	nodeAddr, clientTLS := startTLSServer(t, srv, 3*time.Second)

	// deny 发起一次错误口令的隧道请求，返回读到伪装页的耗时。
	deny := func() time.Duration {
		start := time.Now()
		conn, err := Dial(context.Background(), ClientConfig{
			ServerAddr: nodeAddr,
			Password:   "wrong-password",
			TLSConfig:  clientTLS,
		}, core.Target{Host: host, Port: uint16(port)})
		if err != nil {
			t.Fatalf("trojan.Dial: %v", err)
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadAll(conn); err != nil {
			t.Fatalf("read decoy: %v", err)
		}
		return time.Since(start)
	}

	e1 := deny()
	e2 := deny()
	// 首次失败至少延迟 base（伪装页语义不变，仅时序后移）。
	if e1 < 40*time.Millisecond {
		t.Fatalf("first denial took %v, want >= base(~50ms)", e1)
	}
	// 连续失败：延迟指数增长。
	if e2-e1 < 40*time.Millisecond {
		t.Fatalf("second denial grew only %v (e1=%v e2=%v), want exponential growth", e2-e1, e1, e2)
	}

	// 认证成功：清除记录，退避从头计。
	conn, err := Dial(context.Background(), ClientConfig{
		ServerAddr: nodeAddr,
		Password:   "secret",
		TLSConfig:  clientTLS,
	}, core.Target{Host: host, Port: uint16(port)})
	if err != nil {
		t.Fatalf("trojan.Dial with valid password: %v", err)
	}
	_ = conn.Close()

	e3 := deny()
	if e3 >= e2 {
		t.Fatalf("denial after success took %v (e2=%v), want reset to base", e3, e2)
	}
}
