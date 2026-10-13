package trojan

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/outbound"
)

// newTestTransport 启动回环 Trojan 服务端（自签证书 + 回显目标）并返回
// 与之配套的传输实例，钉住「传输构造时封闭协议参数、口令派生不出包」的契约。
func newTestTransport(t *testing.T) (*Transport, core.Target) {
	t.Helper()
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
	}
	nodeAddr, clientTLS := startTLSServer(t, srv, 3*time.Second)

	tr, err := NewTransport(ClientConfig{
		ServerAddr: nodeAddr,
		Password:   "secret",
		TLSConfig:  clientTLS,
	})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	return tr, core.Target{Host: host, Port: uint16(port)}
}

func TestNewTransportRejectsBadPassword(t *testing.T) {
	cases := []struct {
		name     string
		password string
	}{
		{"empty password", ""},
		{"lf password", "a\nb"},
		{"cr password", "a\rb"},
	}
	for _, tc := range cases {
		if _, err := NewTransport(ClientConfig{ServerAddr: "127.0.0.1:443", Password: tc.password}); err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
	}
}

// TestTransportConformance 把 Trojan 传输跑一遍 outbound 一致性验收
// （回环 TLS 服务端 + 回显目标；dial / prewarm-bind / probe 全部三项能力，
// 断言由 internal/outbound 统一持有：未来协议接入即跑同一套验收，
// 含 Discard 后 Bind 必须失败与取消 ctx 假成功识别等负例）。
func TestTransportConformance(t *testing.T) {
	tr, _ := newTestTransport(t)

	outbound.RunConformance(t, tr)
}

// dialerOf 把 (ctx, addr) 拨号函数适配为 core.TargetDialer（测试假件）。
func dialerOf(fn func(ctx context.Context, addr string) (net.Conn, error)) core.TargetDialer {
	return dialerOfAdapter{fn: fn}
}

type dialerOfAdapter struct {
	fn func(ctx context.Context, addr string) (net.Conn, error)
}

func (a dialerOfAdapter) DialTarget(ctx context.Context, t core.Target) (net.Conn, core.Route, error) {
	conn, err := a.fn(ctx, t.String())
	return conn, core.Route{Action: core.RouteDirect}, err
}
