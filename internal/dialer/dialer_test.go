package dialer

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/nodes"
	"github.com/OopsOo0ps/proxy/internal/routing"
)

type nopConn struct{}

func (nopConn) Read([]byte) (int, error)         { return 0, errors.New("nop") }
func (nopConn) Write(b []byte) (int, error)      { return len(b), nil }
func (nopConn) Close() error                     { return nil }
func (nopConn) LocalAddr() net.Addr              { return nil }
func (nopConn) RemoteAddr() net.Addr             { return nil }
func (nopConn) SetDeadline(time.Time) error      { return nil }
func (nopConn) SetReadDeadline(time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(time.Time) error { return nil }

// stubTransport 是最小的出口传输实现，仅为满足 Node 的构造校验：
// 池逻辑通过注入的拨号函数工作，自身不调用传输。
type stubTransport struct{}

func (stubTransport) DialTunnel(context.Context, core.Target) (net.Conn, error) {
	return nil, errors.New("stub transport: dial tunnel not implemented")
}

func engine(t *testing.T, defaultAction core.RouteAction, privateDirect bool) *routing.Engine {
	t.Helper()
	e, err := routing.NewEngine(nil, routing.Options{Default: defaultAction, PrivateDirect: privateDirect})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestDialDirect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	host, port := splitAddr(t, ln.Addr().String())
	d := New(Options{Router: engine(t, core.RouteProxy, true)})

	conn, route, err := d.DialTarget(context.Background(), core.Target{Host: host, Port: port})
	if err != nil {
		t.Fatalf("DialTarget: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if route.Action != core.RouteDirect {
		t.Fatalf("route = %v, want direct（环回地址应直连）", route.Action)
	}
	if route.Label != "" {
		t.Fatalf("label = %q, want empty（Direct 时标签为空）", route.Label)
	}
}

func TestDialProxy(t *testing.T) {
	pool, err := nodes.New(
		[]nodes.Node{{Addr: "node1.example.com:443", Transport: stubTransport{}}},
		func(context.Context, nodes.Node, core.Target) (net.Conn, error) { return nopConn{}, nil },
		nodes.Options{},
	)
	if err != nil {
		t.Fatal(err)
	}
	d := New(Options{Router: engine(t, core.RouteProxy, false), Pool: pool})

	_, route, err := d.DialTarget(context.Background(), core.Target{Host: "example.com", Port: 443})
	if err != nil {
		t.Fatalf("DialTarget: %v", err)
	}
	if route.Action != core.RouteProxy {
		t.Fatalf("route = %v, want proxy", route.Action)
	}
	if route.Label != "node1.example.com:443" {
		t.Fatalf("label = %q, want the selected node address", route.Label)
	}
}

func TestDialProxyWithoutNodesFails(t *testing.T) {
	d := New(Options{Router: engine(t, core.RouteProxy, false)})
	_, route, err := d.DialTarget(context.Background(), core.Target{Host: "example.com", Port: 443})
	if !errors.Is(err, ErrNoNodes) {
		t.Fatalf("err = %v, want ErrNoNodes", err)
	}
	if route.Action != core.RouteProxy {
		t.Fatalf("route = %v, want proxy", route.Action)
	}
	if route.Label != "pool" {
		t.Fatalf("label = %q, want pool", route.Label)
	}
}

// TestDialTargetKeepsDomainUnresolved 锁定 remote DNS 的核心保证：
// 走代理的目标域名必须原样交给出口节点（客户端不做本地解析），
// 否则 DNS 污染 / 泄漏会重新出现在代理路径上。
func TestDialTargetKeepsDomainUnresolved(t *testing.T) {
	var gotTarget core.Target
	pool, err := nodes.New(
		[]nodes.Node{{Addr: "node1.example.com:443", Transport: stubTransport{}}},
		func(_ context.Context, _ nodes.Node, t core.Target) (net.Conn, error) {
			gotTarget = t
			return nopConn{}, nil
		},
		nodes.Options{},
	)
	if err != nil {
		t.Fatal(err)
	}
	d := New(Options{Router: engine(t, core.RouteProxy, false), Pool: pool})

	// 该名字在本机不可解析（.invalid 保留域）；只要出口拨号函数收到的是
	// 原始域名而非解析结果，就证明客户端未做本地解析。
	if _, _, err := d.DialTarget(context.Background(), core.Target{Host: "remote-only.invalid", Port: 8443}); err != nil {
		t.Fatalf("DialTarget: %v", err)
	}
	if gotTarget.Host != "remote-only.invalid" || gotTarget.Port != 8443 {
		t.Fatalf("exit dial target = %s, want remote-only.invalid:8443（不得本地解析）", gotTarget)
	}
}

// TestDialTargetReject 锁定拒绝分派：路由判定为拒绝时返回 Route{Reject}
// （无连接、无错误），由入站按协议回拒绝响应。
func TestDialTargetReject(t *testing.T) {
	router := stubRouter{action: core.RouteReject}
	d := New(Options{Router: router, Pool: nil})
	conn, route, err := d.DialTarget(context.Background(), core.Target{Host: "blocked.example.com", Port: 443})
	if err != nil || conn != nil {
		t.Fatalf("DialTarget reject = (%v, %v), want (nil, nil)", conn, err)
	}
	if route.Action != core.RouteReject {
		t.Fatalf("route = %v, want reject", route.Action)
	}
}

// stubRouter 是固定动作的分流决策器（仅为本测试服务）。
type stubRouter struct{ action core.RouteAction }

func (r stubRouter) Decide(string) core.RouteAction { return r.action }

func splitAddr(t *testing.T, addr string) (string, uint16) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, uint16(port)
}
