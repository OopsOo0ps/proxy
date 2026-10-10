package dialer

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/config"
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

func engine(t *testing.T, defaultAction routing.Action, privateDirect bool) *routing.Engine {
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
	d := New(Options{Router: engine(t, routing.Proxy, true)})

	conn, route, err := d.DialTarget(context.Background(), host, port)
	if err != nil {
		t.Fatalf("DialTarget: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if route.Action != routing.Direct {
		t.Fatalf("route = %v, want direct（环回地址应直连）", route.Action)
	}
	if route.Label() != "direct" {
		t.Fatalf("label = %q, want direct", route.Label())
	}
}

func TestDialProxy(t *testing.T) {
	pool, err := nodes.New(
		[]config.Node{{Addr: "node1.example.com:443", Password: "p"}},
		func(context.Context, config.Node, string, uint16) (net.Conn, error) { return nopConn{}, nil },
		nodes.Options{},
	)
	if err != nil {
		t.Fatal(err)
	}
	d := New(Options{Router: engine(t, routing.Proxy, false), Pool: pool})

	_, route, err := d.DialTarget(context.Background(), "example.com", 443)
	if err != nil {
		t.Fatalf("DialTarget: %v", err)
	}
	if route.Action != routing.Proxy {
		t.Fatalf("route = %v, want proxy", route.Action)
	}
	if route.Upstream != "node1.example.com:443" {
		t.Fatalf("upstream = %q", route.Upstream)
	}
	if route.Label() != "node1.example.com:443" {
		t.Fatalf("label = %q", route.Label())
	}
}

func TestDialProxyWithoutNodesFails(t *testing.T) {
	d := New(Options{Router: engine(t, routing.Proxy, false)})
	_, route, err := d.DialTarget(context.Background(), "example.com", 443)
	if !errors.Is(err, ErrNoNodes) {
		t.Fatalf("err = %v, want ErrNoNodes", err)
	}
	if route.Action != routing.Proxy {
		t.Fatalf("route = %v, want proxy", route.Action)
	}
	if route.Label() != "pool" {
		t.Fatalf("label = %q, want pool", route.Label())
	}
}

func TestRouteFor(t *testing.T) {
	d := New(Options{Router: engine(t, routing.Proxy, true)})
	if got := d.RouteFor("127.0.0.1"); got != routing.Direct {
		t.Fatalf("RouteFor(127.0.0.1) = %v, want direct", got)
	}
	if got := d.RouteFor("example.com"); got != routing.Proxy {
		t.Fatalf("RouteFor(example.com) = %v, want proxy", got)
	}
}

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
