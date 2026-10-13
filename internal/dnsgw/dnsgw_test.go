package dnsgw

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/testutil"
)

// routeFunc 是测试用分流判定：*.lan 直连，其余走代理（消费方接口的测试桩，
// 与生产组装根包装 routing.Decide 的形状一致）。
type routeFunc func(host string) core.RouteAction

func (f routeFunc) Decide(t core.Target) core.Route {
	return core.Route{Action: f(t.Host)}
}

func testAction(host string) core.RouteAction {
	if strings.HasSuffix(host, ".lan") {
		return core.RouteDirect
	}
	return core.RouteProxy
}

// dialerFunc 把函数适配为 core.TargetDialer（测试桩用）。
type dialerFunc func(ctx context.Context, t core.Target) (net.Conn, core.Route, error)

func (f dialerFunc) DialTarget(ctx context.Context, t core.Target) (net.Conn, core.Route, error) {
	return f(ctx, t)
}

// dialDirectUDP 返回本地解析路径（直连剪枝）的拨号桩：对目标做 UDP 拨号，
// 与生产组装的直连剪枝同语义。
func dialDirectUDP() core.TargetDialer {
	return dialerFunc(func(ctx context.Context, t core.Target) (net.Conn, core.Route, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "udp", t.String())
		return conn, core.Route{Action: core.RouteDirect}, err
	})
}

// dialThroughExit 返回一个“经隧道”的拨号桩：直连给定的上游 DNS 地址，
// 并记录调用参数（测试中网关与上游同机，语义上是出口侧访问）。
func dialThroughExit(t *testing.T, upstream string, calls *atomic.Int64) core.TargetDialer {
	t.Helper()
	host, portString, err := net.SplitHostPort(upstream)
	if err != nil {
		t.Fatal(err)
	}
	wantPort, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatal(err)
	}
	return dialerFunc(func(ctx context.Context, got core.Target) (net.Conn, core.Route, error) {
		calls.Add(1)
		if got.Host != host || int(got.Port) != wantPort {
			return nil, core.Route{}, errors.New("unexpected tunnel target " + got.String())
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", upstream)
		if err != nil {
			return nil, core.Route{}, err
		}
		return conn, core.Route{Action: core.RouteProxy, Label: "test-node"}, nil
	})
}

// noDial 返回一个任何调用都报错的拨号桩（断言路径不应触达出站）。
func noDial(msg string) core.TargetDialer {
	return dialerFunc(func(context.Context, core.Target) (net.Conn, core.Route, error) {
		return nil, core.Route{}, errors.New(msg)
	})
}

// gatewayHandle 封装一个运行中的测试网关。
type gatewayHandle struct {
	srv  *Server
	addr string
}

func startGateway(t *testing.T, opts Options) *gatewayHandle {
	t.Helper()
	if opts.Router == nil {
		opts.Router = routeFunc(testAction)
	}
	srv, err := New(opts)
	if err != nil {
		t.Fatalf("dnsgw.New: %v", err)
	}
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("dnsgw.Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("dnsgw.Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("dnsgw.Serve did not stop")
		}
	})
	return &gatewayHandle{srv: srv, addr: ln.Addr().String()}
}

func mustQuery(t *testing.T, addr, name string, id uint16) []byte {
	t.Helper()
	resp, err := testutil.QueryUDP(addr, testutil.BuildAQuery(name, id), 3*time.Second)
	if err != nil {
		t.Fatalf("query %s: %v", name, err)
	}
	if got := testutil.DNSID(resp); got != id {
		t.Fatalf("response id = %#x, want %#x", got, id)
	}
	return resp
}

func TestRemoteRouteGoesThroughExit(t *testing.T) {
	remote, err := testutil.StartDNSServer(func(q []byte, network string) []byte {
		if network != "tcp" {
			t.Errorf("remote resolver queried over %s, want tcp", network)
		}
		return testutil.BuildReply(q, 0, []netip.Addr{netip.MustParseAddr("10.0.0.1")}, false)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remote.Close)
	local, err := testutil.StartDNSServer(func(q []byte, network string) []byte {
		return testutil.BuildReply(q, 0, []netip.Addr{netip.MustParseAddr("192.168.1.1")}, false)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.Close)

	var tunnelCalls atomic.Int64
	gw := startGateway(t, Options{
		Remote:  remote.Addr,
		Local:   []string{local.Addr},
		Timeout: 2 * time.Second,
		Direct:  dialDirectUDP(),
		Proxy:   dialThroughExit(t, remote.Addr, &tunnelCalls),
	})

	resp := mustQuery(t, gw.addr, "site.test", 0x1111)
	if got := testutil.DNSRcode(resp); got != 0 {
		t.Fatalf("rcode = %d, want 0", got)
	}
	ips := testutil.DNSAnswerIPs(resp)
	if len(ips) != 1 || ips[0].String() != "10.0.0.1" {
		t.Fatalf("answer = %v, want [10.0.0.1]", ips)
	}
	if tunnelCalls.Load() != 1 {
		t.Fatalf("tunnel calls = %d, want 1", tunnelCalls.Load())
	}
	if remote.TCPHits() != 1 {
		t.Fatalf("remote tcp hits = %d, want 1", remote.TCPHits())
	}
	if local.UDPHits() != 0 || local.TCPHits() != 0 {
		t.Fatalf("local resolver was contacted (udp=%d tcp=%d): 代理名字不得走本地解析",
			local.UDPHits(), local.TCPHits())
	}
}

func TestDirectRouteUsesLocalResolver(t *testing.T) {
	remote, err := testutil.StartDNSServer(func(q []byte, network string) []byte {
		return testutil.BuildReply(q, 0, []netip.Addr{netip.MustParseAddr("10.0.0.1")}, false)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remote.Close)
	local, err := testutil.StartDNSServer(func(q []byte, network string) []byte {
		return testutil.BuildReply(q, 0, []netip.Addr{netip.MustParseAddr("192.168.1.9")}, false)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.Close)

	var tunnelCalls atomic.Int64
	gw := startGateway(t, Options{
		Remote:  remote.Addr,
		Local:   []string{local.Addr},
		Timeout: 2 * time.Second,
		Direct:  dialDirectUDP(),
		Proxy:   dialThroughExit(t, remote.Addr, &tunnelCalls),
	})

	resp := mustQuery(t, gw.addr, "printer.lan", 0x2222)
	ips := testutil.DNSAnswerIPs(resp)
	if len(ips) != 1 || ips[0].String() != "192.168.1.9" {
		t.Fatalf("answer = %v, want [192.168.1.9]", ips)
	}
	if local.UDPHits() != 1 {
		t.Fatalf("local udp hits = %d, want 1", local.UDPHits())
	}
	if tunnelCalls.Load() != 0 || remote.TCPHits() != 0 {
		t.Fatalf("直连名字不应经隧道（tunnel=%d remote_tcp=%d）", tunnelCalls.Load(), remote.TCPHits())
	}
}

func TestDirectTruncatedReplyFallsBackToTCP(t *testing.T) {
	local, err := testutil.StartDNSServer(func(q []byte, network string) []byte {
		if network == "udp" {
			return testutil.BuildReply(q, 0, nil, true) // TC=1，无回答
		}
		return testutil.BuildReply(q, 0, []netip.Addr{netip.MustParseAddr("192.168.1.7")}, false)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.Close)

	gw := startGateway(t, Options{
		Local:   []string{local.Addr},
		Timeout: 2 * time.Second,
		Direct:  dialDirectUDP(),
		Proxy:   noDial("tunnel must not be used for direct names"),
	})

	resp := mustQuery(t, gw.addr, "printer.lan", 0x3333)
	ips := testutil.DNSAnswerIPs(resp)
	if len(ips) != 1 || ips[0].String() != "192.168.1.7" {
		t.Fatalf("answer = %v, want [192.168.1.7]（TCP 重试后的完整回答）", ips)
	}
	if local.UDPHits() != 1 || local.TCPHits() != 1 {
		t.Fatalf("local hits udp=%d tcp=%d, want 1/1", local.UDPHits(), local.TCPHits())
	}
}

func TestTCPClientTransport(t *testing.T) {
	remote, err := testutil.StartDNSServer(func(q []byte, network string) []byte {
		return testutil.BuildReply(q, 0, []netip.Addr{netip.MustParseAddr("10.0.0.2")}, false)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remote.Close)

	gw := startGateway(t, Options{
		Remote:  remote.Addr,
		Timeout: 2 * time.Second,
		Direct:  dialDirectUDP(),
		Proxy: dialerFunc(func(ctx context.Context, _ core.Target) (net.Conn, core.Route, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", remote.Addr)
			return conn, core.Route{Action: core.RouteProxy, Label: "test-node"}, err
		}),
	})

	conn, err := net.DialTimeout("tcp", gw.addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if err := testutil.WriteDNSFrame(conn, testutil.BuildAQuery("tcp.test", 0x4444)); err != nil {
		t.Fatal(err)
	}
	resp, err := testutil.ReadDNSFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	if got := testutil.DNSID(resp); got != 0x4444 {
		t.Fatalf("id = %#x, want 0x4444", got)
	}
	ips := testutil.DNSAnswerIPs(resp)
	if len(ips) != 1 || ips[0].String() != "10.0.0.2" {
		t.Fatalf("answer = %v, want [10.0.0.2]", ips)
	}

	// 同一连接上的第二条查询（顺序处理）。
	if err := testutil.WriteDNSFrame(conn, testutil.BuildAQuery("tcp2.test", 0x5555)); err != nil {
		t.Fatal(err)
	}
	resp2, err := testutil.ReadDNSFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	if got := testutil.DNSID(resp2); got != 0x5555 {
		t.Fatalf("second response id = %#x, want 0x5555", got)
	}
}

func TestMalformedQueryGetsFormErr(t *testing.T) {
	gw := startGateway(t, Options{
		Timeout: time.Second,
		Direct:  noDial("must not dial"),
		Proxy:   noDial("must not dial"),
	})
	resp, err := testutil.QueryUDP(gw.addr, []byte{0x12, 0x34, 0x01}, time.Second)
	if err != nil {
		t.Fatalf("expected FORMERR response: %v", err)
	}
	if got := testutil.DNSRcode(resp); got != rcodeFormatErr {
		t.Fatalf("rcode = %d, want %d (FORMERR)", got, rcodeFormatErr)
	}
}

func TestNonQueryIsDropped(t *testing.T) {
	gw := startGateway(t, Options{
		Timeout: time.Second,
		Direct:  noDial("must not dial"),
		Proxy:   noDial("must not dial"),
	})
	// 一条响应报文（QR=1）应被静默丢弃，避免转发环。
	reply := testutil.BuildReply(testutil.BuildAQuery("x.test", 0x6666), 0, nil, false)
	if resp, err := testutil.QueryUDP(gw.addr, reply, 300*time.Millisecond); err == nil {
		t.Fatalf("expected timeout (no response), got %d bytes", len(resp))
	}
}

func TestUnsupportedOpcodeGetsRefused(t *testing.T) {
	gw := startGateway(t, Options{
		Timeout: time.Second,
		Direct:  noDial("must not dial"),
		Proxy:   noDial("must not dial"),
	})
	query := testutil.BuildAQuery("x.test", 0x7777)
	query[2] |= 5 << 3 // opcode = UPDATE
	resp, err := testutil.QueryUDP(gw.addr, query, time.Second)
	if err != nil {
		t.Fatalf("expected REFUSED response: %v", err)
	}
	if got := testutil.DNSRcode(resp); got != rcodeRefused {
		t.Fatalf("rcode = %d, want %d (REFUSED)", got, rcodeRefused)
	}
}

func TestRemoteFailureReturnsServFail(t *testing.T) {
	// 指向一个已关闭的端口：隧道内拨号必定失败。
	deadLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := deadLn.Addr().String()
	_ = deadLn.Close()

	gw := startGateway(t, Options{
		Remote:  deadAddr,
		Timeout: time.Second,
		Direct:  dialDirectUDP(),
		Proxy: dialerFunc(func(ctx context.Context, _ core.Target) (net.Conn, core.Route, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", deadAddr)
			if err != nil {
				return nil, core.Route{}, err
			}
			return conn, core.Route{Action: core.RouteProxy, Label: "test-node"}, nil
		}),
	})

	resp := mustQuery(t, gw.addr, "unreachable.test", 0x8888)
	if got := testutil.DNSRcode(resp); got != rcodeServerFail {
		t.Fatalf("rcode = %d, want %d (SERVFAIL)", got, rcodeServerFail)
	}
	if name := testutil.DNSQuestionName(resp); name != "unreachable.test" {
		t.Fatalf("question name = %q, want unreachable.test（问题段需回显）", name)
	}
}

func TestLocalResolversFromResolvConf(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	content := strings.Join([]string{
		"# generated by test",
		"nameserver 9.9.9.9",
		"nameserver ::1",
		"nameserver 127.0.0.1",
		"nameserver not-an-ip",
		"options ndots:1",
		"search example.com",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LocalResolversFromResolvConf(path, "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"9.9.9.9:53", "[::1]:53"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("resolvers = %v, want %v", got, want)
	}

	// 端口不同则不算自环：网关监听 127.0.0.1:1053 时，127.0.0.1:53 仍可用。
	got, err = LocalResolversFromResolvConf(path, "127.0.0.1:1053")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2] != "127.0.0.1:53" {
		t.Fatalf("resolvers = %v, want 含 127.0.0.1:53", got)
	}

	if _, err := LocalResolversFromResolvConf(filepath.Join(dir, "missing.conf"), ""); err == nil {
		t.Fatal("不存在的文件应返回错误")
	}
}

func TestServeShutdown(t *testing.T) {
	srv, err := New(Options{
		Timeout: time.Second,
		Router:  routeFunc(testAction),
		Direct:  noDial("must not dial"),
		Proxy:   noDial("must not dial"),
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop after cancel")
	}
	if _, err := testutil.QueryUDP(addr, testutil.BuildAQuery("x.test", 1), 200*time.Millisecond); err == nil {
		t.Fatal("关停后监听应已关闭")
	}
}

// TestNewRequiresContractDialers 钉住契约注入约束：分流判定与两侧出站能力
// 必须由组装根注入。
func TestNewRequiresContractDialers(t *testing.T) {
	if _, err := New(Options{}); err == nil || !strings.Contains(err.Error(), "router") {
		t.Fatalf("err = %v, want router required", err)
	}
	if _, err := New(Options{Router: routeFunc(testAction)}); err == nil || !strings.Contains(err.Error(), "direct") {
		t.Fatalf("err = %v, want direct dialer required", err)
	}
	if _, err := New(Options{Router: routeFunc(testAction), Direct: dialDirectUDP()}); err == nil || !strings.Contains(err.Error(), "proxy") {
		t.Fatalf("err = %v, want proxy dialer required", err)
	}
}
