package dnsgw

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/connlimit"
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

// —— 观测契约组件层（§8.4 测试纪律：记录器假件 + 事件序列断言）——

// queryEvent 是一条 QueryDone 观测事件的形状（route/result 词汇）。
type queryEvent struct {
	route  string
	result string
}

// recQueryObserver 记录 DNSObserver 的全部事件（记录器假件）。
type recQueryObserver struct {
	mu     sync.Mutex
	events []queryEvent
}

func (r *recQueryObserver) QueryDone(route, result string, _ time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, queryEvent{route: route, result: result})
}

func (r *recQueryObserver) snapshot() []queryEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]queryEvent(nil), r.events...)
}

// TestObserverQueryEventSequence 钉住查询的观测事件序列与 result 词汇。
// dnsgw 的观测契约是 DNSObserver（§8.4 事件归属：查询结果），一次查询
// 恰好一条 QueryDone；route 取 core.RouteAction 的观测写法（非法报文留空），
// result 取 core.Result*（ok/error/denied）与 ResultInvalid。按顺序发起：
// 代理路由成功 → 直连路由成功 → 代理上游失败 → 分流拒绝 → 非法报文，
// 事件序列必须一一对应（查询逐条等待响应，事件顺序确定）。
func TestObserverQueryEventSequence(t *testing.T) {
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
		if network != "udp" {
			t.Errorf("local resolver queried over %s, want udp", network)
		}
		return testutil.BuildReply(q, 0, []netip.Addr{netip.MustParseAddr("192.168.1.1")}, false)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.Close)

	// 代理剪枝：首次拨通远端解析器，之后出口“宕机”（拨号失败分支）。
	var exitDown atomic.Bool
	proxy := dialerFunc(func(ctx context.Context, got core.Target) (net.Conn, core.Route, error) {
		if exitDown.Load() {
			return nil, core.Route{Action: core.RouteProxy}, errors.New("exit node down")
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", remote.Addr)
		if err != nil {
			return nil, core.Route{Action: core.RouteProxy}, err
		}
		exitDown.Store(true)
		return conn, core.Route{Action: core.RouteProxy, Label: "test-node"}, nil
	})

	obs := &recQueryObserver{}
	gw := startGateway(t, Options{
		Router: routeFunc(func(host string) core.RouteAction {
			if strings.HasPrefix(host, "reject.") {
				return core.RouteReject
			}
			return testAction(host)
		}),
		Remote:   remote.Addr,
		Local:    []string{local.Addr},
		Timeout:  2 * time.Second,
		Direct:   dialDirectUDP(),
		Proxy:    proxy,
		Observer: obs,
	})

	// 1. 代理路由成功。
	if resp := mustQuery(t, gw.addr, "one.proxy.test", 0x0101); testutil.DNSRcode(resp) != 0 {
		t.Fatalf("proxy query rcode = %d, want 0", testutil.DNSRcode(resp))
	}
	// 2. 直连路由成功（*.lan 走本地解析器）。
	if resp := mustQuery(t, gw.addr, "two.lan", 0x0102); testutil.DNSRcode(resp) != 0 {
		t.Fatalf("direct query rcode = %d, want 0", testutil.DNSRcode(resp))
	}
	// 3. 代理路由，上游失败（SERVFAIL）。
	if resp := mustQuery(t, gw.addr, "three.proxy.test", 0x0103); testutil.DNSRcode(resp) != 2 {
		t.Fatalf("failed proxy query rcode = %d, want 2 (SERVFAIL)", testutil.DNSRcode(resp))
	}
	// 4. 分流拒绝（REFUSED，不发给任何上游）。
	if resp := mustQuery(t, gw.addr, "reject.four.test", 0x0104); testutil.DNSRcode(resp) != 5 {
		t.Fatalf("rejected query rcode = %d, want 5 (REFUSED)", testutil.DNSRcode(resp))
	}
	// 5. 非法报文（FORMERR 响应，不转发给任何上游）。
	{
		conn, err := net.Dial("udp", gw.addr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write([]byte{0x12, 0x34}); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 512)
		if _, err := conn.Read(buf); err != nil {
			t.Fatalf("read malformed-query response: %v", err)
		}
	}

	want := []queryEvent{
		{route: "proxy", result: core.ResultOK},
		{route: "direct", result: core.ResultOK},
		{route: "proxy", result: core.ResultError},
		{route: "reject", result: core.ResultDenied},
		{route: "", result: ResultInvalid},
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if got := obs.snapshot(); len(got) == len(want) {
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("events[%d] = %+v, want %+v（全部事件 = %+v）", i, got[i], want[i], got)
				}
			}
			return
		} else if time.Now().After(deadline) {
			t.Fatalf("events = %+v, want %+v", got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// —— 查询闸（背压）：UDP 静默丢弃 / TCP REFUSED / nil 不限 ——

// waitForActive 轮询直到 limiter 活跃占用达到 want（跨 goroutine 的确定性同步）。
func waitForActive(t *testing.T, limiter *connlimit.Limiter, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if limiter.Active() == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("limiter active = %d, want %d", limiter.Active(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitOverloadEvent 轮询直到观测记录中出现 route 为空、result 为 want 的事件。
func waitOverloadEvent(t *testing.T, obs *recQueryObserver, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		for _, ev := range obs.snapshot() {
			if ev.route == "" && ev.result == want {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("observer events = %+v, want a {route:\"\", result:%q} event", obs.snapshot(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestUDPQueryGateDropsAndRecovers 钉住 UDP 查询闸语义：每条在途查询占一个
// 名额，超限查询静默丢弃（不回包）并记 QueryDone("", overloaded, 0)；
// 名额释放后立即恢复服务。
func TestUDPQueryGateDropsAndRecovers(t *testing.T) {
	gate := make(chan struct{}) // 阻塞型本地解析器：收到查询后等待放行
	got := make(chan struct{}, 4)
	local, err := testutil.StartDNSServer(func(q []byte, _ string) []byte {
		got <- struct{}{}
		<-gate
		return testutil.BuildReply(q, 0, []netip.Addr{netip.MustParseAddr("192.168.1.1")}, false)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.Close)

	limiter := connlimit.New(1)
	obs := &recQueryObserver{}
	gw := startGateway(t, Options{
		Local:        []string{local.Addr},
		Timeout:      5 * time.Second,
		Direct:       dialDirectUDP(),
		Proxy:        noDial("unexpected tunnel dial"),
		Observer:     obs,
		QueryLimiter: limiter,
	})

	// Q1 占满唯一名额（解析器阻塞，查询在途）。
	respCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := testutil.QueryUDP(gw.addr, testutil.BuildAQuery("one.lan", 0x0101), 5*time.Second)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()
	<-got
	waitForActive(t, limiter, 1)

	// Q2 超限：静默丢弃，客户端等待超时。
	if _, err := testutil.QueryUDP(gw.addr, testutil.BuildAQuery("two.lan", 0x0202), 300*time.Millisecond); err == nil {
		t.Fatal("over-limit UDP query got a response, want silent drop (timeout)")
	}
	waitOverloadEvent(t, obs, core.ResultOverload)

	// 放行 Q1：得到正常应答。
	close(gate)
	select {
	case resp := <-respCh:
		if testutil.DNSRcode(resp) != 0 {
			t.Fatalf("q1 rcode = %d, want 0", testutil.DNSRcode(resp))
		}
	case err := <-errCh:
		t.Fatalf("q1 failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("q1 did not complete")
	}
	waitForActive(t, limiter, 0)

	// Q3：名额已归还，服务恢复。
	resp := mustQuery(t, gw.addr, "three.lan", 0x0303)
	if testutil.DNSRcode(resp) != 0 {
		t.Fatalf("q3 rcode = %d, want 0", testutil.DNSRcode(resp))
	}
}

// TestUDPQueryGateNilUnlimited 钉住缺省语义：不设 QueryLimiter 时并发查询
// 全部处理，不受任何闸约束。
func TestUDPQueryGateNilUnlimited(t *testing.T) {
	local, err := testutil.StartDNSServer(func(q []byte, _ string) []byte {
		return testutil.BuildReply(q, 0, []netip.Addr{netip.MustParseAddr("192.168.1.1")}, false)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.Close)

	gw := startGateway(t, Options{
		Local:   []string{local.Addr},
		Timeout: 3 * time.Second,
		Direct:  dialDirectUDP(),
		Proxy:   noDial("unexpected tunnel dial"),
	})

	const n = 3
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := testutil.QueryUDP(gw.addr, testutil.BuildAQuery(fmt.Sprintf("host%d.lan", i), uint16(0x10+i)), 3*time.Second)
			if err == nil && testutil.DNSRcode(resp) != 0 {
				err = fmt.Errorf("rcode = %d, want 0", testutil.DNSRcode(resp))
			}
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
	}
}

// TestTCPRejectOverloadRefused 钉住 TCP 查询闸语义：连接占名额、超限连接
// 读首帧查询回 REFUSED（ID 回填），名额释放后恢复服务。
func TestTCPRejectOverloadRefused(t *testing.T) {
	local, err := testutil.StartDNSServer(func(q []byte, _ string) []byte {
		return testutil.BuildReply(q, 0, []netip.Addr{netip.MustParseAddr("192.168.1.1")}, false)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(local.Close)

	limiter := connlimit.New(1)
	gw := startGateway(t, Options{
		Local:        []string{local.Addr},
		Timeout:      5 * time.Second,
		Direct:       dialDirectUDP(),
		Proxy:        noDial("unexpected tunnel dial"),
		QueryLimiter: limiter,
	})

	// 连接 1 占满唯一名额（不发帧，停留在读首帧）。
	conn1, err := net.Dial("tcp", gw.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn1.Close() }()
	waitForActive(t, limiter, 1)

	// 连接 2 超限：发出合法查询，应收到 REFUSED 且 ID 回填。
	conn2, err := net.Dial("tcp", gw.addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn2.SetDeadline(time.Now().Add(3 * time.Second))
	if err := testutil.WriteDNSFrame(conn2, testutil.BuildAQuery("two.lan", 0x0202)); err != nil {
		t.Fatal(err)
	}
	resp2, err := testutil.ReadDNSFrame(conn2)
	if err != nil {
		t.Fatalf("read overload response: %v", err)
	}
	if got := testutil.DNSID(resp2); got != 0x0202 {
		t.Fatalf("overload response id = %#x, want 0x202（ID 应回填）", got)
	}
	if got := testutil.DNSRcode(resp2); got != rcodeRefused {
		t.Fatalf("overload rcode = %d, want %d (REFUSED)", got, rcodeRefused)
	}
	_ = conn2.Close()

	// 释放名额后连接 3 正常得答。
	_ = conn1.Close()
	waitForActive(t, limiter, 0)
	conn3, err := net.Dial("tcp", gw.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn3.Close() }()
	_ = conn3.SetDeadline(time.Now().Add(3 * time.Second))
	if err := testutil.WriteDNSFrame(conn3, testutil.BuildAQuery("three.lan", 0x0303)); err != nil {
		t.Fatal(err)
	}
	resp3, err := testutil.ReadDNSFrame(conn3)
	if err != nil {
		t.Fatalf("read response after recovery: %v", err)
	}
	if got := testutil.DNSRcode(resp3); got != 0 {
		t.Fatalf("recovered rcode = %d, want 0", got)
	}
}
