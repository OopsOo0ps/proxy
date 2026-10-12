package connpool

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/metrics"
)

// fakeClock 是可手动推进的时钟。
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Now()} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeNode 是一个可观测的假节点：Dial 返回内存管道，Start 可注入错误。
type fakeNode struct {
	dials   atomic.Int64
	started atomic.Int64

	mu     sync.Mutex
	peers  []net.Conn // 管道对端（测试侧），可用来模拟服务端行为
	onDial func() (net.Conn, error)
	start  func(ctx context.Context, conn net.Conn, t core.Target) error
}

func (n *fakeNode) dial(ctx context.Context) (net.Conn, error) {
	n.dials.Add(1)
	if n.onDial != nil {
		return n.onDial()
	}
	client, server := net.Pipe()
	n.mu.Lock()
	n.peers = append(n.peers, server)
	n.mu.Unlock()
	return client, nil
}

func (n *fakeNode) startRequest(ctx context.Context, conn net.Conn, t core.Target) error {
	if n.start != nil {
		return n.start(ctx, conn, t)
	}
	n.started.Add(1)
	return nil
}

func (n *fakeNode) spec(addr string) Node {
	return Node{Addr: addr, Dial: n.dial, Start: n.startRequest}
}

func (n *fakeNode) lastPeer(t *testing.T) net.Conn {
	t.Helper()
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.peers) == 0 {
		t.Fatal("no dialed peers")
	}
	return n.peers[len(n.peers)-1]
}

func waitIdle(t *testing.T, p *Pool, addr string, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if p.IdleCounts()[addr] == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("idle[%s] = %d, want %d", addr, p.IdleCounts()[addr], want)
}

// tcpPair 建立一对本地 TCP 连接用于探测类测试（时序语义与生产一致）。
func tcpPair(t testing.TB) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	acceptCh := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			acceptCh <- conn
		}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	select {
	case server := <-acceptCh:
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
		})
		return client, server
	case <-time.After(2 * time.Second):
		t.Fatal("accept timeout")
	}
	return nil, nil
}

// injectIdle 直接把空闲连接放进池中，便于在不起后台任务的情况下测试领取路径。
func injectIdle(p *Pool, addr string, conn net.Conn, at time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.nodes[addr]
	st.idle = append(st.idle, &idleConn{conn: conn, createdAt: at})
}

func metricsText(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rec.Body.String()
}

func TestWarmUpAndClaimHit(t *testing.T) {
	n := &fakeNode{}
	p, err := New([]Node{n.spec("n1")}, Options{MaxIdle: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	p.Start(context.Background())

	waitIdle(t, p, "n1", 2)

	// 连续领取两条：都应命中，且领取后池应异步补齐回 MaxIdle。
	for i := 0; i < 2; i++ {
		conn, ok := p.Claim(context.Background(), "n1", core.Target{Host: "example.com", Port: 443})
		if !ok {
			t.Fatalf("claim %d should hit after warm-up", i+1)
		}
		t.Cleanup(func() { _ = conn.Close() })
	}
	if got := n.started.Load(); got != 2 {
		t.Fatalf("start called %d times, want 2", got)
	}
	waitIdle(t, p, "n1", 2)
}

func TestClaimMissAndWarmFailureMetrics(t *testing.T) {
	m := metrics.New()
	n := &fakeNode{onDial: func() (net.Conn, error) {
		return nil, errors.New("node unreachable")
	}}
	p, err := New([]Node{n.spec("n1")}, Options{MaxIdle: 1, Metrics: m})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	p.Start(context.Background())

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && n.dials.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}

	if _, ok := p.Claim(context.Background(), "n1", core.Target{Host: "example.com", Port: 443}); ok {
		t.Fatal("claim should miss when warm-up failed")
	}

	text := metricsText(t, m)
	for _, want := range []string{
		`upstream_pool_claims_total{node="n1",result="miss"} 1`,
		`upstream_pool_idle_connections{node="n1"} 0`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("/metrics missing %q:\n%s", want, text)
		}
	}
	if !strings.Contains(text, `upstream_pool_warm_failures_total{node="n1"}`) {
		t.Fatalf("/metrics missing warm failures:\n%s", text)
	}
}

func TestClaimSkipsExpiredConn(t *testing.T) {
	clock := newFakeClock()
	m := metrics.New()
	n := &fakeNode{}
	p, err := New([]Node{n.spec("n1")}, Options{MaxIdle: 1, IdleTTL: time.Second, Now: clock.Now, Metrics: m})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	injectIdle(p, "n1", client, clock.Now().Add(-2*time.Second)) // 已超过 IdleTTL

	if _, ok := p.Claim(context.Background(), "n1", core.Target{Host: "example.com", Port: 443}); ok {
		t.Fatal("expired conn must not be claimed")
	}
	if got := p.IdleCounts()["n1"]; got != 0 {
		t.Fatalf("idle = %d, want 0（过期连接应被淘汰）", got)
	}
	// 过期连接应已被关闭：对端读到 EOF。
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := server.Read(make([]byte, 1)); err == nil {
		t.Fatal("expired conn should be closed")
	}
	if !strings.Contains(metricsText(t, m), `upstream_pool_claims_total{node="n1",result="stale"} 1`) {
		t.Fatalf("stale claim not counted:\n%s", metricsText(t, m))
	}
}

func TestClaimSkipsClosedConn(t *testing.T) {
	n := &fakeNode{}
	p, err := New([]Node{n.spec("n1")}, Options{MaxIdle: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)

	client, server := tcpPair(t)
	_ = server.Close() // 模拟服务端已关闭的空闲连接
	// 等到客户端一侧确认 EOF，确保连接处于“已关闭”状态再入池。
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected EOF on closed peer")
	}
	_ = client.SetReadDeadline(time.Time{})
	injectIdle(p, "n1", client, time.Now())

	if _, ok := p.Claim(context.Background(), "n1", core.Target{Host: "example.com", Port: 443}); ok {
		t.Fatal("closed conn must not be claimed")
	}
}

func TestClaimSkipsConnWithPendingData(t *testing.T) {
	n := &fakeNode{}
	p, err := New([]Node{n.spec("n1")}, Options{MaxIdle: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)

	client, server := tcpPair(t)
	injectIdle(p, "n1", client, time.Now())

	// 服务端在收到请求前发来了数据（例如按握手超时回放的伪装响应）：
	// 这样的连接状态不可信，必须丢弃。
	if _, err := server.Write([]byte("HTTP/1.1 200 OK\r\n")); err != nil {
		t.Fatalf("write decoy: %v", err)
	}

	if _, ok := p.Claim(context.Background(), "n1", core.Target{Host: "example.com", Port: 443}); ok {
		t.Fatal("conn with pending data must not be claimed")
	}
}

// delayedReadConn 包装真实 TCP 连接，模拟「探测读被调度延迟」：
// Read 先等待超过探测窗口再委托给底层连接——读取执行时读期限已过，
// Go 网络栈直接返回超时、忽略已排队的数据（存活探测的旧实现即由此漏检）。
type delayedReadConn struct {
	net.Conn
	delay time.Duration
}

func (c *delayedReadConn) Read(p []byte) (int, error) {
	time.Sleep(c.delay)
	return c.Conn.Read(p)
}

// NetConn 暴露底层连接，使非阻塞探测能取到原始套接字。
func (c *delayedReadConn) NetConn() net.Conn { return c.Conn }

// TestClaimSkipsConnWhenProbeReadIsDelayed 是「预热池领取竞态」的回归用例：
// 服务端已按握手超时回收连接并回放伪装响应（数据已排队），但领取时的
// 期限读探测被调度延迟——旧的期限读会返回超时、把连接误判为健康，
// 随后把 Trojan 请求写进这条死连接，伪装响应最终流入业务（浏览器报
// "server gave HTTP response to HTTPS client"）。非阻塞探测不依赖调度，
// 必须识别出队列中的数据并丢弃连接。
func TestClaimSkipsConnWhenProbeReadIsDelayed(t *testing.T) {
	n := &fakeNode{}
	p, err := New([]Node{n.spec("n1")}, Options{MaxIdle: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)

	client, server := tcpPair(t)
	if _, err := server.Write([]byte("HTTP/1.1 200 OK\r\n\r\nIt works!\r\n")); err != nil {
		t.Fatalf("write decoy: %v", err)
	}
	time.Sleep(50 * time.Millisecond) // 伪装响应到达并排队

	conn := &delayedReadConn{Conn: client, delay: 5 * probeWindow}
	injectIdle(p, "n1", conn, time.Now())

	// 前提校验：期限读在此连接上必然漏检（超时被当作健康）。
	if err := probeAliveRead(conn); err != nil {
		t.Fatalf("前提不成立：期限读应因调度延迟返回超时（漏检），got %v", err)
	}

	if _, ok := p.Claim(context.Background(), "n1", core.Target{Host: "example.com", Port: 443}); ok {
		t.Fatal("已回放伪装响应且探测被延迟的连接不得被领取")
	}
}

// TestClaimWithDelayedProbeKeepsHealthyConn：调度延迟不影响健康连接的领取
// （非阻塞探测不消费数据、不误判）。
func TestClaimWithDelayedProbeKeepsHealthyConn(t *testing.T) {
	n := &fakeNode{}
	p, err := New([]Node{n.spec("n1")}, Options{MaxIdle: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)

	client, server := tcpPair(t)
	conn := &delayedReadConn{Conn: client, delay: 5 * probeWindow}
	injectIdle(p, "n1", conn, time.Now())

	got, ok := p.Claim(context.Background(), "n1", core.Target{Host: "example.com", Port: 443})
	if !ok {
		t.Fatal("healthy conn must be claimed even when probe reads would be delayed")
	}
	if got != net.Conn(conn) {
		t.Fatalf("claim = %v, want the injected conn", got)
	}
	// 探测不得消费数据：服务端正常发送的目标字节仍完整可读。
	if _, err := server.Write([]byte("target-bytes")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("target-bytes"))
	if _, err := io.ReadFull(got, buf); err != nil {
		t.Fatalf("read after claim: %v", err)
	}
	if string(buf) != "target-bytes" {
		t.Fatalf("payload = %q", buf)
	}
}

// TestProbeAliveTCP 固化非阻塞探测的契约：排队数据 / EOF / RST 视为失效，
// 健康连接返回 nil 且数据不被消费。
func TestProbeAliveTCP(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		client, server := tcpPair(t)
		if err := probeAlive(client); err != nil {
			t.Fatalf("healthy conn: %v", err)
		}
		// 探测后数据仍可读取（MSG_PEEK 不消费）。
		if _, err := server.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		var one [1]byte
		if _, err := io.ReadFull(client, one[:]); err != nil {
			t.Fatalf("read after probe: %v", err)
		}
	})

	t.Run("pending data", func(t *testing.T) {
		client, server := tcpPair(t)
		if _, err := server.Write([]byte("decoy")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
		if err := probeAlive(client); err == nil {
			t.Fatal("conn with pending data must be stale")
		}
	})

	t.Run("closed", func(t *testing.T) {
		client, server := tcpPair(t)
		_ = server.Close()
		time.Sleep(50 * time.Millisecond)
		if err := probeAlive(client); err == nil {
			t.Fatal("conn with closed peer must be stale")
		}
	})

	t.Run("reset", func(t *testing.T) {
		client, server := tcpPair(t)
		if tcp, ok := server.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		_ = server.Close()
		time.Sleep(50 * time.Millisecond)
		if err := probeAlive(client); err == nil {
			t.Fatal("conn with reset peer must be stale")
		}
	})
}

func TestClaimStartFailureDiscardsConn(t *testing.T) {
	n := &fakeNode{start: func(context.Context, net.Conn, core.Target) error {
		return errors.New("write failed")
	}}
	p, err := New([]Node{n.spec("n1")}, Options{MaxIdle: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	injectIdle(p, "n1", client, time.Now())

	if _, ok := p.Claim(context.Background(), "n1", core.Target{Host: "example.com", Port: 443}); ok {
		t.Fatal("claim must fail when start fails")
	}
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := server.Read(make([]byte, 1)); err == nil {
		t.Fatal("conn should be closed after start failure")
	}
	_ = server.Close()
}

func TestDisabledPoolDoesNothing(t *testing.T) {
	n := &fakeNode{}
	p, err := New([]Node{n.spec("n1")}, Options{MaxIdle: 0})
	if err != nil {
		t.Fatal(err)
	}
	if p.Enabled() {
		t.Fatal("pool with MaxIdle=0 should be disabled")
	}
	p.Start(context.Background())
	if _, ok := p.Claim(context.Background(), "n1", core.Target{Host: "example.com", Port: 443}); ok {
		t.Fatal("disabled pool must not claim")
	}
	time.Sleep(20 * time.Millisecond)
	if got := n.dials.Load(); got != 0 {
		t.Fatalf("disabled pool dialed %d times", got)
	}
	p.Close()
	p.Close() // 重复关闭应安全
}

func TestCloseClosesIdleConns(t *testing.T) {
	n := &fakeNode{}
	p, err := New([]Node{n.spec("n1")}, Options{MaxIdle: 1})
	if err != nil {
		t.Fatal(err)
	}
	p.Start(context.Background())
	waitIdle(t, p, "n1", 1)

	p.Close()
	peer := n.lastPeer(t)
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle conn should be closed by Close")
	}
	if got := p.IdleCounts()["n1"]; got != 0 {
		t.Fatalf("idle = %d after Close, want 0", got)
	}
	if _, ok := p.Claim(context.Background(), "n1", core.Target{Host: "example.com", Port: 443}); ok {
		t.Fatal("closed pool must not claim")
	}
	p.Close()
}

func TestPruneKeepsFreshConns(t *testing.T) {
	clock := newFakeClock()
	n := &fakeNode{}
	p, err := New([]Node{n.spec("n1")}, Options{MaxIdle: 2, IdleTTL: time.Second, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)

	fresh, freshPeer := net.Pipe()
	stale, stalePeer := net.Pipe()
	t.Cleanup(func() {
		_ = fresh.Close()
		_ = freshPeer.Close()
		_ = stale.Close()
		_ = stalePeer.Close()
	})
	injectIdle(p, "n1", fresh, clock.Now())
	injectIdle(p, "n1", stale, clock.Now().Add(-2*time.Second))

	p.prune()
	if got := p.IdleCounts()["n1"]; got != 1 {
		t.Fatalf("idle = %d after prune, want 1", got)
	}
	_ = stalePeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := stalePeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("expired conn should be closed by prune")
	}
	if _, ok := p.Claim(context.Background(), "n1", core.Target{Host: "example.com", Port: 443}); !ok {
		t.Fatal("fresh conn should still be claimable")
	}
}

func TestConcurrentClaims(t *testing.T) {
	n := &fakeNode{}
	m := metrics.New()
	const maxIdle = 4
	p, err := New([]Node{n.spec("n1")}, Options{MaxIdle: maxIdle, Metrics: m})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	p.Start(context.Background())

	const workers = 8
	const perWorker = 20
	var hits, misses atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				conn, ok := p.Claim(context.Background(), "n1", core.Target{Host: "example.com", Port: 443})
				if ok {
					hits.Add(1)
					_ = conn.Close()
				} else {
					misses.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	total := int64(workers * perWorker)
	if got := hits.Load() + misses.Load(); got != total {
		t.Fatalf("hits+misses = %d, want %d", got, total)
	}
	if got := p.IdleCounts()["n1"]; got > maxIdle {
		t.Fatalf("idle = %d, exceeds MaxIdle = %d", got, maxIdle)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(nil, Options{}); err == nil {
		t.Fatal("empty node list should fail")
	}
	dup := []Node{
		{Addr: "n1", Dial: func(context.Context) (net.Conn, error) { return nil, nil }, Start: func(context.Context, net.Conn, core.Target) error { return nil }},
		{Addr: "n1", Dial: func(context.Context) (net.Conn, error) { return nil, nil }, Start: func(context.Context, net.Conn, core.Target) error { return nil }},
	}
	if _, err := New(dup, Options{}); err == nil {
		t.Fatal("duplicate addr should fail")
	}
	if _, err := New([]Node{{Addr: "n1"}}, Options{}); err == nil {
		t.Fatal("missing dial/start funcs should fail")
	}
}

func TestDropNodeClosesIdleConnsAndPausesRefill(t *testing.T) {
	m := metrics.New()
	n1, n2 := &fakeNode{}, &fakeNode{}
	p, err := New([]Node{n1.spec("n1"), n2.spec("n2")}, Options{MaxIdle: 2, IdleTTL: time.Minute, Metrics: m})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	p.Start(context.Background())
	waitIdle(t, p, "n1", 2)
	waitIdle(t, p, "n2", 2)

	p.DropNode("n1")
	if got := p.IdleCounts()["n1"]; got != 0 {
		t.Fatalf("idle[n1] = %d, want 0（摘除后应清空）", got)
	}
	if got := p.IdleCounts()["n2"]; got != 2 {
		t.Fatalf("idle[n2] = %d, want 2（不受其他节点影响）", got)
	}
	// 已入池的连接应被实际关闭：对端读到 EOF/错误。
	n1.mu.Lock()
	peers := append([]net.Conn(nil), n1.peers...)
	n1.mu.Unlock()
	if len(peers) == 0 {
		t.Fatal("n1 should have dialed connections")
	}
	for _, peer := range peers {
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := peer.Read(make([]byte, 1)); err == nil {
			t.Fatal("dropped idle conn should be closed")
		}
	}

	// 摘除期间（无真实领取）不补池。
	time.Sleep(50 * time.Millisecond)
	if got := p.IdleCounts()["n1"]; got != 0 {
		t.Fatalf("idle[n1] = %d, want 0（暂停补池期间不应回升）", got)
	}
	if !strings.Contains(metricsText(t, m), `upstream_pool_idle_connections{node="n1"} 0`) {
		t.Fatalf("idle gauge should be 0 after drop:\n%s", metricsText(t, m))
	}

	// 节点加回后收到真实领取：首次 miss（回退新建），随后自动恢复预热。
	if _, ok := p.Claim(context.Background(), "n1", core.Target{Host: "example.com", Port: 443}); ok {
		t.Fatal("claim should miss right after drop")
	}
	waitIdle(t, p, "n1", 2)

	// 未知节点与 nil 接收者安全。
	p.DropNode("unknown")
	var nilPool *Pool
	nilPool.DropNode("n1")
}

// BenchmarkClaimHit 测量一次“领取成功”的固定开销：存活探测（即时检查 +
// 一个探测窗口复核，健康连接上约等于 probeWindow）与 Trojan 请求写入。
// 用少量真实 TCP 连接循环注入 / 领取，替代逐次新建连接（会耗尽临时端口）。
func BenchmarkClaimHit(b *testing.B) {
	n := &fakeNode{}
	p, err := New([]Node{n.spec("n1")}, Options{MaxIdle: 1, IdleTTL: time.Hour})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(p.Close)

	const ring = 64
	conns := make([]net.Conn, 0, ring)
	for i := 0; i < ring; i++ {
		client, _ := tcpPair(b)
		conns = append(conns, client)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		injectIdle(p, "n1", conns[i%ring], p.opts.Now())
		conn, ok := p.Claim(context.Background(), "n1", core.Target{Host: "example.com", Port: 443})
		if !ok {
			b.Fatal("claim miss in benchmark")
		}
		_ = conn
	}
}
