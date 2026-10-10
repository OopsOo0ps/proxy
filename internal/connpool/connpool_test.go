package connpool

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	start  func(conn net.Conn, host string, port uint16) error
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

func (n *fakeNode) startRequest(conn net.Conn, host string, port uint16) error {
	if n.start != nil {
		return n.start(conn, host, port)
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
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
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
		conn, ok := p.Claim(context.Background(), "n1", "example.com", 443)
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

	if _, ok := p.Claim(context.Background(), "n1", "example.com", 443); ok {
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

	if _, ok := p.Claim(context.Background(), "n1", "example.com", 443); ok {
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

	if _, ok := p.Claim(context.Background(), "n1", "example.com", 443); ok {
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

	if _, ok := p.Claim(context.Background(), "n1", "example.com", 443); ok {
		t.Fatal("conn with pending data must not be claimed")
	}
}

func TestClaimStartFailureDiscardsConn(t *testing.T) {
	n := &fakeNode{start: func(net.Conn, string, uint16) error {
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

	if _, ok := p.Claim(context.Background(), "n1", "example.com", 443); ok {
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
	if _, ok := p.Claim(context.Background(), "n1", "example.com", 443); ok {
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
	if _, ok := p.Claim(context.Background(), "n1", "example.com", 443); ok {
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
	if _, ok := p.Claim(context.Background(), "n1", "example.com", 443); !ok {
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
				conn, ok := p.Claim(context.Background(), "n1", "example.com", 443)
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
		{Addr: "n1", Dial: func(context.Context) (net.Conn, error) { return nil, nil }, Start: func(net.Conn, string, uint16) error { return nil }},
		{Addr: "n1", Dial: func(context.Context) (net.Conn, error) { return nil, nil }, Start: func(net.Conn, string, uint16) error { return nil }},
	}
	if _, err := New(dup, Options{}); err == nil {
		t.Fatal("duplicate addr should fail")
	}
	if _, err := New([]Node{{Addr: "n1"}}, Options{}); err == nil {
		t.Fatal("missing dial/start funcs should fail")
	}
}

// BenchmarkClaimHit 测量一次“领取成功”的固定开销：首先是存活探测
// （等待探测窗口，健康连接上无数据即超时），其次是 Trojan 请求写入。
// 使用内存管道、超长 TTL，结果即为领取路径的下限（约等于 probeWindow）。
func BenchmarkClaimHit(b *testing.B) {
	n := &fakeNode{}
	p, err := New([]Node{n.spec("n1")}, Options{MaxIdle: 1, IdleTTL: time.Hour})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(p.Close)

	// 预备 b.N 条空闲连接（不启动后台任务，避免补池干扰计时）。
	for i := 0; i < b.N; i++ {
		client, _ := net.Pipe()
		injectIdle(p, "n1", client, p.opts.Now())
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, ok := p.Claim(context.Background(), "n1", "example.com", 443)
		if !ok {
			b.Fatal("claim miss in benchmark")
		}
		_ = conn
	}
}
