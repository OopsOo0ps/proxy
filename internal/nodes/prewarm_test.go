package nodes

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/outbound"
)

// prewarmTransport 是实现全部出口能力的假传输：
//   - DialTunnel / ConnectIdle 生成一对 net.Pipe（一端交给调用方/池，另一端
//     留在测试内供读写验证），connect / bind / dial 各自计数；
//   - Bind 原样交回句柄携带的连接（与真实两阶段传输的语义一致）。
//
// 预热池收归本包（§5.3：NodePool → 每节点 PrewarmPool）后的行为锚点：
// 拨号 = 预热领取命中直接用池内连接；未命中回退注入的 DialFunc（缺省为
// 节点传输的 DialTunnel）。
type prewarmTransport struct {
	mu       sync.Mutex
	peers    []net.Conn
	connects atomic.Int64
	binds    atomic.Int64
	dials    atomic.Int64
	bindErr  error
}

func (t *prewarmTransport) addPeer(c net.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.peers = append(t.peers, c)
}

func (t *prewarmTransport) peer(i int) net.Conn {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.peers[i]
}

func (t *prewarmTransport) DialTunnel(context.Context, core.Target) (net.Conn, error) {
	t.dials.Add(1)
	idle, peer := net.Pipe()
	t.addPeer(peer)
	return idle, nil
}

// idleHandle 把 net.Pipe 连接包装成两阶段句柄（Discard 即关闭连接，
// 与真实传输释放空闲隧道的语义一致）。
type idleHandle struct{ net.Conn }

func (h idleHandle) Discard() { _ = h.Close() }

func (t *prewarmTransport) ConnectIdle(ctx context.Context) (outbound.Prepared, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	t.connects.Add(1)
	idle, peer := net.Pipe()
	t.addPeer(peer)
	return idleHandle{Conn: idle}, nil
}

func (t *prewarmTransport) Bind(ctx context.Context, p outbound.Prepared, _ core.Target) (net.Conn, error) {
	t.binds.Add(1)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if t.bindErr != nil {
		return nil, t.bindErr
	}
	conn, ok := p.(net.Conn)
	if !ok {
		return nil, errors.New("prewarm test: handle does not carry a connection")
	}
	return conn, nil
}

// pipeRoundTrip 验证一条 net.Pipe 连接可双向通行：写入 payload 并从对端读回
// （net.Pipe 是同步管道，写协程由对端 Read 解锁）。
func pipeRoundTrip(t *testing.T, conn net.Conn, peer net.Conn, payload string) {
	t.Helper()
	go func() { _, _ = conn.Write([]byte(payload)) }()
	got := make([]byte, len(payload))
	_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := peer.Read(got); err != nil {
		t.Fatalf("read from peer: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("round trip = %q, want %q", got, payload)
	}
}

// TestPrewarmClaimHitServesDial 预热领取命中：DialTarget 直接用池内连接
// 补发绑定后返回，不回退节点拨号，且连接可双向通行。
func TestPrewarmClaimHitServesDial(t *testing.T) {
	tr := &prewarmTransport{}
	rec := newRecorder()
	pool, err := New(
		[]Node{{Addr: "n1.example.com:443", Transport: tr}},
		rec.dial,
		Options{Prewarm: PrewarmOptions{Size: 1, TTL: time.Minute}},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	pool.Start(context.Background())

	waitFor(t, 3*time.Second, func() bool {
		return pool.IdleCounts()["n1.example.com:443"] == 1
	})

	conn, route, err := pool.DialTarget(context.Background(), core.Target{Host: "example.com", Port: 443})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if route.Action != core.RouteProxy || route.Label != "n1.example.com:443" {
		t.Fatalf("route = %+v, want proxy/n1.example.com:443", route)
	}
	if got := rec.callsFor("n1.example.com:443"); got != 0 {
		t.Fatalf("fallback dial called %d times, want 0（预热命中不回退）", got)
	}
	if tr.binds.Load() != 1 {
		t.Fatalf("binds = %d, want 1（领取时补发绑定）", tr.binds.Load())
	}
	pipeRoundTrip(t, conn, tr.peer(0), "prewarm-hit")
}

// TestPrewarmMissFallsBackToDial 预热未命中（未启动补池即拨号）：
// 回退注入的节点拨号函数，行为与组装根自持预热池时等价。
func TestPrewarmMissFallsBackToDial(t *testing.T) {
	tr := &prewarmTransport{}
	rec := newRecorder()
	pool, err := New(
		[]Node{{Addr: "n1.example.com:443", Transport: tr}},
		rec.dial,
		Options{Prewarm: PrewarmOptions{Size: 1, TTL: time.Minute}},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	conn, route, err := pool.DialTarget(context.Background(), core.Target{Host: "example.com", Port: 443})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if route.Action != core.RouteProxy || route.Label != "n1.example.com:443" {
		t.Fatalf("route = %+v, want proxy/n1.example.com:443", route)
	}
	if got := rec.callsFor("n1.example.com:443"); got != 1 {
		t.Fatalf("fallback dial called %d times, want 1（未命中回退）", got)
	}
	if tr.connects.Load() != 0 {
		t.Fatalf("connects = %d, want 0（未 Start 不预热）", tr.connects.Load())
	}
}

// TestPrewarmDisabledWithoutSize 未启用预热（Size <= 0 或无 Prewarmer 节点）：
// 不建预热池，拨号恒走回退路径。
func TestPrewarmDisabledWithoutSize(t *testing.T) {
	tr := &prewarmTransport{}
	rec := newRecorder()
	pool, err := New([]Node{{Addr: "n1.example.com:443", Transport: tr}}, rec.dial, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if pool.IdleCounts() != nil {
		t.Fatalf("idle counts = %v, want nil（未启用预热）", pool.IdleCounts())
	}
	conn, _, err := pool.DialTarget(context.Background(), core.Target{Host: "example.com", Port: 443})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
	if got := rec.callsFor("n1.example.com:443"); got != 1 {
		t.Fatalf("fallback dial called %d times, want 1", got)
	}
	if tr.connects.Load() != 0 {
		t.Fatalf("connects = %d, want 0", tr.connects.Load())
	}
}

// TestNilDialFallsBackToTransport 组装根不传拨号闭包时，回退路径默认走
// 节点自身传输的 DialTunnel。
func TestNilDialFallsBackToTransport(t *testing.T) {
	tr := &prewarmTransport{}
	pool, err := New([]Node{{Addr: "n1.example.com:443", Transport: tr}}, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	conn, route, err := pool.DialTarget(context.Background(), core.Target{Host: "example.com", Port: 443})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if route.Action != core.RouteProxy || route.Label != "n1.example.com:443" {
		t.Fatalf("route = %+v, want proxy/n1.example.com:443", route)
	}
	if tr.dials.Load() != 1 {
		t.Fatalf("transport dials = %d, want 1", tr.dials.Load())
	}
	pipeRoundTrip(t, conn, tr.peer(0), "transport-fallback")
}

// TestPrewarmReleasedWhenNodeRemoved 节点被主动健康检查摘除时，其空闲
// 预热连接被同步释放（DropNode 语义随摘除进入本包）。
func TestPrewarmReleasedWhenNodeRemoved(t *testing.T) {
	tr := &prewarmTransport{}
	pool, err := New(
		[]Node{{Addr: "n1.example.com:443", Transport: tr}},
		newRecorder().dial,
		Options{
			Prewarm: PrewarmOptions{Size: 1, TTL: time.Minute},
			Health:  HealthOptions{Interval: time.Minute, Timeout: time.Second, Failures: 1, Successes: 2},
			Probe:   func(context.Context, Node) error { return nil },
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	pool.Start(context.Background())
	waitFor(t, 3*time.Second, func() bool {
		return pool.IdleCounts()["n1.example.com:443"] == 1
	})

	pool.recordProbe(findState(t, pool, "n1.example.com:443"), errors.New("down"))
	if !snapshotFor(t, pool, "n1.example.com:443").Removed {
		t.Fatal("node should be removed after 1 probe failure")
	}
	waitFor(t, 3*time.Second, func() bool {
		return pool.IdleCounts()["n1.example.com:443"] == 0
	})
	// 被释放的空闲连接应已关闭（对端读到错误而非无限挂起）。
	peer := tr.peer(0)
	_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("released idle connection should be closed")
	}
}

// TestPrewarmCloseReleasesIdle 池关闭时释放全部空闲预热连接。
func TestPrewarmCloseReleasesIdle(t *testing.T) {
	tr := &prewarmTransport{}
	pool, err := New(
		[]Node{{Addr: "n1.example.com:443", Transport: tr}},
		newRecorder().dial,
		Options{Prewarm: PrewarmOptions{Size: 2, TTL: time.Minute}},
	)
	if err != nil {
		t.Fatal(err)
	}
	pool.Start(context.Background())
	waitFor(t, 3*time.Second, func() bool {
		return pool.IdleCounts()["n1.example.com:443"] == 2
	})

	pool.Close()
	if got := pool.IdleCounts()["n1.example.com:443"]; got != 0 {
		t.Fatalf("idle after close = %d, want 0", got)
	}
}
