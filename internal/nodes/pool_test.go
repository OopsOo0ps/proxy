package nodes

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/core"
)

// nopConn 是最小的 net.Conn 实现，仅用于测试。
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
// 池逻辑通过注入的 DialFunc/ProbeFunc 工作自身不调用传输。
type stubTransport struct{}

func (stubTransport) DialTunnel(context.Context, core.Target) (net.Conn, error) {
	return nil, errors.New("stub transport: dial tunnel not implemented")
}

func testNodes() []Node {
	return []Node{
		{Addr: "node1.example.com:443", Transport: stubTransport{}},
		{Addr: "node2.example.com:443", Transport: stubTransport{}},
		{Addr: "node3.example.com:443", Transport: stubTransport{}},
	}
}

// recorder 记录每个节点的拨号次数与给定错误。
type recorder struct {
	mu    sync.Mutex
	calls map[string]int
	errs  map[string]error
}

func newRecorder() *recorder {
	return &recorder{calls: map[string]int{}, errs: map[string]error{}}
}

func (r *recorder) dial(_ context.Context, node Node, _ core.Target) (net.Conn, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls[node.Addr]++
	if err := r.errs[node.Addr]; err != nil {
		return nil, err
	}
	return nopConn{}, nil
}

func (r *recorder) callsFor(addr string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[addr]
}

func (r *recorder) setErr(addr string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs[addr] = err
}

// blockingDial 返回一个拨号函数：每次调用计数并阻塞到上下文结束，
// 模拟“TCP 可连但始终不完成握手”的半死节点。
func blockingDial() (DialFunc, func() int) {
	var calls atomic.Int64
	dial := func(ctx context.Context, _ Node, _ core.Target) (net.Conn, error) {
		calls.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return dial, func() int { return int(calls.Load()) }
}

func TestDialFailoverBudgetExhausted(t *testing.T) {
	dial, calls := blockingDial()
	pool, err := New(testNodes(), dial, Options{FailoverBudget: 150 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, _, err = pool.Dial(context.Background(), core.Target{Host: "example.com", Port: 443})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("dial must fail when the failover budget expires")
	}
	if !strings.Contains(err.Error(), "failover budget") {
		t.Fatalf("err = %v, want failover budget annotation", err)
	}
	if elapsed < 100*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("elapsed = %v, want ≈150ms (budget)", elapsed)
	}
	if got := calls(); got != 1 {
		t.Fatalf("attempts = %d, want 1: the chain must stop at the budget", got)
	}
	// 预算中断不是节点自身的错误：不得把节点送入被动冷却。
	for _, st := range pool.Snapshot() {
		if st.Fails != 0 {
			t.Fatalf("node %s fails = %d, want 0 (budget abort must not cool down nodes)", st.Addr, st.Fails)
		}
	}
}

func TestDialParentDeadlineBeatsBudget(t *testing.T) {
	dial, calls := blockingDial()
	pool, err := New(testNodes(), dial, Options{FailoverBudget: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err = pool.Dial(ctx, core.Target{Host: "example.com", Port: 443})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("dial must fail when the caller context expires first")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context deadline exceeded", err)
	}
	if strings.Contains(err.Error(), "failover budget") {
		t.Fatalf("err = %v: caller deadline must not be labeled as the failover budget", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("elapsed = %v, want ≈100ms (caller deadline)", elapsed)
	}
	if got := calls(); got != 1 {
		t.Fatalf("attempts = %d, want 1", got)
	}
}

func TestDialFailoverBudgetDoesNotBlockFailover(t *testing.T) {
	rec := newRecorder()
	rec.setErr("node1.example.com:443", errors.New("refused"))
	pool, err := New(testNodes(), rec.dial, Options{FailoverBudget: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	_, node, err := pool.Dial(context.Background(), core.Target{Host: "example.com", Port: 443})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if node.Addr != "node2.example.com:443" {
		t.Fatalf("node = %s, want node2 (first candidate failed)", node.Addr)
	}
	if got := rec.callsFor("node1.example.com:443"); got != 1 {
		t.Fatalf("node1 attempts = %d, want 1", got)
	}
}

func TestRoundRobinUsesAllNodes(t *testing.T) {
	rec := newRecorder()
	pool, err := New(testNodes(), rec.dial, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, _, err := pool.Dial(context.Background(), core.Target{Host: "example.com", Port: 443}); err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
	}
	for _, n := range testNodes() {
		if got := rec.callsFor(n.Addr); got != 2 {
			t.Fatalf("node %s calls = %d, want 2（轮询应均匀）", n.Addr, got)
		}
	}
	if pool.Len() != 3 {
		t.Fatalf("Len = %d, want 3", pool.Len())
	}
}

func TestFailoverToNextNode(t *testing.T) {
	rec := newRecorder()
	rec.setErr("node1.example.com:443", errors.New("connection refused"))
	pool, err := New(testNodes(), rec.dial, Options{})
	if err != nil {
		t.Fatal(err)
	}

	_, node, err := pool.Dial(context.Background(), core.Target{Host: "example.com", Port: 443})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if node.Addr != "node2.example.com:443" {
		t.Fatalf("selected %s, want node2（node1 失败后应转移）", node.Addr)
	}
	if rec.callsFor("node1.example.com:443") != 1 {
		t.Fatal("node1 should be attempted once")
	}
}

func TestCooldownSkipsFailedNode(t *testing.T) {
	rec := newRecorder()
	rec.setErr("node1.example.com:443", errors.New("boom"))

	now := time.Now()
	clock := func() time.Time { return now }
	pool, err := New(testNodes(), rec.dial, Options{Cooldown: 30 * time.Second, Now: clock})
	if err != nil {
		t.Fatal(err)
	}

	// 第一次拨号会尝试 node1（失败）然后 node2（成功）。
	if _, _, err := pool.Dial(context.Background(), core.Target{Host: "example.com", Port: 443}); err != nil {
		t.Fatal(err)
	}
	node1Calls := rec.callsFor("node1.example.com:443")

	// 冷却期内多次拨号不应再触碰 node1。
	for i := 0; i < 3; i++ {
		if _, _, err := pool.Dial(context.Background(), core.Target{Host: "example.com", Port: 443}); err != nil {
			t.Fatal(err)
		}
	}
	if got := rec.callsFor("node1.example.com:443"); got != node1Calls {
		t.Fatalf("node1 calls during cooldown = %d, want %d", got, node1Calls)
	}

	// 冷却结束后节点恢复可尝试：清除故障并轮询若干次，应再次命中 node1。
	rec.setErr("node1.example.com:443", nil)
	now = now.Add(31 * time.Second)
	retried := false
	for i := 0; i < 4 && !retried; i++ {
		if _, _, err := pool.Dial(context.Background(), core.Target{Host: "example.com", Port: 443}); err != nil {
			t.Fatal(err)
		}
		retried = rec.callsFor("node1.example.com:443") > node1Calls
	}
	if !retried {
		t.Fatal("node1 should become eligible again after cooldown")
	}
}

func TestCooldownBackoffCaps(t *testing.T) {
	pool, err := New(testNodes(), newRecorder().dial, Options{Cooldown: 10 * time.Second, MaxCooldown: 25 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		fails int
		want  time.Duration
	}{
		{1, 10 * time.Second},
		{2, 20 * time.Second},
		{3, 25 * time.Second},
		{10, 25 * time.Second},
	}
	for _, tc := range cases {
		if got := pool.cooldownFor(tc.fails); got != tc.want {
			t.Fatalf("cooldownFor(%d) = %v, want %v", tc.fails, got, tc.want)
		}
	}
}

func TestAllNodesCoolingStillAttempted(t *testing.T) {
	rec := newRecorder()
	for _, n := range testNodes() {
		rec.setErr(n.Addr, errors.New("down"))
	}
	now := time.Now()
	pool, err := New(testNodes(), rec.dial, Options{Cooldown: time.Minute, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}

	// 第一轮：全部失败并进入冷却。
	if _, _, err := pool.Dial(context.Background(), core.Target{Host: "example.com", Port: 443}); err == nil {
		t.Fatal("expected failure")
	}
	// 第二轮（全部冷却中）：仍应全量尝试，避免永久黑洞。
	if _, _, err := pool.Dial(context.Background(), core.Target{Host: "example.com", Port: 443}); err == nil {
		t.Fatal("expected failure")
	}
	for _, n := range testNodes() {
		if got := rec.callsFor(n.Addr); got != 2 {
			t.Fatalf("node %s calls = %d, want 2", n.Addr, got)
		}
	}
}

func TestAllFailReturnsAggregatedError(t *testing.T) {
	rec := newRecorder()
	for _, n := range testNodes() {
		rec.setErr(n.Addr, errors.New("down"))
	}
	pool, err := New(testNodes(), rec.dial, Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = pool.Dial(context.Background(), core.Target{Host: "example.com", Port: 443})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "all exit nodes failed") {
		t.Fatalf("err = %v", err)
	}
	for _, n := range testNodes() {
		if !strings.Contains(err.Error(), n.Addr) {
			t.Fatalf("error should mention %s: %v", n.Addr, err)
		}
	}
}

func TestContextCancelStopsDialing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rec := newRecorder()
	pool, err := New(testNodes(), rec.dial, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := pool.Dial(ctx, core.Target{Host: "example.com", Port: 443}); err == nil {
		t.Fatal("expected error for canceled context")
	}
}

func TestNewValidation(t *testing.T) {
	dial := newRecorder().dial
	if _, err := New(nil, dial, Options{}); err == nil {
		t.Fatal("empty nodes should be rejected")
	}
	// dial 为 nil 是合法输入：回退路径默认走节点传输的 DialTunnel
	//（预热池收归本包后，组装根不再需要传拨号闭包，见 prewarm_test.go）。
	if _, err := New(testNodes(), nil, Options{}); err != nil {
		t.Fatalf("nil dial should default to the node transport: %v", err)
	}
	if _, err := New([]Node{{Addr: "no-port", Transport: stubTransport{}}}, dial, Options{}); err == nil {
		t.Fatal("bad addr should be rejected")
	}
	// 口令非空等协议参数校验已随节点去协议化移出本包：
	// 归 config 校验与协议传输构造器（internal/trojan.NewTransport）。
	if _, err := New([]Node{{Addr: "n.example.com:443"}}, dial, Options{}); err == nil {
		t.Fatal("nil transport should be rejected")
	}
}

func TestSnapshotReflectsFailuresAndCooldown(t *testing.T) {
	rec := newRecorder()
	rec.setErr("node1.example.com:443", errors.New("boom"))

	now := time.Now()
	clock := func() time.Time { return now }
	pool, err := New(testNodes(), rec.dial, Options{Cooldown: 30 * time.Second, Now: clock})
	if err != nil {
		t.Fatal(err)
	}

	// 初始：全部健康，无失败记录。
	snap := pool.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("snapshot len = %d, want 3", len(snap))
	}
	for _, n := range snap {
		if !n.Healthy || n.Fails != 0 || n.CooldownRemaining != 0 {
			t.Fatalf("initial snapshot = %+v, want 健康且无失败", n)
		}
	}
	if !pool.AnyHealthy() {
		t.Fatal("初始应存在健康节点")
	}

	// 一次拨号：node1 失败进入冷却（随后 node2 成功）。
	if _, _, err := pool.Dial(context.Background(), core.Target{Host: "example.com", Port: 443}); err != nil {
		t.Fatalf("dial: %v", err)
	}
	snap = pool.Snapshot()
	byAddr := map[string]Status{}
	for _, n := range snap {
		byAddr[n.Addr] = n
	}
	n1 := byAddr["node1.example.com:443"]
	if n1.Healthy || n1.Fails != 1 || n1.CooldownRemaining != 30*time.Second {
		t.Fatalf("node1 snapshot = %+v, want 冷却中（30s，1 次失败）", n1)
	}
	if n2 := byAddr["node2.example.com:443"]; !n2.Healthy {
		t.Fatalf("node2 snapshot = %+v, want 健康", n2)
	}
	if !pool.AnyHealthy() {
		t.Fatal("node2 健康时应报告存在可用节点")
	}

	// 冷却到期后视为健康。
	now = now.Add(31 * time.Second)
	if n1 := pool.Snapshot()[0]; !n1.Healthy || n1.CooldownRemaining != 0 {
		t.Fatalf("冷却到期后 snapshot = %+v, want 健康", n1)
	}
}

func TestAnyHealthyFalseWhenAllNodesCooling(t *testing.T) {
	rec := newRecorder()
	for _, n := range testNodes() {
		rec.setErr(n.Addr, errors.New("down"))
	}
	pool, err := New(testNodes(), rec.dial, Options{Cooldown: time.Minute})
	if err != nil {
		t.Fatal(err)
	}

	// 全部节点拨号失败后进入冷却。
	if _, _, err := pool.Dial(context.Background(), core.Target{Host: "example.com", Port: 443}); err == nil {
		t.Fatal("expected dial error")
	}
	if pool.AnyHealthy() {
		t.Fatal("全部节点冷却时应报告无健康节点")
	}
	for _, n := range pool.Snapshot() {
		if n.Healthy || n.Fails != 1 || n.CooldownRemaining <= 0 {
			t.Fatalf("snapshot = %+v, want 全部冷却", n)
		}
	}
}

// findState 返回指定地址的内部状态（同包测试内省用）。
func findState(t *testing.T, p *Pool, addr string) *state {
	t.Helper()
	for _, st := range p.nodes {
		if st.cfg.Addr == addr {
			return st
		}
	}
	t.Fatalf("state for %s not found", addr)
	return nil
}

// snapshotFor 返回指定地址节点的状态快照。
func snapshotFor(t *testing.T, p *Pool, addr string) Status {
	t.Helper()
	for _, snap := range p.Snapshot() {
		if snap.Addr == addr {
			return snap
		}
	}
	t.Fatalf("snapshot for %s not found", addr)
	return Status{}
}

// waitFor 轮询等待条件成立（测试辅助）。
func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within deadline")
}

func TestHealthCheckRemovesThenRejoins(t *testing.T) {
	rec := newRecorder()
	rec.setErr("node1.example.com:443", errors.New("connection refused"))
	var removals, rejoins []string
	pool, err := New(testNodes(), rec.dial, Options{
		Health: HealthOptions{Interval: time.Minute, Timeout: time.Second, Failures: 2, Successes: 2},
		Probe:  func(context.Context, Node) error { return nil }, // 本用例手动驱动，不启动探测循环
		OnRemove: func(addr string) {
			removals = append(removals, addr)
		},
		OnRejoin: func(addr string) {
			rejoins = append(rejoins, addr)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	// 先用一次真实拨号失败制造被动冷却（node1 fails=1 且处于冷却中）。
	if _, _, err := pool.Dial(context.Background(), core.Target{Host: "example.com", Port: 443}); err != nil {
		t.Fatalf("dial: %v", err)
	}
	rec.setErr("node1.example.com:443", nil)
	st := findState(t, pool, "node1.example.com:443")
	probeErr := errors.New("tls handshake failed")

	// 第 1 次探测失败：未达阈值，节点未被摘除。
	pool.recordProbe(st, probeErr)
	if snap := snapshotFor(t, pool, "node1.example.com:443"); snap.Removed || snap.ProbeFails != 1 {
		t.Fatalf("snapshot after 1 probe failure = %+v, want 未摘除且探测失败 1 次", snap)
	}

	// 第 2 次探测失败：摘除（硬摘除，拨号不再经过它）。
	pool.recordProbe(st, probeErr)
	if snap := snapshotFor(t, pool, "node1.example.com:443"); !snap.Removed || snap.Healthy {
		t.Fatalf("snapshot after removal = %+v, want 已摘除", snap)
	}
	before := rec.callsFor("node1.example.com:443")
	for i := 0; i < 6; i++ {
		if _, _, err := pool.Dial(context.Background(), core.Target{Host: "example.com", Port: 443}); err != nil {
			t.Fatalf("dial %d after removal: %v", i, err)
		}
	}
	if got := rec.callsFor("node1.example.com:443"); got != before {
		t.Fatalf("removed node dialed %d times, want %d（摘除后不应参与拨号）", got, before)
	}
	if len(removals) != 1 || removals[0] != "node1.example.com:443" {
		t.Fatalf("OnRemove calls = %v, want 1 次 node1", removals)
	}

	// 恢复：单个成功不够（要求连续 2 次）。
	pool.recordProbe(st, nil)
	if snap := snapshotFor(t, pool, "node1.example.com:443"); !snap.Removed {
		t.Fatalf("snapshot after 1 success = %+v, want 仍摘除", snap)
	}
	pool.recordProbe(st, nil)
	snap := snapshotFor(t, pool, "node1.example.com:443")
	if snap.Removed || !snap.Healthy || snap.Fails != 0 || snap.CooldownRemaining != 0 || snap.ProbeFails != 0 {
		t.Fatalf("snapshot after rejoin = %+v, want 已加回且被动状态清零", snap)
	}
	if len(rejoins) != 1 || rejoins[0] != "node1.example.com:443" {
		t.Fatalf("OnRejoin calls = %v, want 1 次 node1", rejoins)
	}

	// 加回后重新参与轮询。
	before = rec.callsFor("node1.example.com:443")
	used := false
	for i := 0; i < 3; i++ {
		if _, _, err := pool.Dial(context.Background(), core.Target{Host: "example.com", Port: 443}); err != nil {
			t.Fatalf("dial %d after rejoin: %v", i, err)
		}
		if rec.callsFor("node1.example.com:443") > before {
			used = true
		}
	}
	if !used {
		t.Fatal("rejoined node should serve traffic again")
	}
}

func TestHealthCheckRecoveryRequiresConsecutiveSuccesses(t *testing.T) {
	rec := newRecorder()
	var removals int
	pool, err := New(testNodes(), rec.dial, Options{
		Health:   HealthOptions{Interval: time.Minute, Timeout: time.Second, Failures: 1, Successes: 2},
		Probe:    func(context.Context, Node) error { return nil },
		OnRemove: func(string) { removals++ },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	st := findState(t, pool, "node1.example.com:443")
	pool.recordProbe(st, errors.New("down"))
	if !snapshotFor(t, pool, "node1.example.com:443").Removed {
		t.Fatal("node1 should be removed after 1 failure (failures=1)")
	}

	// 成功、失败、成功：连续成功被失败打断，不应加回。
	pool.recordProbe(st, nil)
	pool.recordProbe(st, errors.New("down"))
	pool.recordProbe(st, nil)
	if snap := snapshotFor(t, pool, "node1.example.com:443"); !snap.Removed {
		t.Fatalf("snapshot = %+v, want 仍摘除（成功需连续）", snap)
	}

	// 再来一次成功：连续 2 次，加回。
	pool.recordProbe(st, nil)
	if snap := snapshotFor(t, pool, "node1.example.com:443"); snap.Removed {
		t.Fatalf("snapshot = %+v, want 已加回", snap)
	}
	// 已摘除状态下继续失败不应重复触发 OnRemove。
	if removals != 1 {
		t.Fatalf("OnRemove calls = %d, want 1", removals)
	}
}

func TestHealthCheckAllRemovedFailsFast(t *testing.T) {
	rec := newRecorder()
	pool, err := New(testNodes(), rec.dial, Options{
		Health: HealthOptions{Interval: time.Minute, Timeout: time.Second, Failures: 1, Successes: 1},
		Probe:  func(context.Context, Node) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	probeErr := errors.New("down")
	for _, st := range pool.nodes {
		pool.recordProbe(st, probeErr)
	}
	if pool.AnyHealthy() {
		t.Fatal("全部节点被摘除时应报告无健康节点")
	}
	for _, snap := range pool.Snapshot() {
		if !snap.Removed || snap.Healthy {
			t.Fatalf("snapshot = %+v, want 全部摘除", snap)
		}
	}
	if _, _, err := pool.Dial(context.Background(), core.Target{Host: "example.com", Port: 443}); !errors.Is(err, ErrNoHealthyNodes) {
		t.Fatalf("Dial error = %v, want ErrNoHealthyNodes", err)
	}
	for _, n := range testNodes() {
		if got := rec.callsFor(n.Addr); got != 0 {
			t.Fatalf("node %s dialed %d times, want 0（全部摘除后应快速失败）", n.Addr, got)
		}
	}
}

func TestHealthCheckLoopRemovesAndRejoins(t *testing.T) {
	rec := newRecorder()
	var failing atomic.Bool
	failing.Store(true)
	var probes atomic.Int64
	pool, err := New(testNodes(), rec.dial, Options{
		Health: HealthOptions{Interval: 5 * time.Millisecond, Timeout: 50 * time.Millisecond, Failures: 2, Successes: 2},
		Probe: func(context.Context, Node) error {
			probes.Add(1)
			if failing.Load() {
				return errors.New("probe failed")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		pool.Close()
	})

	pool.StartHealthChecks(ctx)
	waitFor(t, 3*time.Second, func() bool { return !pool.AnyHealthy() })
	for _, snap := range pool.Snapshot() {
		if !snap.Removed {
			t.Fatalf("snapshot = %+v, want 探测循环连续失败后全部摘除", snap)
		}
	}

	// 节点恢复：探测循环应自动加回。
	failing.Store(false)
	waitFor(t, 3*time.Second, func() bool {
		for _, snap := range pool.Snapshot() {
			if snap.Removed {
				return false
			}
		}
		return pool.AnyHealthy()
	})
	for _, snap := range pool.Snapshot() {
		if snap.Removed || !snap.Healthy {
			t.Fatalf("snapshot = %+v, want 全部加回", snap)
		}
	}
	if probes.Load() == 0 {
		t.Fatal("probe func should be called by the health loop")
	}

	// 重复启动应幂等（不 panic、不重复建循环）。
	pool.StartHealthChecks(ctx)
}

func TestHealthCheckDisabledWithoutInterval(t *testing.T) {
	var probes atomic.Int64
	pool, err := New(testNodes(), newRecorder().dial, Options{
		Health: HealthOptions{Interval: 0},
		Probe: func(context.Context, Node) error {
			probes.Add(1)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool.StartHealthChecks(ctx)
	time.Sleep(30 * time.Millisecond)
	if got := probes.Load(); got != 0 {
		t.Fatalf("probes = %d, want 0（未配置 interval 时不应探测）", got)
	}
	pool.Close()

	var nilPool *Pool
	nilPool.Close() // 应安全
}

// TestCloseWaitsForInFlightProbe 钉住 Close 的排空语义：Close 返回前会等待
// 在途探测退出，且取消后的探测结果不再落账。热加载替换运行时依赖这一保证
// （新配置生效后，旧循环不会再有迟到的结果改变健康状态或计数）。
func TestCloseWaitsForInFlightProbe(t *testing.T) {
	probeStarted := make(chan struct{})
	releaseProbe := make(chan struct{})
	var once sync.Once
	pool, err := New(testNodes()[:1], newRecorder().dial, Options{
		Health: HealthOptions{Interval: time.Hour, Timeout: time.Minute, Failures: 1, Successes: 1},
		Probe: func(context.Context, Node) error {
			once.Do(func() { close(probeStarted) })
			<-releaseProbe
			return errors.New("probe failed")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool.StartHealthChecks(ctx)
	select {
	case <-probeStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("probe did not start")
	}

	closed := make(chan struct{})
	go func() {
		pool.Close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("Close returned while a probe was still in flight")
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseProbe)
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not return after the in-flight probe finished")
	}

	// Close 返回后不得再落账：被取消的探测结果按非故障丢弃，状态保持初始。
	before := pool.Snapshot()
	if len(before) != 1 || before[0].ProbeFails != 0 || before[0].Removed {
		t.Fatalf("probe result leaked past Close: %+v", before)
	}
	time.Sleep(100 * time.Millisecond)
	if after := pool.Snapshot(); after[0] != before[0] {
		t.Fatalf("health state changed after Close: %+v -> %+v", before[0], after[0])
	}
}

func TestNewRequiresProbeWhenHealthCheckEnabled(t *testing.T) {
	_, err := New(testNodes(), newRecorder().dial, Options{Health: HealthOptions{Interval: time.Second}})
	if err == nil {
		t.Fatal("expected error when health check is enabled without a probe func")
	}
	if !strings.Contains(err.Error(), "probe func") {
		t.Fatalf("error = %v, want 提及 probe func", err)
	}
}

// TestHealthCheckLoopSurvivesGenerationCancel 钉住 B-1 契约：探测循环绑定
// 首次 Start 传入的应用级 ctx，寿命由 Close 终结——代际 ctx（其子 ctx）取消
// 后循环仍按周期探测（热加载复用实例的后台循环不随 gen.cancel() 停摆）；
// 重复 Start（restore 浅拷贝路径）不重建循环（首次调用生效）；Close 后计数
// 冻结。
func TestHealthCheckLoopSurvivesGenerationCancel(t *testing.T) {
	var probes atomic.Int64
	pool, err := New(testNodes()[:1], newRecorder().dial, Options{
		Health: HealthOptions{Interval: 5 * time.Millisecond, Timeout: 50 * time.Millisecond, Failures: 2, Successes: 2},
		Probe: func(context.Context, Node) error {
			probes.Add(1)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	parent := context.Background()              // 应用级 ctx（startResources 绑定它）
	gctx, gcancel := context.WithCancel(parent) // 代际 ctx
	t.Cleanup(pool.Close)

	pool.StartHealthChecks(parent)
	waitFor(t, 3*time.Second, func() bool { return probes.Load() >= 3 })

	// 代际结束：复用实例的探测循环仍继续探测。
	gcancel()
	baseline := probes.Load()
	waitFor(t, 3*time.Second, func() bool { return probes.Load() > baseline })

	// 重复 Start（restore 浅拷贝路径）：首次调用生效，不重建第二个循环——
	// 用 done 通道同一性机械固化「不重建」，用计数继续增长固化「原循环仍活」，
	// 两者合起来即计数增速不会翻倍。
	doneBefore := pool.hcDone
	pool.StartHealthChecks(gctx) // 传入已取消的代际 ctx 也必须被忽略
	if pool.hcDone != doneBefore {
		t.Fatal("重复 Start 重建了探测循环（应首次调用生效）")
	}
	more := probes.Load()
	waitFor(t, 3*time.Second, func() bool { return probes.Load() > more })

	// Close 后计数冻结。
	pool.Close()
	frozen := probes.Load()
	time.Sleep(50 * time.Millisecond)
	if got := probes.Load(); got != frozen {
		t.Fatalf("probes after Close = %d, want frozen at %d", got, frozen)
	}
}
