package nodes

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/config"
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

func testNodes() []config.Node {
	return []config.Node{
		{Addr: "node1.example.com:443", Password: "p1"},
		{Addr: "node2.example.com:443", Password: "p2"},
		{Addr: "node3.example.com:443", Password: "p3"},
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

func (r *recorder) dial(_ context.Context, node config.Node, _ string, _ uint16) (net.Conn, error) {
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

func TestRoundRobinUsesAllNodes(t *testing.T) {
	rec := newRecorder()
	pool, err := New(testNodes(), rec.dial, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, _, err := pool.Dial(context.Background(), "example.com", 443); err != nil {
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

	_, node, err := pool.Dial(context.Background(), "example.com", 443)
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
	if _, _, err := pool.Dial(context.Background(), "example.com", 443); err != nil {
		t.Fatal(err)
	}
	node1Calls := rec.callsFor("node1.example.com:443")

	// 冷却期内多次拨号不应再触碰 node1。
	for i := 0; i < 3; i++ {
		if _, _, err := pool.Dial(context.Background(), "example.com", 443); err != nil {
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
		if _, _, err := pool.Dial(context.Background(), "example.com", 443); err != nil {
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
	if _, _, err := pool.Dial(context.Background(), "example.com", 443); err == nil {
		t.Fatal("expected failure")
	}
	// 第二轮（全部冷却中）：仍应全量尝试，避免永久黑洞。
	if _, _, err := pool.Dial(context.Background(), "example.com", 443); err == nil {
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
	_, _, err = pool.Dial(context.Background(), "example.com", 443)
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
	if _, _, err := pool.Dial(ctx, "example.com", 443); err == nil {
		t.Fatal("expected error for canceled context")
	}
}

func TestNewValidation(t *testing.T) {
	dial := newRecorder().dial
	if _, err := New(nil, dial, Options{}); err == nil {
		t.Fatal("empty nodes should be rejected")
	}
	if _, err := New(testNodes(), nil, Options{}); err == nil {
		t.Fatal("nil dial should be rejected")
	}
	if _, err := New([]config.Node{{Addr: "no-port", Password: "x"}}, dial, Options{}); err == nil {
		t.Fatal("bad addr should be rejected")
	}
	if _, err := New([]config.Node{{Addr: "n.example.com:443", Password: ""}}, dial, Options{}); err == nil {
		t.Fatal("empty password should be rejected")
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
	if _, _, err := pool.Dial(context.Background(), "example.com", 443); err != nil {
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
	if _, _, err := pool.Dial(context.Background(), "example.com", 443); err == nil {
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
