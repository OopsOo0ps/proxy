package accounts

import (
	"strings"
	"testing"
	"time"
)

// —— 形状护栏：不 import core / trojan，以测试内局部契约同形断言钉住方法形状
//（正式的编译期断言随组装根接线落在 serverapp；此处保证 GateView 形状不漂移）。

type inboundAuthenticator interface {
	Authenticate(username, password string) bool
}

type tunnelVerifier interface {
	VerifyTunnel(hashHex string) (string, bool)
}

var (
	_ inboundAuthenticator = (*GateView)(nil)
	_ tunnelVerifier       = (*GateView)(nil)
)

// gateFixture：alice 启用 + 有效订阅（授予 = 假时钟当前，到期 +90 天）；
// bob 停用 + 无订阅；carol 启用 + 无订阅。
type gateFixture struct {
	store *Store
	gate  *GateView
	clock *fakeClock
}

const (
	aliceStart = "2026-06-01T00:00:00Z"
	alicePw    = "pw-alice"
	bobPw      = "pw-bob"
	carolPw    = "pw-carol"
)

func newGateFixture(t *testing.T) *gateFixture {
	t.Helper()
	start, err := time.Parse(time.RFC3339, aliceStart)
	if err != nil {
		t.Fatal(err)
	}
	path := writeFile(t, fileWith("1",
		userLine("alice", sha256HexOf(alicePw), sha224HexOf(alicePw), "active"),
		userLine("bob", sha256HexOf(bobPw), sha224HexOf(bobPw), "disabled"),
	))
	st := mustOpen(t, path)
	clock := newFakeClock(start)
	st.Now = clock.Now
	if err := st.Create(testUser("carol", carolPw)); err != nil {
		t.Fatalf("Create carol: %v", err)
	}
	if err := st.SetSubscriptionExpiresAt("alice", start.Add(90*24*time.Hour)); err != nil {
		t.Fatalf("grant alice subscription: %v", err)
	}
	return &gateFixture{store: st, gate: st.Gate(false), clock: clock}
}

// gateOn 返回门禁强制开启的视图（on = cfg.Gate.Enabled 的注入点，Store.Gate）。
func (f *gateFixture) gateOn() *GateView {
	return f.store.Gate(true)
}

// TestGateSwitchDenyByDefault 钉住开关语义：同一 Store，Gate(false) 对无订阅
// 用户放行（现状等价），Gate(true) 立即拒绝（deny-by-default）——开关只影响
// 订阅维度，口令与状态维度不受影响。
func TestGateSwitchDenyByDefault(t *testing.T) {
	f := newGateFixture(t)

	if !f.gate.Authenticate("carol", carolPw) {
		t.Fatal("gate off: user without subscription must pass (status quo equivalence)")
	}
	if f.store.Gate(true).Authenticate("carol", carolPw) {
		t.Fatal("gate on: user without subscription must be denied")
	}
	// 隧道路径同判：门禁开 + 无订阅 ⇒ 拒绝且原因 no_subscription。
	name, d := f.store.Gate(true).DecideTunnel(sha224HexOf(carolPw))
	if d.Allow || d.Reason != ReasonNoSubscription || name != "carol" {
		t.Fatalf("tunnel gate on = %q, %+v, want deny/no_subscription", name, d)
	}
}

// —— 门禁关闭（与现状等价的形态：订阅维度不参与判定）——

func TestGateOffAuthenticateBranches(t *testing.T) {
	f := newGateFixture(t)

	// 未知名。
	if d := f.gate.Decide("ghost", "x"); d.Allow || d.Reason != ReasonUnknownUser {
		t.Fatalf("unknown user = %+v, want deny/unknown_user", d)
	}
	// 口令不匹配。
	if d := f.gate.Decide("alice", "wrong"); d.Allow || d.Reason != ReasonBadCredentials {
		t.Fatalf("bad password = %+v, want deny/bad_credentials", d)
	}
	// 停用（口令正确）。
	if d := f.gate.Decide("bob", bobPw); d.Allow || d.Reason != ReasonDisabled {
		t.Fatalf("disabled user = %+v, want deny/disabled", d)
	}
	// 有效订阅 + 启用 ⇒ 放行。
	if d := f.gate.Decide("alice", alicePw); !d.Allow || d.Reason != ReasonNone {
		t.Fatalf("active user = %+v, want allow", d)
	}
	// 无订阅 + 启用 ⇒ 门禁关时同样放行（订阅维度不参与判定）。
	if d := f.gate.Decide("carol", carolPw); !d.Allow {
		t.Fatalf("active user without subscription = %+v, want allow while gate is off", d)
	}
	// 门禁关 + 订阅已过期 ⇒ 放行（与现状等价的关键分支）。
	f.clock.Set(f.clock.Now().Add(91 * 24 * time.Hour))
	if d := f.gate.Decide("alice", alicePw); !d.Allow {
		t.Fatalf("expired subscription with gate off = %+v, want allow (gate-off equivalence)", d)
	}
	if !f.gate.Authenticate("alice", alicePw) {
		t.Fatal("Authenticate must mirror Decide")
	}
}

func TestGateOffTunnelBranches(t *testing.T) {
	f := newGateFixture(t)

	if name, ok := f.gate.VerifyTunnel(sha224HexOf(alicePw)); !ok || name != "alice" {
		t.Fatalf("VerifyTunnel(alice) = %q, %v", name, ok)
	}
	// 摘要大小写不敏感（镜像 auth.Store / trojan 客户端口径）。
	if name, ok := f.gate.VerifyTunnel(strings.ToUpper(sha224HexOf(alicePw))); !ok || name != "alice" {
		t.Fatalf("VerifyTunnel(uppercase) = %q, %v", name, ok)
	}
	// 未命中。
	if name, ok := f.gate.VerifyTunnel(strings.Repeat("0", 56)); ok || name != "" {
		t.Fatalf("VerifyTunnel(unknown) = %q, %v", name, ok)
	}
	// 形状非法（长度/编码）。
	if _, ok := f.gate.VerifyTunnel("nothex"); ok {
		t.Fatal("VerifyTunnel(malformed) must fail")
	}
	// 停用用户：匹配名返回但判定拒绝（原因经 DecideTunnel 供日志）。
	if name, ok := f.gate.VerifyTunnel(sha224HexOf(bobPw)); ok || name != "bob" {
		t.Fatalf("VerifyTunnel(disabled) = %q, %v; want matched name with deny", name, ok)
	}
	if d := func() Decision { _, d := f.gate.DecideTunnel(sha224HexOf(bobPw)); return d }(); d.Reason != ReasonDisabled {
		t.Fatalf("DecideTunnel(disabled) = %+v, want disabled", d)
	}
}

// —— 门禁开启（Store.Gate(true)：无有效订阅即拒绝，deny-by-default）——

func TestGateOnSubscriptionBranches(t *testing.T) {
	f := newGateFixture(t)
	g := f.gateOn()

	// 有效窗口内 ⇒ 放行。
	if d := g.Decide("alice", alicePw); !d.Allow {
		t.Fatalf("valid subscription = %+v, want allow", d)
	}
	// 无订阅 ⇒ 拒绝。
	if d := g.Decide("carol", carolPw); d.Allow || d.Reason != ReasonNoSubscription {
		t.Fatalf("no subscription = %+v, want deny/no_subscription", d)
	}
	// 过期 ⇒ 拒绝。
	f.clock.Set(f.clock.Now().Add(91 * 24 * time.Hour))
	if d := g.Decide("alice", alicePw); d.Allow || d.Reason != ReasonExpired {
		t.Fatalf("expired subscription = %+v, want deny/expired", d)
	}
	// 停用优先级不受订阅影响。
	if d := g.Decide("bob", bobPw); d.Allow || d.Reason != ReasonDisabled {
		t.Fatalf("disabled user = %+v, want deny/disabled", d)
	}
}

func TestGateOnClockRollbackRejects(t *testing.T) {
	f := newGateFixture(t)
	g := f.gateOn()

	// 系统时刻早于授予时刻（时钟回拨）⇒ 拒绝，fail-closed。
	f.clock.Set(f.clock.Now().Add(-time.Second))
	if d := g.Decide("alice", alicePw); d.Allow || d.Reason != ReasonClockRollback {
		t.Fatalf("clock rollback = %+v, want deny/clock_rollback", d)
	}
	name, d := g.DecideTunnel(sha224HexOf(alicePw))
	if d.Allow || d.Reason != ReasonClockRollback || name != "alice" {
		t.Fatalf("tunnel clock rollback = %q, %+v", name, d)
	}
	// 时刻恰等于授予时刻：不算回拨，有效窗口内 ⇒ 放行。
	f.clock.Set(f.clock.Now().Add(time.Second))
	if d := g.Decide("alice", alicePw); !d.Allow {
		t.Fatalf("grant boundary = %+v, want allow", d)
	}
}
