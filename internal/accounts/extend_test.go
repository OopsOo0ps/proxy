package accounts

import (
	"errors"
	"testing"
	"time"
)

// ExtendSubscriptionExpiresAt 的单调延长语义（设计书 §1.2 Grant 支付路径：
// new = max(old, paid_until)，只增不减；管理员纠错通道 SetSubscriptionExpiresAt
// 不受此约束）。

func TestExtendSubscriptionExpiresAtMonotonic(t *testing.T) {
	path := writeFile(t, fileWith("1", userLine("alice", sha256HexOf("pw"), sha224HexOf("pw"), "active")))
	st := mustOpen(t, path)
	base := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	clock := newFakeClock(base)
	st.Now = clock.Now

	// 无订阅 ⇒ 延长即首次授予（到期与授予时刻成对出现）。
	first := base.Add(30 * 24 * time.Hour)
	if err := st.ExtendSubscriptionExpiresAt("alice", first); err != nil {
		t.Fatalf("first extend: %v", err)
	}
	got, err := st.Get("alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Subscription.ExpiresAt.Equal(first) || !got.Subscription.GrantedAt.Equal(base) {
		t.Fatalf("after first extend = %+v, want expires %v granted %v", got.Subscription, first, base)
	}

	// 更早的目标 = no-op：到期与授予时刻都不回退、不改写（幂等无落盘）。
	clock.Set(base.Add(time.Hour))
	earlier := first.Add(-24 * time.Hour)
	if err := st.ExtendSubscriptionExpiresAt("alice", earlier); err != nil {
		t.Fatalf("earlier extend: %v", err)
	}
	got, _ = st.Get("alice")
	if !got.Subscription.ExpiresAt.Equal(first) || !got.Subscription.GrantedAt.Equal(base) {
		t.Fatalf("earlier extend regressed subscription: %+v", got.Subscription)
	}

	// 相同目标 = no-op；零值目标同样 no-op（永不回到无订阅）。
	for _, at := range []time.Time{first, {}} {
		if err := st.ExtendSubscriptionExpiresAt("alice", at); err != nil {
			t.Fatalf("no-op extend(%v): %v", at, err)
		}
	}
	got, _ = st.Get("alice")
	if !got.Subscription.ExpiresAt.Equal(first) || !got.Subscription.GrantedAt.Equal(base) {
		t.Fatalf("no-op extend regressed subscription: %+v", got.Subscription)
	}

	// 更晚的目标胜出；授予时刻取注入时钟的当前值（随本次授予更新）。
	later := first.Add(30 * 24 * time.Hour)
	if err := st.ExtendSubscriptionExpiresAt("alice", later); err != nil {
		t.Fatalf("later extend: %v", err)
	}
	got, _ = st.Get("alice")
	if !got.Subscription.ExpiresAt.Equal(later) || !got.Subscription.GrantedAt.Equal(clock.Now()) {
		t.Fatalf("after later extend = %+v, want expires %v granted %v", got.Subscription, later, clock.Now())
	}

	// 持久化生效：重新打开后延长结果仍在（原子落盘，镜像其它 mutator 的纪律）。
	round := mustOpen(t, path)
	got2, err := round.Get("alice")
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if !got2.Subscription.ExpiresAt.Equal(later) {
		t.Fatalf("extend did not round-trip: %+v", got2.Subscription)
	}

	if err := st.ExtendSubscriptionExpiresAt("ghost", later); !errors.Is(err, ErrUnknownUser) {
		t.Fatalf("unknown user err = %v, want ErrUnknownUser", err)
	}
}

func TestExtendSubscriptionExpiresAtReadOnly(t *testing.T) {
	path := writeFile(t, fileWith("1", userLine("alice", sha256HexOf("pw"), sha224HexOf("pw"), "active")))
	ro, err := LoadReadOnly(path)
	if err != nil {
		t.Fatalf("LoadReadOnly: %v", err)
	}
	if err := ro.ExtendSubscriptionExpiresAt("alice", time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("ExtendSubscriptionExpiresAt on read-only err = %v, want ErrReadOnly", err)
	}
}
