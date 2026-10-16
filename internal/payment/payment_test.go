package payment

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/accounts"
)

// —— 假时钟与夹具（设计书 §5：计费假件 = TempDir 真实 accounts.Store，文件
// 持久化轻到不值得 mock，不 mock 领域层）——

// fakeClock 是可步进的假时钟（-race 下经互斥锁读写）。
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock { return &fakeClock{now: start} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

const (
	testPeriodDays = 30
	testPriceCents = int64(3000)
	testTradeNo    = "2026101522001400001234567890"
	testGmtPayment = "2026-10-15 20:00:00"
)

var testBase = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func sha256HexOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sha224HexOf(s string) string {
	sum := sha256.Sum224([]byte(s))
	return hex.EncodeToString(sum[:])
}

// newAccountsStore 建立真实账户存储（TempDir + 空库文件 + 预置用户），时钟
// 注入与被测服务共用同一假时钟。
func newAccountsStore(t *testing.T, clock *fakeClock, usernames ...string) *accounts.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "accounts.json")
	if err := os.WriteFile(path, []byte(`{"version": 1, "users": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := accounts.Open(path)
	if err != nil {
		t.Fatalf("accounts.Open: %v", err)
	}
	st.Now = clock.Now
	for _, name := range usernames {
		if err := st.Create(accounts.User{
			Username:       name,
			PasswordSHA256: sha256HexOf("pw-" + name),
			PasswordSHA224: sha224HexOf("pw-" + name),
			Status:         accounts.StatusActive,
		}); err != nil {
			t.Fatalf("accounts.Create(%s): %v", name, err)
		}
	}
	return st
}

// newService 建立被测服务（orders.json 独立于账户文件，注入假时钟）。
func newService(t *testing.T, store *accounts.Store, clock *fakeClock) *Service {
	t.Helper()
	svc, err := Open(filepath.Join(t.TempDir(), "orders.json"), store, testPeriodDays, testPriceCents)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	svc.Now = clock.Now
	return svc
}

// reopen 从同一 orders.json 重新加载服务（验证持久化纪律：文件是权威状态）。
func reopen(t *testing.T, svc *Service, store *accounts.Store) *Service {
	t.Helper()
	again, err := Open(svc.path, store, testPeriodDays, testPriceCents)
	if err != nil {
		t.Fatalf("reopen %s: %v", svc.path, err)
	}
	return again
}

func tradeFor(o Order, amountCents int64) Trade {
	return Trade{OutTradeNo: o.OrderID, TradeNo: testTradeNo, AmountCents: amountCents, GmtPayment: testGmtPayment}
}

func mustNotify(t *testing.T, svc *Service, trade Trade) {
	t.Helper()
	ack, err := svc.ApplyNotify(trade)
	if err != nil {
		t.Fatalf("ApplyNotify(%s): %v", trade.TradeNo, err)
	}
	if !ack {
		t.Fatalf("ApplyNotify(%s): ack = false, want true", trade.TradeNo)
	}
}

func accountSubscription(t *testing.T, st *accounts.Store, name string) accounts.Subscription {
	t.Helper()
	u, err := st.Get(name)
	if err != nil {
		t.Fatalf("accounts.Get(%s): %v", name, err)
	}
	return u.Subscription
}

func orderOf(t *testing.T, svc *Service, id string) Order {
	t.Helper()
	for _, o := range svc.List() {
		if o.OrderID == id {
			return o
		}
	}
	t.Fatalf("order %s not found", id)
	return Order{}
}

// —— Create：pending 订单 + 唯一订单号 + 弱引用 ——

func TestCreatePendingOrder(t *testing.T) {
	clock := newFakeClock(testBase)
	st := newAccountsStore(t, clock, "alice")
	svc := newService(t, st, clock)

	o, err := svc.Create("alice")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if o.OrderID == "" || o.Username != "alice" {
		t.Fatalf("order = %+v, want non-empty order_id and username alice", o)
	}
	if o.Status != OrderPending || o.AmountCents != testPriceCents {
		t.Fatalf("order = %+v, want pending %d cents", o, testPriceCents)
	}
	if !o.CreatedAt.Equal(testBase) || !o.ExpiresAt.Equal(testBase.Add(orderTTL)) {
		t.Fatalf("created_at/expires_at = %v/%v, want %v/%v", o.CreatedAt, o.ExpiresAt, testBase, testBase.Add(orderTTL))
	}
	if o.TradeNo != "" || o.GmtPayment != "" || !o.AppliedAt.IsZero() {
		t.Fatalf("pending order must not carry payment facts: %+v", o)
	}

	// 订单号唯一（= out_trade_no）。
	other, err := svc.Create("alice")
	if err != nil {
		t.Fatalf("second Create: %v", err)
	}
	if other.OrderID == o.OrderID {
		t.Fatalf("order_id not unique: %s", o.OrderID)
	}

	// 弱引用（设计书 §1.1）：未知名也可下单；形状非法拒绝。
	if _, err := svc.Create("ghost"); err != nil {
		t.Fatalf("Create for unknown username (weak reference): %v", err)
	}
	for _, bad := range []string{"", "  ", "a\nb"} {
		if _, err := svc.Create(bad); !errors.Is(err, ErrInvalidOrder) {
			t.Fatalf("Create(%q) err = %v, want ErrInvalidOrder", bad, err)
		}
	}

	// 持久化生效：重开后 3 笔订单仍在（插入序）。
	round := reopen(t, svc, st)
	if got := round.List(); len(got) != 3 || got[0].OrderID != o.OrderID || got[2].Username != "ghost" {
		t.Fatalf("List after reopen = %+v, want 3 orders in insertion order", got)
	}
}

// —— ApplyNotify：幂等落地 + 订阅单调延长（设计书 §1.1 I4 / §1.2）——

func TestApplyNotifyLandsOnceAndIsIdempotent(t *testing.T) {
	clock := newFakeClock(testBase)
	st := newAccountsStore(t, clock, "alice")
	svc := newService(t, st, clock)

	o, err := svc.Create("alice")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	mustNotify(t, svc, tradeFor(o, testPriceCents))

	// 落地 = 订阅延长一个周期（无订阅 ⇒ 自 now 起算）+ 订单终态。
	sub := accountSubscription(t, st, "alice")
	if want := testBase.Add(testPeriodDays * 24 * time.Hour); !sub.ExpiresAt.Equal(want) {
		t.Fatalf("expires_at = %v, want %v", sub.ExpiresAt, want)
	}
	if !sub.GrantedAt.Equal(testBase) {
		t.Fatalf("granted_at = %v, want injected now %v", sub.GrantedAt, testBase)
	}
	got := orderOf(t, svc, o.OrderID)
	if got.Status != OrderApplied || got.TradeNo != testTradeNo || got.GmtPayment != testGmtPayment || !got.AppliedAt.Equal(testBase) {
		t.Fatalf("landed order = %+v, want applied with trade facts", got)
	}

	// 同 trade_no 二次通知 ⇒ ACK 且恰好一次延长（幂等，I4）。
	mustNotify(t, svc, tradeFor(o, testPriceCents))
	sub2 := accountSubscription(t, st, "alice")
	if !sub2.ExpiresAt.Equal(sub.ExpiresAt) || !sub2.GrantedAt.Equal(sub.GrantedAt) {
		t.Fatalf("replay changed subscription: %+v → %+v", sub, sub2)
	}
	if got2 := orderOf(t, svc, o.OrderID); !got2.AppliedAt.Equal(got.AppliedAt) {
		t.Fatalf("replay changed order: %+v → %+v", got, got2)
	}

	// 持久化一致：重开后订阅与订单终态都在。
	round := reopen(t, svc, st)
	sub3 := accountSubscription(t, round.accounts, "alice")
	if !sub3.ExpiresAt.Equal(sub.ExpiresAt) {
		t.Fatalf("subscription did not round-trip: %+v", sub3)
	}
	if got3 := orderOf(t, round, o.OrderID); got3.Status != OrderApplied || got3.TradeNo != testTradeNo {
		t.Fatalf("order did not round-trip: %+v", got3)
	}
}

func TestApplyNotifyStacksMonotonically(t *testing.T) {
	clock := newFakeClock(testBase)
	st := newAccountsStore(t, clock, "alice")
	svc := newService(t, st, clock)

	// 已订阅用户（管理员设置，到期仍在未来）⇒ 自当前到期叠加，而非自 now 起算。
	future := testBase.Add(200 * 24 * time.Hour)
	if err := st.SetSubscriptionExpiresAt("alice", future); err != nil {
		t.Fatalf("SetSubscriptionExpiresAt: %v", err)
	}
	o1, _ := svc.Create("alice")
	mustNotify(t, svc, tradeFor(o1, testPriceCents))
	if got := accountSubscription(t, st, "alice").ExpiresAt; !got.Equal(future.Add(testPeriodDays * 24 * time.Hour)) {
		t.Fatalf("first renewal = %v, want %v (stack on current expiry)", got, future.Add(testPeriodDays*24*time.Hour))
	}

	// 第二笔订单再叠加一个周期（new = max(old, paid_until) 单调递增）。
	o2, _ := svc.Create("alice")
	mustNotify(t, svc, tradeFor(o2, testPriceCents))
	if got := accountSubscription(t, st, "alice").ExpiresAt; !got.Equal(future.Add(2 * testPeriodDays * 24 * time.Hour)) {
		t.Fatalf("second renewal = %v, want %v", got, future.Add(2*testPeriodDays*24*time.Hour))
	}

	// 更小的目标永不回退：时钟回拨到过去再支付 ⇒ max(now, current) 取 current。
	clock.Set(testBase.Add(-48 * time.Hour))
	o3, _ := svc.Create("alice")
	mustNotify(t, svc, tradeFor(o3, testPriceCents))
	if got := accountSubscription(t, st, "alice").ExpiresAt; !got.Equal(future.Add(3 * testPeriodDays * 24 * time.Hour)) {
		t.Fatalf("renewal after clock rollback = %v, want %v (never regress)", got, future.Add(3*testPeriodDays*24*time.Hour))
	}
}

func TestApplyNotifyRejectsAmountMismatch(t *testing.T) {
	clock := newFakeClock(testBase)
	st := newAccountsStore(t, clock, "alice")
	svc := newService(t, st, clock)

	o, err := svc.Create("alice")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	ack, err := svc.ApplyNotify(tradeFor(o, testPriceCents-1))
	if ack || !errors.Is(err, ErrAmountMismatch) {
		t.Fatalf("mismatched notify = (%v, %v), want (false, ErrAmountMismatch)", ack, err)
	}
	// 不动账、订单保持 pending（无支付事实）。
	if sub := accountSubscription(t, st, "alice"); !sub.ExpiresAt.IsZero() {
		t.Fatalf("ledger changed on mismatch: %+v", sub)
	}
	if got := orderOf(t, svc, o.OrderID); got.Status != OrderPending || got.TradeNo != "" {
		t.Fatalf("order changed on mismatch: %+v", got)
	}

	// 正确金额随后照常落地。
	mustNotify(t, svc, tradeFor(o, testPriceCents))
	if got := accountSubscription(t, st, "alice").ExpiresAt; !got.Equal(testBase.Add(testPeriodDays * 24 * time.Hour)) {
		t.Fatalf("expires_at after correct notify = %v", got)
	}
}

func TestApplyNotifyClosedExpiredOrderIsAckWithoutLedgerChange(t *testing.T) {
	clock := newFakeClock(testBase)
	st := newAccountsStore(t, clock, "alice")
	svc := newService(t, st, clock)

	o, err := svc.Create("alice")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// 惰性超时：越过订单时限后通知才到达（无后台清扫线程）。
	clock.Advance(orderTTL + time.Minute)
	ack, err := svc.ApplyNotify(tradeFor(o, testPriceCents))
	if !ack || err != nil {
		t.Fatalf("expired notify = (%v, %v), want (true, nil)", ack, err)
	}
	if sub := accountSubscription(t, st, "alice"); !sub.ExpiresAt.IsZero() {
		t.Fatalf("ledger changed on expired order: %+v", sub)
	}
	if got := orderOf(t, svc, o.OrderID); got.Status != OrderClosed {
		t.Fatalf("expired order status = %q, want closed (lazy evaluation)", got.Status)
	}

	// closed 终态再通知 ⇒ 仍 ACK、仍不动账。
	ack, err = svc.ApplyNotify(tradeFor(o, testPriceCents))
	if !ack || err != nil {
		t.Fatalf("closed notify = (%v, %v), want (true, nil)", ack, err)
	}
	if sub := accountSubscription(t, st, "alice"); !sub.ExpiresAt.IsZero() {
		t.Fatalf("ledger changed on closed order: %+v", sub)
	}

	// 惰性关闭持久化：重开后订单仍是 closed。
	if got := orderOf(t, reopen(t, svc, st), o.OrderID); got.Status != OrderClosed {
		t.Fatalf("closed status did not round-trip: %+v", got)
	}
}

func TestApplyNotifyRejectsTradeConflictAndBadTrades(t *testing.T) {
	clock := newFakeClock(testBase)
	st := newAccountsStore(t, clock, "alice")
	svc := newService(t, st, clock)

	o, err := svc.Create("alice")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	mustNotify(t, svc, tradeFor(o, testPriceCents))
	want := accountSubscription(t, st, "alice")

	// 同一订单换一个 trade_no = 幂等键冲突，拒落地。
	conflict := tradeFor(o, testPriceCents)
	conflict.TradeNo = "T-OTHER"
	if ack, err := svc.ApplyNotify(conflict); ack || !errors.Is(err, ErrTradeConflict) {
		t.Fatalf("conflicting notify = (%v, %v), want (false, ErrTradeConflict)", ack, err)
	}
	if got := accountSubscription(t, st, "alice"); !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("ledger changed on conflict: %+v → %+v", want, got)
	}

	// 未知名订单与形状非法通知一律拒绝（fail-closed）。
	for _, bad := range []Trade{
		{OutTradeNo: "no-such-order", TradeNo: testTradeNo, AmountCents: testPriceCents},
		{OutTradeNo: o.OrderID, AmountCents: testPriceCents},                // 缺 trade_no
		{OutTradeNo: o.OrderID, TradeNo: testTradeNo, AmountCents: 0},       // 金额非正
		{OutTradeNo: "", TradeNo: testTradeNo, AmountCents: testPriceCents}, // 缺订单号
	} {
		if ack, err := svc.ApplyNotify(bad); ack || err == nil {
			t.Fatalf("bad trade %+v = (%v, %v), want (false, error)", bad, ack, err)
		}
	}
	if got := accountSubscription(t, st, "alice"); !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("ledger changed on bad trades: %+v → %+v", want, got)
	}
}

// 落地中断的检查点语义：延长失败 ⇒ 订单停在 paid（支付事实已固定），账户就位
// 后同号通知自检查点续落地，且恰好延长一次。
func TestApplyNotifyResumesFromPaidCheckpoint(t *testing.T) {
	clock := newFakeClock(testBase)
	st := newAccountsStore(t, clock) // 账户库为空：用户尚未创建
	svc := newService(t, st, clock)

	o, err := svc.Create("alice") // 弱引用：下单不查账户库
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	ack, err := svc.ApplyNotify(tradeFor(o, testPriceCents))
	if ack || !errors.Is(err, accounts.ErrUnknownUser) {
		t.Fatalf("notify for unknown account = (%v, %v), want (false, accounts.ErrUnknownUser)", ack, err)
	}
	if got := orderOf(t, svc, o.OrderID); got.Status != OrderPaid || got.TradeNo != testTradeNo {
		t.Fatalf("order after failed extend = %+v, want paid checkpoint with trade_no", got)
	}

	// 账户就位后重试：自 paid 续落地，恰好延长一次（不是两个周期）。
	if err := st.Create(accounts.User{
		Username:       "alice",
		PasswordSHA256: sha256HexOf("pw-alice"),
		PasswordSHA224: sha224HexOf("pw-alice"),
		Status:         accounts.StatusActive,
	}); err != nil {
		t.Fatalf("accounts.Create(alice): %v", err)
	}
	mustNotify(t, svc, tradeFor(o, testPriceCents))
	if got := accountSubscription(t, st, "alice").ExpiresAt; !got.Equal(testBase.Add(testPeriodDays * 24 * time.Hour)) {
		t.Fatalf("expires_at = %v, want exactly one period %v", got, testBase.Add(testPeriodDays*24*time.Hour))
	}
	if got := orderOf(t, svc, o.OrderID); got.Status != OrderApplied {
		t.Fatalf("order after resume = %+v, want applied", got)
	}
}

// —— 并发（-race：并发落地与下单/读路径）——

func TestConcurrentNotifyCreateAndList(t *testing.T) {
	clock := newFakeClock(testBase)
	st := newAccountsStore(t, clock, "alice")
	svc := newService(t, st, clock)

	// 同一用户两笔订单并发落地 ⇒ 恰好叠加两个周期（单调且不丢）。
	o1, err := svc.Create("alice")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	o2, err := svc.Create("alice")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	for _, o := range []Order{o1, o2} {
		o := o
		go func() {
			defer wg.Done()
			if ack, err := svc.ApplyNotify(tradeFor(o, testPriceCents)); err != nil || !ack {
				t.Errorf("ApplyNotify(%s) = (%v, %v)", o.OrderID, ack, err)
			}
		}()
	}
	wg.Wait()
	if got := accountSubscription(t, st, "alice").ExpiresAt; !got.Equal(testBase.Add(2 * testPeriodDays * 24 * time.Hour)) {
		t.Fatalf("expires_at after concurrent landings = %v, want %v", got, testBase.Add(2*testPeriodDays*24*time.Hour))
	}

	// 并发下单 + 列表读不 panic、不竞争（-race 下运行本测试即验收）。
	const n = 8
	wg.Add(2 * n)
	for i := range n {
		go func() {
			defer wg.Done()
			if _, err := svc.Create(fmt.Sprintf("user-%d", i)); err != nil {
				t.Errorf("concurrent Create: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			_ = svc.List()
		}()
	}
	wg.Wait()

	// 全部变更落盘：重开后订单总数一致。
	if got := len(reopen(t, svc, st).List()); got != 2+n {
		t.Fatalf("orders after reopen = %d, want %d", got, 2+n)
	}
}
