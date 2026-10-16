package payment

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// —— orders.json 文件纪律（严格加载 + 缺失即空库 + 原子落盘）——

// orderLine 生成 orders 数组的一个元素（最小形状，按需拼支付事实字段）。
func orderLine(amountCents int64, status, tradeNo, appliedAt string) string {
	line := `{"order_id": "O20261015120000abcdef01", "username": "alice", "amount_cents": ` +
		strconv.FormatInt(amountCents, 10) + `, "status": "` + status +
		`", "created_at": "2026-10-15T12:00:00Z", "expires_at": "2026-10-15T14:00:00Z"`
	if tradeNo != "" {
		line += `, "trade_no": "` + tradeNo + `"`
	}
	if appliedAt != "" {
		line += `, "applied_at": "` + appliedAt + `"`
	}
	return line + `}`
}

func ordersFile(orders ...string) string {
	return `{"version": 1, "orders": [` + strings.Join(orders, ",") + `]}`
}

func writeOrdersFile(t *testing.T, content string) (string, *fakeClock) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "orders.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	clock := newFakeClock(testBase)
	return path, clock
}

func mustFailOpen(t *testing.T, content, want string) {
	t.Helper()
	path, clock := writeOrdersFile(t, content)
	st := newAccountsStore(t, clock)
	if _, err := Open(path, st, testPeriodDays, testPriceCents); err == nil {
		t.Fatalf("Open must fail, want error containing %q", want)
	} else if !strings.Contains(err.Error(), want) {
		t.Fatalf("Open error = %q, want containing %q", err.Error(), want)
	}
}

func TestOpenMissingFileIsEmptyStore(t *testing.T) {
	// 首次运行合法（与 accounts 的「缺失即拒启动」不同：订单库允许从零生长）。
	dir := t.TempDir()
	path := filepath.Join(dir, "orders.json")
	clock := newFakeClock(testBase)
	st := newAccountsStore(t, clock, "alice")

	svc, err := Open(path, st, testPeriodDays, testPriceCents)
	if err != nil {
		t.Fatalf("Open without file: %v", err)
	}
	svc.Now = clock.Now
	if got := svc.List(); len(got) != 0 {
		t.Fatalf("empty store = %d orders", len(got))
	}
	// 空库即可下单：首笔落盘后文件存在且可重读。
	if _, err := svc.Create("alice"); err != nil {
		t.Fatalf("Create on empty store: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("orders.json not created: %v", err)
	}
	round, err := Open(path, st, testPeriodDays, testPriceCents)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := round.List(); len(got) != 1 {
		t.Fatalf("orders after reopen = %d, want 1", len(got))
	}

	// 构造期 fail-fast：账户存储必填、档位参数必须为正。
	if _, err := Open(path, nil, testPeriodDays, testPriceCents); err == nil {
		t.Fatal("Open with nil accounts store must fail")
	}
	if _, err := Open(path, st, 0, testPriceCents); err == nil {
		t.Fatal("Open with period_days = 0 must fail")
	}
	if _, err := Open(path, st, -1, testPriceCents); err == nil {
		t.Fatal("Open with negative period_days must fail")
	}
	if _, err := Open(path, st, testPeriodDays, 0); err == nil {
		t.Fatal("Open with price_cents = 0 must fail")
	}
}

func TestOpenRejectsCorruptOrdersFile(t *testing.T) {
	mustFailOpen(t, "not json at all", "payment: load")
	mustFailOpen(t, ordersFile()+`{"version": 1, "orders": []}`, "unexpected trailing data")
	mustFailOpen(t, `{"version": 2, "orders": []}`, "unsupported version 2")
	mustFailOpen(t, `{"orders": []}`, "unsupported version 0")
	mustFailOpen(t, `{"version": 1, "orders": [], "extra": 1}`, "unknown field")
	mustFailOpen(t, ordersFile(`{"order_id": "O1", "username": "alice", "amount_cents": 3000, "status": "pending", "created_at": "2026-10-15T12:00:00Z", "expires_at": "2026-10-15T14:00:00Z", "bogus": 1}`), "unknown field")
	mustFailOpen(t, ordersFile(orderLine(testPriceCents, "bogus", "", "")), `unknown status "bogus"`)
	// 状态机字段组合把关：pending/closed 不携带支付事实，paid/applied 必有幂等键。
	mustFailOpen(t, ordersFile(orderLine(testPriceCents, "pending", testTradeNo, "")), "must not carry payment facts")
	mustFailOpen(t, ordersFile(orderLine(testPriceCents, "paid", "", "")), "paid order must carry trade_no")
	mustFailOpen(t, ordersFile(orderLine(testPriceCents, "applied", testTradeNo, "")), "must carry trade_no and applied_at")
	mustFailOpen(t, ordersFile(orderLine(0, "pending", "", "")), "amount_cents must be positive")
	mustFailOpen(t, ordersFile(`{"order_id": "O1", "username": "", "amount_cents": 3000, "status": "pending", "created_at": "2026-10-15T12:00:00Z", "expires_at": "2026-10-15T14:00:00Z"}`), "username must not be empty")
	mustFailOpen(t, ordersFile(`{"order_id": "O1", "username": "alice", "amount_cents": 3000, "status": "pending", "created_at": "2026-10-15T12:00:00Z"}`), "created_at and expires_at must be set")
	// 重复订单号拒绝（order_id 是幂等创建键）。
	mustFailOpen(t, ordersFile(orderLine(testPriceCents, "pending", "", ""), orderLine(testPriceCents, "pending", "", "")), "duplicate order_id")
}

// 原子落盘 + RFC3339 往返：遗留半写临时文件不影响加载，落地后的支付事实
// （trade_no / gmt_payment / applied_at）重开仍在，主文件为规范形状。
func TestOrdersFileAtomicPersistAndRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "orders.json")
	if err := os.WriteFile(path+".tmp-stale", []byte(`{"version": 1, "orders": [{"order_id": "ghost"`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(ordersFile(orderLine(testPriceCents, "pending", "", ""))), 0o600); err != nil {
		t.Fatal(err)
	}

	clock := newFakeClock(testBase)
	st := newAccountsStore(t, clock, "alice")
	svc, err := Open(path, st, testPeriodDays, testPriceCents)
	if err != nil {
		t.Fatalf("Open with stale temp file: %v", err)
	}
	svc.Now = clock.Now
	if got := svc.List(); len(got) != 1 || got[0].Status != OrderPending {
		t.Fatalf("List = %+v, want 1 pending order (old file intact, stale temp ignored)", got)
	}

	o := svc.List()[0]
	mustNotify(t, svc, tradeFor(o, testPriceCents))

	round, err := Open(path, st, testPeriodDays, testPriceCents)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got := orderOf(t, round, o.OrderID)
	if got.Status != OrderApplied || got.TradeNo != testTradeNo || got.GmtPayment != testGmtPayment || !got.AppliedAt.Equal(testBase) {
		t.Fatalf("order did not round-trip: %+v", got)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"version": 1`, testTradeNo, testGmtPayment, `"order_id": "` + o.OrderID + `"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("persisted file missing %q:\n%s", want, data)
		}
	}
}

// 未落地订单省略 applied_at（零值 → 字段整体省略，镜像 accounts 文件格式的
// timePtr 手法）；落地后字段出现。
func TestOrdersFileOmitsAppliedAtUntilLanded(t *testing.T) {
	path, clock := writeOrdersFile(t, ordersFile())
	st := newAccountsStore(t, clock, "alice")
	svc, err := Open(path, st, testPeriodDays, testPriceCents)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	svc.Now = clock.Now

	o, err := svc.Create("alice")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "applied_at") || strings.Contains(string(data), "trade_no") {
		t.Fatalf("unlanded orders must omit payment facts:\n%s", data)
	}

	mustNotify(t, svc, tradeFor(o, testPriceCents))
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"applied_at"`) || !strings.Contains(string(data), testTradeNo) {
		t.Fatalf("landed order must record payment facts:\n%s", data)
	}
}
