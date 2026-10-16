package control

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/accounts"
	"github.com/OopsOo0ps/proxy/internal/alipay"
	"github.com/OopsOo0ps/proxy/internal/payment"
	"github.com/OopsOo0ps/proxy/internal/testutil"
)

// —— 测试脚手架：httptest + TempDir 的真实 accounts/payment 存储（不 mock 领域
// 层，设计书 §5）；网关侧签名用真密钥——坏签名负例因此与真实网关行为同构 ——

// payTest 是支付端点测试的完整夹具：控制面（启用支付）+ 账户/订单存储 +
// 商户与支付宝两对演示密钥。gateway 可签发真实网关形态的异步通知（签名经
// Client.VerifyNotify 可验），坏签名负例直接篡改表单即可。
type payTest struct {
	store   *accounts.Store
	pay     *payment.Service
	gateway *alipay.Gateway // 网关侧签名助手（持有支付宝私钥）
	ts      *httptest.Server
}

// newPayTestServer 起一个启用支付的控制面：TempDir 落盘 accounts.json/orders.json
// （订单库缺失合法，直接交给 payment.Open 从零生长），密钥由 testutil 全新生成
// （商户私钥给 Client 签下单请求，支付宝密钥对给 Gateway 签通知 / Client 验签）。
func newPayTestServer(t *testing.T) *payTest {
	t.Helper()
	dir := t.TempDir()
	accountsPath := filepath.Join(dir, "accounts.json")
	if err := os.WriteFile(accountsPath, []byte("{\"version\":1,\"users\":[]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := accounts.Open(accountsPath)
	if err != nil {
		t.Fatalf("accounts.Open: %v", err)
	}
	pay, err := payment.Open(filepath.Join(dir, "orders.json"), store, 30, 3000)
	if err != nil {
		t.Fatalf("payment.Open: %v", err)
	}
	merchantPriv, merchantPub, err := testutil.NewRSAKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	gatewayPriv, gatewayPub, err := testutil.NewRSAKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	client, err := alipay.New(alipay.ClientConfig{
		Gateway:        "https://127.0.0.1:9400/gateway.do",
		AppID:          "2026000000000000",
		MerchantKeyPEM: merchantPriv,
		AlipayKeyPEM:   gatewayPub,
	})
	if err != nil {
		t.Fatalf("alipay.New: %v", err)
	}
	gateway, err := alipay.NewGateway(alipay.GatewayConfig{
		AppID:          "2026000000000000",
		MerchantPubPEM: merchantPub,
		NotifyKeyPEM:   gatewayPriv,
	})
	if err != nil {
		t.Fatalf("alipay.NewGateway: %v", err)
	}
	srv, err := New(Deps{
		Store:     store,
		Logger:    slog.New(slog.DiscardHandler),
		Pay:       pay,
		Alipay:    client,
		NotifyURL: "http://127.0.0.1:9300/notify/alipay",
	})
	if err != nil {
		t.Fatalf("control.New: %v", err)
	}
	ts := httptest.NewServer(srv.handler)
	t.Cleanup(ts.Close)
	return &payTest{store: store, pay: pay, gateway: gateway, ts: ts}
}

// postForm 发送 form-POST 并返回状态码与响应体原文（通知应答是纯文本协议）。
func (p *payTest) postForm(t *testing.T, target string, form url.Values) (int, string) {
	t.Helper()
	resp, err := p.ts.Client().PostForm(p.ts.URL+target, form)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("POST %s: read response: %v", target, err)
	}
	return resp.StatusCode, string(raw)
}

// buildNotify 签发一笔 TRADE_SUCCESS 异步通知（网关原文形态）。
func (p *payTest) buildNotify(t *testing.T, outTradeNo, totalAmount, tradeNo string) url.Values {
	t.Helper()
	form, err := p.gateway.BuildNotify(alipay.TradeNotify{
		TradeNo:     tradeNo,
		OutTradeNo:  outTradeNo,
		TotalAmount: totalAmount,
		Subject:     orderSubject,
		PaidAt:      time.Now(),
	})
	if err != nil {
		t.Fatalf("BuildNotify: %v", err)
	}
	return form
}

// seedUser 经控制面创建一个用户（下单的前置）。
func (p *payTest) seedUser(t *testing.T, username string) {
	t.Helper()
	code, body := doJSON(t, p.ts, http.MethodPost, "/users", map[string]string{"username": username, "password": "pw-" + username})
	if code != http.StatusCreated {
		t.Fatalf("seed user %s: got status %d, want 201 (body: %v)", username, code, body)
	}
}

// createOrder 经控制面下一单，返回订单号与收银台 URL。
func (p *payTest) createOrder(t *testing.T, username string) (string, string) {
	t.Helper()
	code, body := doJSON(t, p.ts, http.MethodPost, "/orders", map[string]string{"username": username})
	if code != http.StatusCreated {
		t.Fatalf("create order for %s: got status %d, want 201 (body: %v)", username, code, body)
	}
	orderID, _ := body["order_id"].(string)
	payURL, _ := body["pay_url"].(string)
	if orderID == "" || payURL == "" {
		t.Fatalf("create order: response must carry order_id and pay_url, got %v", body)
	}
	return orderID, payURL
}

// —— POST /orders：正常路径 ——
func TestCreateOrderHappyPath(t *testing.T) {
	p := newPayTestServer(t)
	p.seedUser(t, "alice")

	orderID, payURL := p.createOrder(t, "alice")

	// pay_url 指向配置注入的网关：公共参数齐全（app_id / method / 签名），
	// notify_url 指向控制面回调，订单号与金额在 biz_content 业务参数内。
	u, err := url.Parse(payURL)
	if err != nil {
		t.Fatalf("parse pay_url %q: %v", payURL, err)
	}
	if u.Scheme != "https" || u.Host != "127.0.0.1:9400" || u.Path != "/gateway.do" {
		t.Fatalf("pay_url = %q, want the configured gateway cashier URL", payURL)
	}
	q := u.Query()
	if q.Get("app_id") != "2026000000000000" || q.Get("method") != alipay.MethodPagePay ||
		q.Get("sign_type") != alipay.SignTypeRSA2 || q.Get("sign") == "" {
		t.Fatalf("pay_url query = %v, want signed page.pay request", q)
	}
	if q.Get("notify_url") != "http://127.0.0.1:9300/notify/alipay" {
		t.Fatalf("pay_url notify_url = %q, want the configured control-plane callback", q.Get("notify_url"))
	}
	var biz struct {
		OutTradeNo  string `json:"out_trade_no"`
		TotalAmount string `json:"total_amount"`
		Subject     string `json:"subject"`
	}
	if err := json.Unmarshal([]byte(q.Get("biz_content")), &biz); err != nil {
		t.Fatalf("decode biz_content: %v", err)
	}
	if biz.OutTradeNo != orderID || biz.TotalAmount != "30.00" || biz.Subject != orderSubject {
		t.Fatalf("biz_content = %+v, want the created order at 30.00", biz)
	}
	// 订单落库为 pending（金额 = 固定档位 price_cents）。
	orders := p.pay.List()
	if len(orders) != 1 {
		t.Fatalf("after create: %d orders, want 1", len(orders))
	}
	o := orders[0]
	if o.OrderID != orderID || o.Username != "alice" || o.AmountCents != 3000 || o.Status != payment.OrderPending {
		t.Fatalf("order = %+v, want pending order for alice at 3000 cents", o)
	}
}

// —— POST /orders：400 / 404，且不留半写状态 ——
func TestCreateOrderErrors(t *testing.T) {
	p := newPayTestServer(t)
	p.seedUser(t, "alice")

	// 损坏的 JSON ⇒ 400。
	resp, err := http.Post(p.ts.URL+"/orders", "application/json", strings.NewReader("{not-json"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed JSON: got status %d, want 400", resp.StatusCode)
	}

	// 字段形状负例 ⇒ 400。
	for i, body := range []map[string]string{
		{"username": ""},
		{"username": "   "},
		{"username": "ali\nce"},
		{},
	} {
		code, got := doJSON(t, p.ts, http.MethodPost, "/orders", body)
		if code != http.StatusBadRequest {
			t.Fatalf("case %d (%v): got status %d, want 400 (body: %v)", i, body, code, got)
		}
	}

	// 未知用户 ⇒ 404（订单以用户名弱引用账户，但不存在的账户永远无法落地
	// 订阅——控制面在下单口拒绝）。
	code, got := doJSON(t, p.ts, http.MethodPost, "/orders", map[string]string{"username": "ghost"})
	if code != http.StatusNotFound {
		t.Fatalf("unknown user: got status %d, want 404 (body: %v)", code, got)
	}

	// 全部失败路径都不产生订单。
	if got := len(p.pay.List()); got != 0 {
		t.Fatalf("after failed requests: %d orders, want 0 (no partial writes)", got)
	}
}

// —— POST /notify/alipay：有效签名落地 + 幂等 ——
func TestNotifyLandsAndIsIdempotent(t *testing.T) {
	p := newPayTestServer(t)
	p.seedUser(t, "alice")
	orderID, _ := p.createOrder(t, "alice")

	form := p.buildNotify(t, orderID, "30.00", "T20261015001")
	code, body := p.postForm(t, "/notify/alipay", form)
	if code != http.StatusOK || body != notifySuccess {
		t.Fatalf("first notify: got (%d, %q), want (200, %q)", code, body, notifySuccess)
	}

	// 落地检查：订单 applied，订阅被单调延长一个档位。
	orders := p.pay.List()
	if len(orders) != 1 || orders[0].Status != payment.OrderApplied || orders[0].TradeNo != "T20261015001" {
		t.Fatalf("after notify: orders = %+v, want one applied order", orders)
	}
	u, err := p.store.Get("alice")
	if err != nil || u.Subscription.ExpiresAt.IsZero() {
		t.Fatalf("after notify: subscription = %+v (err %v), want extended", u.Subscription, err)
	}
	expires := u.Subscription.ExpiresAt

	// 幂等重放：同 trade_no 二次通知 ⇒ ACK（success），订阅不再延长（I4）。
	code, body = p.postForm(t, "/notify/alipay", form)
	if code != http.StatusOK || body != notifySuccess {
		t.Fatalf("replay notify: got (%d, %q), want (200, %q)", code, body, notifySuccess)
	}
	u, err = p.store.Get("alice")
	if err != nil || !u.Subscription.ExpiresAt.Equal(expires) {
		t.Fatalf("after replay: expires_at = %+v (err %v), want unchanged %v", u.Subscription.ExpiresAt, err, expires)
	}
	if orders := p.pay.List(); len(orders) != 1 || orders[0].Status != payment.OrderApplied {
		t.Fatalf("after replay: orders = %+v, want single applied order", orders)
	}
}

// —— POST /notify/alipay：拒绝路径（不动账） ——
func TestNotifyRejects(t *testing.T) {
	p := newPayTestServer(t)
	p.seedUser(t, "alice")
	orderID, _ := p.createOrder(t, "alice")

	// 有效签名但金额被篡改 ⇒ 坏签名拒绝（验签串被破坏）。
	tampered := p.buildNotify(t, orderID, "30.00", "T20261015002")
	tampered.Set("total_amount", "999.99")
	code, body := p.postForm(t, "/notify/alipay", tampered)
	if body == notifySuccess {
		t.Fatalf("tampered notify: body %q must not acknowledge", body)
	}
	if code == http.StatusOK {
		t.Fatalf("tampered notify: got status 200, want a rejection code")
	}

	// 有效签名但金额不符（未篡改的通知，金额对不上订单）⇒ 拒落地。
	wrongAmount := p.buildNotify(t, orderID, "99.00", "T20261015003")
	if code, body := p.postForm(t, "/notify/alipay", wrongAmount); body == notifySuccess {
		t.Fatalf("amount mismatch notify: got (%d, %q), want fail", code, body)
	}

	// 有效签名但订单不存在 ⇒ fail-closed 拒绝。
	unknown := p.buildNotify(t, "O20260101000000ffffffffffffffff", "30.00", "T20261015004")
	if code, body := p.postForm(t, "/notify/alipay", unknown); body == notifySuccess {
		t.Fatalf("unknown order notify: got (%d, %q), want fail", code, body)
	}

	// 空表单 / 缺签名 ⇒ 形状非法拒绝。
	if code, body := p.postForm(t, "/notify/alipay", url.Values{}); body == notifySuccess {
		t.Fatalf("empty notify: got (%d, %q), want fail", code, body)
	}
	unsigned := p.buildNotify(t, orderID, "30.00", "T20261015005")
	unsigned.Del("sign")
	if code, body := p.postForm(t, "/notify/alipay", unsigned); body == notifySuccess {
		t.Fatalf("unsigned notify: got (%d, %q), want fail", code, body)
	}

	// 全部拒绝路径都不动账：订单仍是 pending，订阅仍为空。
	orders := p.pay.List()
	if len(orders) != 1 || orders[0].Status != payment.OrderPending {
		t.Fatalf("after rejections: orders = %+v, want single pending order (no ledger change)", orders)
	}
	if u, err := p.store.Get("alice"); err != nil || !u.Subscription.ExpiresAt.IsZero() {
		t.Fatalf("after rejections: subscription = %+v (err %v), want untouched", u.Subscription, err)
	}
}

// —— 支付端点仅在启用支付时注册 ——
func TestPaymentRoutesRequireDeps(t *testing.T) {
	store := func(t *testing.T) *accounts.Store {
		t.Helper()
		path := filepath.Join(t.TempDir(), "accounts.json")
		if err := os.WriteFile(path, []byte("{\"version\":1,\"users\":[]}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := accounts.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	// 未启用支付（Pay/Alipay 缺省）：/orders 与 /notify/alipay 不存在。
	srv, err := New(Deps{Store: store(t)})
	if err != nil {
		t.Fatalf("control.New: %v", err)
	}
	ts := httptest.NewServer(srv.handler)
	t.Cleanup(ts.Close)
	for _, target := range []string{"/orders", "/notify/alipay"} {
		resp, err := http.Post(ts.URL+target, "application/x-www-form-urlencoded", strings.NewReader(""))
		if err != nil {
			t.Fatalf("POST %s: %v", target, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("payment disabled: POST %s = %d, want 404 (route must not exist)", target, resp.StatusCode)
		}
	}

	// 成对约束：只给其一、或启用支付却不给回调目标，都是组装错误。
	if _, err := New(Deps{Store: store(t), Pay: &payment.Service{}}); err == nil {
		t.Fatal("New with Pay but no Alipay must fail")
	}
	if _, err := New(Deps{Store: store(t), Alipay: &alipay.Client{}}); err == nil {
		t.Fatal("New with Alipay but no Pay must fail")
	}
	pay, err := payment.Open(filepath.Join(t.TempDir(), "orders.json"), store(t), 30, 3000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Deps{Store: store(t), Pay: pay, Alipay: &alipay.Client{}}); err == nil {
		t.Fatal("New with payment but no notify url must fail")
	}
}

// —— 金额换算辅助（网关原文 ⇄ 分） ——
func TestAmountConversion(t *testing.T) {
	for _, tc := range []struct {
		cents int64
		want  string
	}{
		{3000, "30.00"},
		{3050, "30.50"},
		{5, "0.05"},
		{0, "0.00"},
	} {
		if got := centsString(tc.cents); got != tc.want {
			t.Fatalf("centsString(%d) = %q, want %q", tc.cents, got, tc.want)
		}
	}
	for _, tc := range []struct {
		s    string
		want int64
	}{
		{"30.00", 3000},
		{"30", 3000},
		{"30.5", 3050},
		{"0.99", 99},
	} {
		cents, ok := parseAmountCents(tc.s)
		if !ok || cents != tc.want {
			t.Fatalf("parseAmountCents(%q) = (%d, %v), want (%d, true)", tc.s, cents, ok, tc.want)
		}
	}
	for _, s := range []string{"", ".5", "30.", "30.505", "3a.00", "-1.00", "+30.00", "99999999999999999999.00"} {
		if cents, ok := parseAmountCents(s); ok {
			t.Fatalf("parseAmountCents(%q) = (%d, true), want rejected", s, cents)
		}
	}
}
