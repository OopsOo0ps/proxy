// TestPaymentFlow 是订阅门禁迭代③的黑盒用例（设计书 §1.1–§1.4 领域模型、
// §2.1 控制面「支付下单与 notify 回调」、§5 门禁/支付端到端行）：起真
// proxy-server（accounts 模式 + 环回控制面 + payment 段指向 mockpay）与真
// mockpay 二进制，全链路只经进程边界验证支付回路：
//
//  1. 控制面下单：POST /orders 返回 order_id 与指向 mockpay 网关的已签名
//     pay_url（服务端以商户私钥完成 RSA2 签名）；
//  2. 收银台：GET pay_url（HTTPS，跳过自签证书校验）拿到 mockpay 收银台页
//     ——有效签名被网关受理；解析确认表单的隐藏域（原样回传的已验签参数），
//     带 mockpay_action=confirm 标记 POST 确认；
//  3. 异步通知落地：mockpay 同步投递已签名 notify 到控制面 /notify/alipay，
//     验签通过后订单 applied、订阅按 period_days 延长（GET /users 的
//     subscription.expires_at ≈ 确认时刻 + period_days）；
//  4. 幂等（§1.1 I4）：重复确认（mockpay 只投递一次通知）与同 trade_no 的
//     已签名 notify 重放（控制面幂等 ACK）都不产生第二次延长——"alipay
//     notify landed" 服务端日志恒为 1 条；
//  5. 负例：篡改 total_amount 的 notify 验签必败（400 + fail），账户库一个
//     字节都不变。
//
// 黑盒边界：不 import internal/accounts / internal/control / internal/alipaymock
// ——账户形状经 JSON 线上观测、重放/篡改通知经 internal/alipay 的网关侧线
// 格式助手（与真支付宝同一份签名实现）组装、收银台表单按 HTML 线上形态解析。
package integration

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/alipay"
	"github.com/OopsOo0ps/proxy/internal/testutil"
)

func TestPaymentFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test builds and runs the real binaries; skipped with -short")
	}

	const (
		payUser     = "pay-user"
		payPassword = "pay-secret"
		appID       = "2026000000000099"
		orderTitle  = "proxy subscription" // 控制面下单的固定单一档位标题（线上观测所得）
		periodDays  = 30
		priceCents  = int64(3000) // 30.00 元；网关口径金额为两位小数十进制串
	)
	period := time.Duration(periodDays) * 24 * time.Hour
	price := fmt.Sprintf("%d.%02d", priceCents/100, priceCents%100)

	dir := t.TempDir()

	// ---- 1. 密钥材料：商户对 + 网关（支付宝）对 + 两份自签 TLS 证书 ----
	merchantPriv, merchantPub, err := testutil.NewRSAKeyPEM()
	if err != nil {
		t.Fatalf("generate merchant RSA key: %v", err)
	}
	gatewayPriv, gatewayPub, err := testutil.NewRSAKeyPEM()
	if err != nil {
		t.Fatalf("generate gateway RSA key: %v", err)
	}
	// proxy-server 侧：商户私钥（下单请求签名）+ 支付宝公钥（通知验签）。
	merchantKeyFile := writeFile(t, dir, "merchant-key.pem", string(merchantPriv))
	alipayPubFile := writeFile(t, dir, "alipay-public.pem", string(gatewayPub))
	// mockpay 侧：商户公钥（收银台请求验签）+ 支付宝私钥（通知签名）。
	// 两侧各持半副钥匙：签名/验签方向互为镜像，坏钥在两端都会被拒。
	mockMerchantPubFile := writeFile(t, dir, "mockpay-merchant-pub.pem", string(merchantPub))
	mockGatewayKeyFile := writeFile(t, dir, "mockpay-gateway-key.pem", string(gatewayPriv))

	// trojan 入站与 mockpay 各需一份自签证书（WriteTLSCertFiles 以固定文件名
	// 落盘，两份证书必须隔离目录）。
	trojanCert, trojanKey := writeTLSCertPair(t, dir, "trojan")
	mockCert, mockKey := writeTLSCertPair(t, dir, "mockpay")

	// 控制面地址不在 listening 日志回显、mockpay 日志为 text 格式（records 只
	// 解析 JSON），黑盒统一预选固定环回端口（与控制面用例同一手法）。
	controlAddr := freeFixedPort(t)
	mockAddr := freeFixedPort(t)

	// 账户库预置一个用户（无订阅）：支付延长落在它身上。
	sum256 := sha256.Sum256([]byte(payPassword))
	sum224 := sha256.Sum224([]byte(payPassword))
	accountsFile := writeFile(t, dir, "accounts.json", fmt.Sprintf(
		`{"version":1,"users":[{"username":%q,"password_sha256":%q,"password_sha224":%q,"status":"active"}]}`,
		payUser, hex.EncodeToString(sum256[:]), hex.EncodeToString(sum224[:])))
	// 订单库允许从零生长（缺失 = 空库，与 accounts 的缺失即拒启动不同）。
	ordersFile := filepath.Join(dir, "orders.json")

	// ---- 2. 启动真 mockpay（回环 HTTPS 假支付宝网关）----
	mockProc := startProcess(t, "mockpay", filepath.Join(binDir, "mockpay"),
		"-listen", mockAddr,
		"-cert", mockCert, "-key", mockKey,
		"-merchant-pub", mockMerchantPubFile,
		"-gateway-key", mockGatewayKeyFile,
		"-app-id", appID,
	)
	waitForMockpayReady(t, mockProc, mockAddr)

	// ---- 3. 启动真 proxy-server：accounts + control + payment + 无静态用户的 trojan 入站 ----
	serverConfig := writeFile(t, dir, "server.yaml", fmt.Sprintf(`
log:
  level: info
  format: json
api:
  listen: "127.0.0.1:0"
control:
  listen: %q
accounts:
  file: %q
payment:
  gateway_url: "https://%s/gateway.do"
  app_id: %q
  merchant_key_file: %q
  alipay_public_key_file: %q
  notify_url: "http://%s/notify/alipay"
  orders_file: %q
  period_days: %d
  price_cents: %d
inbounds:
  - type: trojan
    listen: "127.0.0.1:0"
    params:
      cert-file: %q
      key-file: %q
`, controlAddr, accountsFile, mockAddr, appID, merchantKeyFile, alipayPubFile,
		controlAddr, ordersFile, periodDays, priceCents, trojanCert, trojanKey))
	serverProc := startProcess(t, "proxy-server", filepath.Join(binDir, "proxy-server"), "-config", serverConfig)
	serverListen := waitForRecords(t, serverProc, "listening", 1, 10*time.Second)[0]
	serverMetricsAddr := strField(t, serverProc, serverListen, "metrics")
	waitForStatusOK(t, serverMetricsAddr, 10*time.Second)

	// 起点证明：预置用户无订阅（支付延长才有可见效果）。
	startUsers := fetchBody(t, "http://"+controlAddr+"/users")
	if got := subscriptionExpiresAt(t, startUsers, payUser); got != "" {
		t.Fatalf("起点 %s 已有订阅 expires_at=%q, want 无订阅", payUser, got)
	}

	// ---- 4. 控制面下单：POST /orders → 已签名 pay_url 指向 mockpay ----
	orderBody := controlRequest(t, controlAddr, http.MethodPost, "/orders",
		fmt.Sprintf(`{"username":%q}`, payUser), http.StatusCreated)
	var order struct {
		OrderID string `json:"order_id"`
		PayURL  string `json:"pay_url"`
	}
	if err := json.Unmarshal([]byte(orderBody), &order); err != nil {
		t.Fatalf("parse POST /orders response %s: %v", orderBody, err)
	}
	if order.OrderID == "" {
		t.Fatalf("POST /orders 响应缺少 order_id：%s", orderBody)
	}
	wantPrefix := "https://" + mockAddr + "/gateway.do?"
	if !strings.HasPrefix(order.PayURL, wantPrefix) {
		t.Fatalf("pay_url = %q, want 前缀 %q（指向 mockpay 网关）", order.PayURL, wantPrefix)
	}

	// ---- 5. 收银台：GET pay_url（HTTPS，跳过自签校验），有效签名被网关受理 ----
	cashier := httpsGetBody(t, order.PayURL)
	for _, want := range []string{"支付宝收银台", order.OrderID, orderTitle, price + " 元"} {
		if !strings.Contains(cashier, want) {
			t.Fatalf("收银台页缺少 %q：%s", want, cashier)
		}
	}

	// ---- 6. 确认支付：回传隐藏域 + confirm 标记 → mockpay 投递已签名 notify ----
	action, fields := parseCashierForm(t, cashier)
	if !strings.HasPrefix(action, "/gateway.do?") || !strings.Contains(action, "mockpay_action=confirm") {
		t.Fatalf("收银台确认动作 = %q, want /gateway.do 上的 mockpay_action=confirm", action)
	}
	beforeConfirm := time.Now()
	paidPage := httpsPostForm(t, "https://"+mockAddr+action, fields)
	afterConfirm := time.Now()
	if !strings.Contains(paidPage, "支付成功") || !strings.Contains(paidPage, "商户通知：已投递") {
		t.Fatalf("确认支付后的结果页不是「支付成功 + 商户通知已投递」：%s", paidPage)
	}
	tradeNo := parseTradeNo(t, paidPage)
	if tradeNo == "" {
		t.Fatalf("支付结果页的交易号为空：%s", paidPage)
	}

	// ---- 7. 订阅延长：notify 落地，expires_at ≈ 确认时刻 + period_days ----
	lower := beforeConfirm.Add(period).Add(-5 * time.Second)
	upper := afterConfirm.Add(period).Add(5 * time.Second)
	expiresAt := waitForSubscription(t, controlAddr, payUser, 10*time.Second)
	got, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		t.Fatalf("parse subscription.expires_at %q: %v", expiresAt, err)
	}
	if got.Before(lower) || got.After(upper) {
		t.Fatalf("expires_at = %s, want [%s, %s]（确认时刻 + %d 天）",
			got.Format(time.RFC3339), lower.Format(time.RFC3339), upper.Format(time.RFC3339), periodDays)
	}
	usersAfterLand := fetchBody(t, "http://"+controlAddr+"/users")
	ordersAfterLand := readOrdersFile(t, ordersFile)

	// 落地证据链：账户库延长之外，订单库恰好一行且终态 applied（支付路径的
	// 「单次效果」在两份持久化文件上都可观测）。
	if len(ordersAfterLand) != 1 {
		t.Fatalf("订单库行数 = %d, want 1：%v", len(ordersAfterLand), ordersAfterLand)
	}
	o := ordersAfterLand[0]
	if o["order_id"] != order.OrderID || o["username"] != payUser || o["status"] != "applied" ||
		o["trade_no"] != tradeNo || intOf(t, o["amount_cents"]) != priceCents {
		t.Fatalf("订单行与支付事实不符：%v（order_id=%s trade_no=%s price_cents=%d）",
			o, order.OrderID, tradeNo, priceCents)
	}
	// 一笔支付的通知此刻恰好被受理一次（幂等重放会共用 "alipay notify
	// landed" 这条消息，计数断言只在落地点做）。
	if got := len(records(serverProc.logs, "alipay notify landed")); got != 1 {
		t.Errorf("alipay notify landed 日志 = %d 条, want 1（一笔支付恰好落地一次）", got)
	}

	// ---- 8. 幂等（§1.1 I4）：重复确认与同号 notify 重放都不再延长 ----
	// 8a. 收银台重复确认：mockpay 幂等，不再投递通知（商户侧无第二次落地机会）。
	replayPage := httpsPostForm(t, "https://"+mockAddr+action, fields)
	if !strings.Contains(replayPage, "支付成功") || !strings.Contains(replayPage, "通知只投递一次") {
		t.Fatalf("重复确认的结果页未声明幂等：%s", replayPage)
	}
	if got := fetchBody(t, "http://"+controlAddr+"/users"); got != usersAfterLand {
		t.Fatalf("重复确认改变了账户库：\nbefore: %s\nafter:  %s", usersAfterLand, got)
	}
	if got := len(records(serverProc.logs, "alipay notify landed")); got != 1 {
		t.Errorf("重复确认后 alipay notify landed 日志 = %d 条, want 1（mockpay 只投递一次通知）", got)
	}

	// 8b. 同 trade_no 的已签名 notify 重放（网关侧助手重签，内容逐字同原通知）：
	// 控制面验签通过后幂等 ACK（success），订阅不动。落地与幂等应答在服务端
	// 共用 "alipay notify landed" 日志消息，单次效果改由两份账本逐字不变证明。
	gw, err := alipay.NewGateway(alipay.GatewayConfig{
		AppID:          appID,
		MerchantPubPEM: merchantPub,
		NotifyKeyPEM:   gatewayPriv,
	})
	if err != nil {
		t.Fatalf("build alipay gateway helper: %v", err)
	}
	notifyForm, err := gw.BuildNotify(alipay.TradeNotify{
		TradeNo:     tradeNo,
		OutTradeNo:  order.OrderID,
		TotalAmount: price,
		Subject:     orderTitle,
		PaidAt:      beforeConfirm,
	})
	if err != nil {
		t.Fatalf("build replay notify: %v", err)
	}
	if got := postNotify(t, controlAddr, notifyForm, http.StatusOK); got != "success" {
		t.Fatalf("同号 notify 重放应答 = %q, want success（幂等 ACK）", got)
	}
	assertLedgerUnchanged(t, controlAddr, usersAfterLand, ordersFile, ordersAfterLand)

	// ---- 9. 负例：篡改金额的 notify 必被验签拒绝，账本无变化 ----
	// 同钥重签的原通知上改一个字段而保留原签名 = 内容被篡改，验签必败
	//（金额伪造是异步通知要防的核心攻击面）。
	tampered := make(url.Values, len(notifyForm))
	for k, vs := range notifyForm {
		tampered[k] = append([]string(nil), vs...)
	}
	tampered.Set("total_amount", "0.01")
	if got := postNotify(t, controlAddr, tampered, http.StatusBadRequest); got != "fail" {
		t.Fatalf("篡改金额的 notify 应答 = %q, want fail（验签拒绝）", got)
	}
	assertLedgerUnchanged(t, controlAddr, usersAfterLand, ordersFile, ordersAfterLand)
	if got := len(records(serverProc.logs, "alipay notify rejected")); got != 1 {
		t.Errorf("alipay notify rejected 日志 = %d 条, want 1（篡改通知被拒）", got)
	}

	// 进程体面收尾：三个真实二进制都应能优雅退出（与主链路用例同一断言）。
	if err := mockProc.terminate(t, 20*time.Second); err != nil {
		t.Fatalf("mockpay 退出: %v", err)
	}
	if err := serverProc.terminate(t, 20*time.Second); err != nil {
		t.Fatalf("proxy-server 退出: %v", err)
	}
}

// —— 本文件的黑盒辅助（复用 integration_test.go / accounts_control_test.go /
// chaos_test.go 的脚手架）——

// writeTLSCertPair 在 dir 的子目录里生成一份自签 TLS 证书并返回 cert/key 路径。
func writeTLSCertPair(t *testing.T, dir, name string) (certFile, keyFile string) {
	t.Helper()
	sub := filepath.Join(dir, name)
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", sub, err)
	}
	cert, key, err := testutil.WriteTLSCertFiles(sub)
	if err != nil {
		t.Fatalf("write TLS cert %s: %v", name, err)
	}
	return cert, key
}

// httpsClient 返回跳过证书校验的 HTTPS 客户端（mockpay 为本地自签证书）。
func httpsClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // 本地自签证书
			DisableKeepAlives: true,
		},
	}
}

// httpsGetBody GET 指定 HTTPS URL 并要求 200，返回响应体（收银台页）。
func httpsGetBody(t *testing.T, rawURL string) string {
	t.Helper()
	resp, err := httpsClient().Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("GET %s: read body: %v", rawURL, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d, body %s", rawURL, resp.StatusCode, body)
	}
	return string(body)
}

// httpsPostForm 向指定 HTTPS URL POST 表单并要求 200，返回响应体（支付结果页）。
func httpsPostForm(t *testing.T, rawURL string, form url.Values) string {
	t.Helper()
	resp, err := httpsClient().PostForm(rawURL, form)
	if err != nil {
		t.Fatalf("POST %s: %v", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("POST %s: read body: %v", rawURL, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s: status %d, body %s", rawURL, resp.StatusCode, body)
	}
	return string(body)
}

// waitForMockpayReady 轮询 mockpay 的 HTTPS 端口直到有 HTTP 应答（受理端点对
// 空请求回 4xx，任何状态码都证明 TLS 服务已就绪）。进程若提前退出（密钥或
// 证书非法）立即失败并给出日志，避免白等到超时。
func waitForMockpayReady(t *testing.T, p *process, addr string) {
	t.Helper()
	client := httpsClient()
	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get("https://" + addr + "/gateway.do")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			return
		}
		lastErr = err
		select {
		case <-p.exited:
			t.Fatalf("mockpay 在就绪前退出（最后一次错误 %v）：\n%s", lastErr, p.logs.String())
		default:
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("mockpay %s 未在期限内就绪；最后一次错误: %v\n日志:\n%s", addr, lastErr, p.logs.String())
}

// waitForSubscription 轮询 GET /users 直到 username 出现订阅，返回 expires_at
// 原文。通知投递在确认请求内同步完成，轮询只为吸收进程间的时序差。
func waitForSubscription(t *testing.T, controlAddr, username string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		last = fetchBody(t, "http://"+controlAddr+"/users")
		if exp := subscriptionExpiresAt(t, last, username); exp != "" {
			return exp
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("用户 %s 的订阅在 %s 内未出现：GET /users = %s", username, timeout, last)
	return ""
}

// subscriptionExpiresAt 从 GET /users 响应中取 username 的订阅到期时刻；
// 无订阅返回空串，用户不存在即失败（复用 accounts 用例的 JSON 线上形态）。
func subscriptionExpiresAt(t *testing.T, usersJSON, username string) string {
	t.Helper()
	var list controlListResponse
	if err := json.Unmarshal([]byte(usersJSON), &list); err != nil {
		t.Fatalf("parse GET /users response %s: %v", usersJSON, err)
	}
	for _, u := range list.Users {
		if u.Username != username {
			continue
		}
		if u.Subscription == nil {
			return ""
		}
		return u.Subscription.ExpiresAt
	}
	t.Fatalf("GET /users 缺少用户 %s：%s", username, usersJSON)
	return ""
}

// postNotify 把一张 notify 表单 POST 到控制面回调端点，校验状态码并返回
// 响应体（通知协议的线上答案：success | fail）。
func postNotify(t *testing.T, addr string, form url.Values, wantStatus int) string {
	t.Helper()
	resp, err := (&http.Client{Timeout: 5 * time.Second}).PostForm("http://"+addr+"/notify/alipay", form)
	if err != nil {
		t.Fatalf("POST /notify/alipay: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("POST /notify/alipay: read body: %v", err)
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf("POST /notify/alipay = %d %q, want %d", resp.StatusCode, body, wantStatus)
	}
	return string(body)
}

// readOrdersFile 读取订单库持久化文件（进程落盘的 JSON 产物，黑盒可见）并
// 返回订单行切片；文件缺失/损坏即失败（严格加载语义的镜像观察面）。
func readOrdersFile(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read orders file %s: %v", path, err)
	}
	var envelope struct {
		Version int              `json:"version"`
		Orders  []map[string]any `json:"orders"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("parse orders file %s: %v", path, err)
	}
	return envelope.Orders
}

// intOf 读取 JSON 数字字段（encoding/json 统一解码为 float64）。
func intOf(t *testing.T, v any) int64 {
	t.Helper()
	f, ok := v.(float64)
	if !ok {
		t.Fatalf("JSON 数字字段缺失或类型错误: %v (%T)", v, v)
	}
	return int64(f)
}

// assertLedgerUnchanged 断言两份账本（控制面账户视图 + 订单库文件）与落地后
// 快照逐字一致：幂等重放与坏签名通知都不得产生任何账务变化。
func assertLedgerUnchanged(t *testing.T, controlAddr, usersJSON, ordersFile string, orders []map[string]any) {
	t.Helper()
	if got := fetchBody(t, "http://"+controlAddr+"/users"); got != usersJSON {
		t.Fatalf("账户库发生变化：\nbefore: %s\nafter:  %s", usersJSON, got)
	}
	got := readOrdersFile(t, ordersFile)
	if !reflect.DeepEqual(got, orders) {
		t.Fatalf("订单库发生变化：\nbefore: %v\nafter:  %v", orders, got)
	}
}

// 收银台与支付结果页的线上 HTML 形态锚点（mockpay 模板输出；属性值经 HTML
// 转义，解析后逐值还原）。
var (
	cashierFormRe  = regexp.MustCompile(`<form method="POST" action="([^"]*)">`)
	cashierFieldRe = regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)">`)
	tradeNoRe      = regexp.MustCompile(`支付宝交易号</dt><dd>([^<]+)</dd>`)
)

// parseCashierForm 从收银台页解析确认动作目标与全部隐藏域（原样回传的已验签
// 参数）。只按线上 HTML 形态解析，不 import 假网关包（黑盒边界）。
func parseCashierForm(t *testing.T, page string) (string, url.Values) {
	t.Helper()
	m := cashierFormRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("收银台页缺少确认表单：%s", page)
	}
	action := html.UnescapeString(m[1])
	fields := url.Values{}
	for _, f := range cashierFieldRe.FindAllStringSubmatch(page, -1) {
		fields.Set(html.UnescapeString(f[1]), html.UnescapeString(f[2]))
	}
	if len(fields) == 0 {
		t.Fatalf("收银台确认表单没有隐藏域：%s", page)
	}
	return action, fields
}

// parseTradeNo 从支付结果页解析支付宝交易号（notify 重放的幂等键）。
func parseTradeNo(t *testing.T, page string) string {
	t.Helper()
	m := tradeNoRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("支付结果页缺少交易号：%s", page)
	}
	return m[1]
}
