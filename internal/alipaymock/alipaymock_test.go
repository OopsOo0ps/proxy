package alipaymock

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/alipay"
)

// 测试密钥（hermetic，设计书 §5）：一次性生成的 RSA2 2048 密钥——商户对
// （签名 page.pay 请求 / 网关验签）、支付宝对（网关签 notify / 商户验签）、
// 第三方对（非受理商户的换钥负例）。与 alipay 包黄金测试的密钥互不相干。
var (
	testPEMOnce sync.Once
	testPEMPair [6][]byte
)

// mustPEMs 展开一次性测试密钥：
// 商户私钥 / 商户公钥 / 支付宝私钥 / 支付宝公钥 / 第三方私钥 / 第三方公钥。
func mustPEMs(t *testing.T) [6][]byte {
	t.Helper()
	testPEMOnce.Do(func() {
		merchantPriv := mustKey(rsa.GenerateKey(rand.Reader, 2048))
		gatewayPriv := mustKey(rsa.GenerateKey(rand.Reader, 2048))
		otherPriv := mustKey(rsa.GenerateKey(rand.Reader, 2048))
		testPEMPair = [6][]byte{
			pemPrivate(mustDER(x509.MarshalPKCS8PrivateKey(merchantPriv))),
			pemPublic(&merchantPriv.PublicKey),
			pemPrivate(mustDER(x509.MarshalPKCS8PrivateKey(gatewayPriv))),
			pemPublic(&gatewayPriv.PublicKey),
			pemPrivate(mustDER(x509.MarshalPKCS8PrivateKey(otherPriv))),
			pemPublic(&otherPriv.PublicKey),
		}
	})
	return testPEMPair
}

// mustKey / mustDER 把「不会失败的测试密钥构造」收敛为 panic（失败即测试
// 编程错误，不值得错误传播样板）。
func mustKey(priv *rsa.PrivateKey, err error) *rsa.PrivateKey {
	if err != nil {
		panic(err)
	}
	return priv
}

func mustDER(der []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return der
}

// pemPublic / pemPrivate 把 DER 包成 PEM（与真实密钥文件的块型一致）。
func pemPrivate(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func pemPublic(key any) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: mustDER(x509.MarshalPKIXPublicKey(key))})
}

// 固定订单要素与假时钟（gmt_payment 断言用：UTC 12:00 = GMT+8 20:00）。
const (
	testOutTradeNo = "T20261015000001"
	testSubject    = "订阅 30 天"
	testAmount     = "30.00"
	testAppID      = "2026000000000000"
)

var testNow = func() time.Time { return time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC) }

// cloneValues 深拷贝参数表（url.Values 无 Clone；负例需在不污染基准表的
// 前提下改写单个字段）。
func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

// newHandler 构建被测假网关（默认：测试密钥 + 固定时钟；mutate 可改写任一项）。
func newHandler(t *testing.T, mutate func(*Options)) http.Handler {
	t.Helper()
	keys := mustPEMs(t)
	opts := Options{
		AppID:          testAppID,
		MerchantPubPEM: keys[1],
		NotifyKeyPEM:   keys[2],
		Now:            testNow,
	}
	if mutate != nil {
		mutate(&opts)
	}
	h, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

// newClientWith 构建 merchant 侧 alipay.Client（appID 可换、商户钥可选第三方，
// 供 app_id / 换钥负例）：以商户私钥签 page.pay 请求、以支付宝公钥验 notify
// ——与生产对接方式逐字一致（复用 internal/alipay）。
func newClientWith(t *testing.T, appID string, otherMerchant bool) *alipay.Client {
	t.Helper()
	keys := mustPEMs(t)
	key := keys[0]
	if otherMerchant {
		key = keys[4]
	}
	cl, err := alipay.New(alipay.ClientConfig{
		Gateway:        "https://gateway.test/gateway.do",
		AppID:          appID,
		MerchantKeyPEM: key,
		AlipayKeyPEM:   keys[3],
	})
	if err != nil {
		t.Fatalf("alipay.New: %v", err)
	}
	return cl
}

func newClient(t *testing.T) *alipay.Client {
	t.Helper()
	return newClientWith(t, testAppID, false)
}

// payForm 经真实 Client.PayURL 产出已签名 page.pay 参数表（表单语义解码后
// 的 url.Values，与网关收到的 form 逐字一致）。
func payForm(t *testing.T, cl *alipay.Client, notifyURL string) url.Values {
	t.Helper()
	raw, err := cl.PayURL(alipay.PayRequest{
		OutTradeNo:  testOutTradeNo,
		TotalAmount: testAmount,
		Subject:     testSubject,
		NotifyURL:   notifyURL,
	})
	if err != nil {
		t.Fatalf("PayURL: %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse pay url: %v", err)
	}
	return u.Query()
}

// get / postForm 把参数表投给被测网关（page.pay 的两种真实介质）。
func get(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func postForm(t *testing.T, h http.Handler, target string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// notifyRecorder 是商户 notify_url 假件：记录收到的每一笔通知表单。
type notifyRecorder struct {
	mu  sync.Mutex
	got []url.Values
}

func (n *notifyRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	n.mu.Lock()
	n.got = append(n.got, cloneValues(r.Form))
	n.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (n *notifyRecorder) received() []url.Values {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]url.Values(nil), n.got...)
}

// startRecorder 起一个本地通知接收器，返回其 /notify 地址。
func startRecorder(t *testing.T) (*notifyRecorder, string) {
	t.Helper()
	rec := &notifyRecorder{}
	srv := httptest.NewServer(rec)
	t.Cleanup(srv.Close)
	return rec, srv.URL + "/notify"
}

// TestNewRejectsBadOptions 钉死构造期 fail-closed：非法 app_id、密钥形状
// 错位（公钥进私钥槽 / 私钥进公钥槽）、垃圾 PEM、负超时一律拒绝。
func TestNewRejectsBadOptions(t *testing.T) {
	keys := mustPEMs(t)
	cases := map[string]func(*Options){
		"app-id-empty":            func(o *Options) { o.AppID = "" },
		"app-id-crlf":             func(o *Options) { o.AppID = "2026\r\n0000" },
		"merchant-pub-garbage":    func(o *Options) { o.MerchantPubPEM = []byte("garbage") },
		"merchant-pub-is-private": func(o *Options) { o.MerchantPubPEM = keys[0] },
		"notify-key-is-public":    func(o *Options) { o.NotifyKeyPEM = keys[3] },
		"notify-key-garbage":      func(o *Options) { o.NotifyKeyPEM = []byte("garbage") },
		"notify-timeout-negative": func(o *Options) { o.NotifyTimeout = -time.Second },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			opts := Options{AppID: testAppID, MerchantPubPEM: keys[1], NotifyKeyPEM: keys[2]}
			mutate(&opts)
			h, err := New(opts)
			if err == nil {
				t.Fatalf("构造必须失败")
			}
			if h != nil {
				t.Fatalf("失败构造不得返回 handler")
			}
		})
	}
	// 合法构造（缺省时钟与超时）必须成功。
	if _, err := New(Options{AppID: testAppID, MerchantPubPEM: keys[1], NotifyKeyPEM: keys[2]}); err != nil {
		t.Fatalf("New: %v", err)
	}
}

// TestBadSignatureRejected 是保真验收的核心负例（设计书 §5）：篡改参数、
// 垃圾签名、缺 sign、不在签名内的额外参数、非受理商户的合法 RSA2 签名
// ——收到的内容未被签名覆盖（或签名本身不可用）一律 403 显式拒绝，无收
// 银台页、无通知；缺 sign 这类形状缺失为 400。
func TestBadSignatureRejected(t *testing.T) {
	h := newHandler(t, nil)
	rec, notifyURL := startRecorder(t)
	valid := payForm(t, newClient(t), notifyURL)

	tamperAmount := cloneValues(valid)
	tamperAmount.Set("biz_content", `{"out_trade_no":"`+testOutTradeNo+`","subject":"`+testSubject+`","total_amount":"0.01"}`)
	tamperTimestamp := cloneValues(valid)
	tamperTimestamp.Set("timestamp", "2026-10-15 00:00:00") // 签名覆盖字段被篡改
	garbageSign := cloneValues(valid)
	garbageSign.Set("sign", "!!!not-base64!!!")
	missingSign := cloneValues(valid)
	missingSign.Del("sign")
	extraParam := cloneValues(valid)
	extraParam.Set("extra_param", "x") // 不在签名内：规范化后签名必不复

	cases := map[string]struct {
		want int
		form url.Values
	}{
		"tampered-amount":    {http.StatusForbidden, tamperAmount},
		"tampered-timestamp": {http.StatusForbidden, tamperTimestamp},
		"garbage-sign":       {http.StatusForbidden, garbageSign},
		"extra-unsigned":     {http.StatusForbidden, extraParam},
		"missing-sign":       {http.StatusBadRequest, missingSign},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			resp := get(t, h, "/gateway.do?"+tc.form.Encode())
			if resp.Code != tc.want {
				t.Fatalf("status = %d, want %d（body: %s）", resp.Code, tc.want, resp.Body)
			}
			if strings.Contains(resp.Body.String(), "收银台") || strings.Contains(resp.Body.String(), testOutTradeNo) {
				t.Fatalf("坏签名不得渲染收银台页: %s", resp.Body)
			}
		})
	}

	// 换钥负例：合法 RSA2 签名但出自非受理商户的私钥——网关必须拒绝。
	other := payForm(t, newClientWith(t, testAppID, true), notifyURL)
	if resp := get(t, h, "/gateway.do?"+other.Encode()); resp.Code != http.StatusForbidden {
		t.Fatalf("非受理商户签名 status = %d, want 403（body: %s）", resp.Code, resp.Body)
	}

	// 全部负例都不得触发任何通知。
	if got := rec.received(); len(got) != 0 {
		t.Fatalf("坏签名不得触发通知，got %d 笔", len(got))
	}
}

// TestValidRequestServesCashierPage 验收有效请求：GET 与 POST 两种介质都
// 渲染收银台页（订单要素 + 确认动作），且不触发通知。
func TestValidRequestServesCashierPage(t *testing.T) {
	rec, notifyURL := startRecorder(t)
	form := payForm(t, newClient(t), notifyURL)

	t.Run("get-query", func(t *testing.T) {
		h := newHandler(t, nil)
		resp := get(t, h, "/gateway.do?"+form.Encode())
		if resp.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200（body: %s）", resp.Code, resp.Body)
		}
		if ct := resp.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
			t.Fatalf("Content-Type = %q, want text/html", ct)
		}
		body := resp.Body.String()
		for _, want := range []string{testOutTradeNo, testSubject, testAmount + " 元", "确认支付", confirmAction + "=" + confirmValue} {
			if !strings.Contains(body, want) {
				t.Fatalf("收银台页缺少 %q:\n%s", want, body)
			}
		}
		if got := rec.received(); len(got) != 0 {
			t.Fatalf("浏览收银台不得触发通知，got %d 笔", len(got))
		}
	})
	t.Run("post-form", func(t *testing.T) {
		h := newHandler(t, nil)
		resp := postForm(t, h, "/gateway.do", form)
		if resp.Code != http.StatusOK || !strings.Contains(resp.Body.String(), testOutTradeNo) {
			t.Fatalf("POST form 受理失败: status=%d body=%s", resp.Code, resp.Body)
		}
	})
}

// TestConfirmSendsSignedNotifyVerifiableByAlipay 验收闭环：确认支付后，
// notify_url 收到一笔真实字段、可被 internal/alipay 验签通过的异步通知。
func TestConfirmSendsSignedNotifyVerifiableByAlipay(t *testing.T) {
	h := newHandler(t, nil)
	rec, notifyURL := startRecorder(t)
	form := payForm(t, newClient(t), notifyURL)

	if resp := get(t, h, "/gateway.do?"+form.Encode()); resp.Code != http.StatusOK {
		t.Fatalf("page.pay: status = %d（body: %s）", resp.Code, resp.Body)
	}
	resp := postForm(t, h, confirmTarget("/gateway.do"), form)
	if resp.Code != http.StatusOK {
		t.Fatalf("confirm: status = %d（body: %s）", resp.Code, resp.Body)
	}

	got := rec.received()
	if len(got) != 1 {
		t.Fatalf("通知笔数 = %d, want 1", len(got))
	}
	notify := got[0]
	want := url.Values{
		"app_id":       {testAppID},
		"charset":      {"utf-8"},
		"gmt_payment":  {"2026-10-15 20:00:00"}, // Now 注入生效（GMT+8 墙钟）
		"out_trade_no": {testOutTradeNo},
		"subject":      {testSubject},
		"total_amount": {testAmount},
		"trade_status": {"TRADE_SUCCESS"},
		"sign_type":    {"RSA2"},
	}
	for k, vs := range want {
		if got := notify.Get(k); got != vs[0] {
			t.Fatalf("通知字段 %s = %q, want %q（全部字段: %v）", k, got, vs[0], notify)
		}
	}
	if notify.Get("trade_no") == "" {
		t.Fatalf("通知必须携带 trade_no")
	}
	if notify.Get("sign") == "" {
		t.Fatalf("通知必须携带 sign")
	}

	// 商户侧以支付宝公钥经 internal/alipay 验签：必须通过且字段还原一致。
	np, err := newClient(t).VerifyNotify(notify)
	if err != nil {
		t.Fatalf("alipay 验签失败: %v", err)
	}
	if np.AppID != testAppID || np.OutTradeNo != testOutTradeNo || np.TotalAmount != testAmount ||
		np.TradeStatus != alipay.TradeStatusSuccess || np.GmtPayment != "2026-10-15 20:00:00" {
		t.Fatalf("验签后字段不符: %+v", np)
	}

	// 确认结果页应展示交易号。
	if !strings.Contains(resp.Body.String(), np.TradeNo) {
		t.Fatalf("支付结果页缺少交易号 %q:\n%s", np.TradeNo, resp.Body)
	}
}

// TestConfirmReplayIsSingleEffect 验收重放幂等：同单重复确认（含重新下单
// 后再确认）单效果——通知只投递一次。
func TestConfirmReplayIsSingleEffect(t *testing.T) {
	h := newHandler(t, nil)
	rec, notifyURL := startRecorder(t)
	form := payForm(t, newClient(t), notifyURL)

	first := postForm(t, h, confirmTarget("/gateway.do"), form)
	if first.Code != http.StatusOK {
		t.Fatalf("首次确认: status = %d（body: %s）", first.Code, first.Body)
	}
	// 重新下单（同一 out_trade_no）后再确认：仍不得产生第二笔通知。
	if resp := get(t, h, "/gateway.do?"+form.Encode()); resp.Code != http.StatusOK {
		t.Fatalf("重复下单: status = %d", resp.Code)
	}
	second := postForm(t, h, confirmTarget("/gateway.do"), form)
	if second.Code != http.StatusOK {
		t.Fatalf("重复确认: status = %d（body: %s）", second.Code, second.Body)
	}
	if !strings.Contains(second.Body.String(), "重复确认") {
		t.Fatalf("重复确认结果页应说明幂等语义:\n%s", second.Body)
	}
	got := rec.received()
	if len(got) != 1 {
		t.Fatalf("通知笔数 = %d, want 1（重放必须单效果）", len(got))
	}
	if got[0].Get("trade_status") != "TRADE_SUCCESS" {
		t.Fatalf("通知状态不符: %v", got[0])
	}
}

// TestConcurrentConfirmSingleNotify 在 -race 下摇幂等窗口：并发确认同一
// 订单，通知必须恰好一笔、全部请求 200。
func TestConcurrentConfirmSingleNotify(t *testing.T) {
	h := newHandler(t, nil)
	rec, notifyURL := startRecorder(t)
	form := payForm(t, newClient(t), notifyURL)
	if resp := get(t, h, "/gateway.do?"+form.Encode()); resp.Code != http.StatusOK {
		t.Fatalf("page.pay: status = %d", resp.Code)
	}

	const workers = 8
	codes := make(chan int, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- postForm(t, h, confirmTarget("/gateway.do"), form).Code
		}()
	}
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != http.StatusOK {
			t.Fatalf("并发确认出现非 200: %d", code)
		}
	}
	if got := rec.received(); len(got) != 1 {
		t.Fatalf("通知笔数 = %d, want 1（并发重放必须单效果）", len(got))
	}
}

// TestDeterministicTradeNoAcrossInstances 验收「按 out_trade_no 确定」：
// 交易号由订单号确定性派生——换一个 handler 实例（模拟进程重启）同单同号，
// 形状为 28 位十六进制流水（对齐真实 trade_no 的定长口径）。
func TestDeterministicTradeNoAcrossInstances(t *testing.T) {
	rec, notifyURL := startRecorder(t)
	form := payForm(t, newClient(t), notifyURL)
	for i := 0; i < 2; i++ {
		h := newHandler(t, nil)
		if resp := postForm(t, h, confirmTarget("/gateway.do"), form); resp.Code != http.StatusOK {
			t.Fatalf("confirm #%d: status = %d", i, resp.Code)
		}
	}
	tradeNo := ""
	for _, notify := range rec.received() {
		if tradeNo == "" {
			tradeNo = notify.Get("trade_no")
			continue
		}
		if notify.Get("trade_no") != tradeNo {
			t.Fatalf("同单跨实例交易号漂移: %q vs %q", tradeNo, notify.Get("trade_no"))
		}
	}
	if !regexp.MustCompile(`^[0-9a-f]{28}$`).MatchString(tradeNo) {
		t.Fatalf("trade_no 形状非法: %q", tradeNo)
	}
}

// TestNotifyDeliveryFailureSurfaced 验收投递失败的行为：支付事实已成立
// （200），结果页显式说明投递失败（假件不做重试，失败不静默）。
func TestNotifyDeliveryFailureSurfaced(t *testing.T) {
	h := newHandler(t, nil)
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close() // 已关闭端口 = 投递必然失败
	form := payForm(t, newClient(t), deadURL+"/notify")

	resp := postForm(t, h, confirmTarget("/gateway.do"), form)
	if resp.Code != http.StatusOK {
		t.Fatalf("支付事实成立，confirm 必须 200，got %d", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), "投递失败") {
		t.Fatalf("结果页必须说明投递失败:\n%s", resp.Body)
	}
}

// TestRejectsMalformedRequests 验收形状负例：缺 method、app_id 不符（合法
// 签名、错应用——网关按 app_id 选钥，先于验签拒绝）、空表单——全部 400
// 显式拒绝。biz_content 解析把关需「合法签名 + 非法 biz_content」的组合，
// 客户端 API 产不出该形状，归 internal/alipay 的 Gateway 单测覆盖。
func TestRejectsMalformedRequests(t *testing.T) {
	h := newHandler(t, nil)
	rec, notifyURL := startRecorder(t)
	valid := payForm(t, newClient(t), notifyURL)

	missingMethod := cloneValues(valid)
	missingMethod.Del("method")

	cases := map[string]url.Values{
		"empty-form":      {},
		"missing-method":  missingMethod,
		"app-id-mismatch": payForm(t, newClientWith(t, "2026888888888888", false), notifyURL),
	}
	for name, form := range cases {
		t.Run(name, func(t *testing.T) {
			resp := get(t, h, "/gateway.do?"+form.Encode())
			if resp.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400（body: %s）", resp.Code, resp.Body)
			}
		})
	}
	if got := rec.received(); len(got) != 0 {
		t.Fatalf("形状负例不得触发通知，got %d 笔", len(got))
	}
}

// TestNowInjectionAffectsGmtPayment 钉死时间注入：改写 Options.Now 即改变
// gmt_payment（缺省 time.Now 的路径由 mockpay 冒烟覆盖）。
func TestNowInjectionAffectsGmtPayment(t *testing.T) {
	h := newHandler(t, func(o *Options) {
		o.Now = func() time.Time { return time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC) }
	})
	rec, notifyURL := startRecorder(t)
	form := payForm(t, newClient(t), notifyURL)
	if resp := postForm(t, h, confirmTarget("/gateway.do"), form); resp.Code != http.StatusOK {
		t.Fatalf("confirm: status = %d（body: %s）", resp.Code, resp.Body)
	}
	got := rec.received()
	if len(got) != 1 || got[0].Get("gmt_payment") != "2027-01-02 11:04:05" {
		t.Fatalf("Now 注入未生效: %v", got)
	}
}
