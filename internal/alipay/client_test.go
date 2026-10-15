package alipay

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// stubRT 是可比较的测试 RoundTripper（传输注入语义断言用；struct 保可比较，
// 函数类型做接口比较会 panic）。
type stubRT struct{ id int }

func (stubRT) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("stub transport")
}

// TestNewRejectsBadConfig 钉死构造期 fail-closed：非 https 网关（设计书 §5
// 的关键负例）、缺 host、带 query/fragment、密钥 PEM 形状错位、非法 app_id。
func TestNewRejectsBadConfig(t *testing.T) {
	cases := map[string]func(*ClientConfig){
		"gateway-empty":      func(c *ClientConfig) { c.Gateway = "" },
		"gateway-http":       func(c *ClientConfig) { c.Gateway = "http://gateway.test/gateway.do" },
		"gateway-ftp":        func(c *ClientConfig) { c.Gateway = "ftp://gateway.test/gateway.do" },
		"gateway-no-host":    func(c *ClientConfig) { c.Gateway = "https:///gateway.do" },
		"gateway-with-query": func(c *ClientConfig) { c.Gateway = "https://gateway.test/gateway.do?x=1" },
		"gateway-fragment":   func(c *ClientConfig) { c.Gateway = "https://gateway.test/gateway.do#frag" },
		"app-id-empty":       func(c *ClientConfig) { c.AppID = "" },
		"app-id-cr-lf":       func(c *ClientConfig) { c.AppID = "2026\r\n0000" },
		"merchant-key-is-public-key": func(c *ClientConfig) {
			c.MerchantKeyPEM = []byte(testMerchantPubPEM) // 公钥放进私钥槽位
		},
		"alipay-key-is-private-key": func(c *ClientConfig) {
			c.AlipayKeyPEM = []byte(testGatewayKeyPEM) // 私钥放进公钥槽位
		},
		"merchant-key-garbage": func(c *ClientConfig) { c.MerchantKeyPEM = []byte("garbage") },
		"alipay-key-garbage":   func(c *ClientConfig) { c.AlipayKeyPEM = []byte("garbage") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := testClientConfig()
			mutate(&cfg)
			cl, err := New(cfg)
			if err == nil {
				t.Fatalf("构造必须失败")
			}
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("必须命中 ErrInvalidConfig，got %v", err)
			}
			if cl != nil {
				t.Fatalf("失败构造不得返回 Client")
			}
		})
	}
}

// TestNewKeepsTransportInjection 钉死传输注入语义：指针原样保存（持有方可
// 热替换）、nil 缺省合法。
func TestNewKeepsTransportInjection(t *testing.T) {
	tr := http.RoundTripper(http.DefaultTransport)
	cfg := testClientConfig()
	cfg.HTTP = &tr
	cl, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if cl.transport != &tr {
		t.Fatalf("注入的 RoundTripper 指针必须原样保存")
	}
	swapped := http.RoundTripper(stubRT{id: 2})
	*cfg.HTTP = swapped // 持有方热替换
	if cl.transport != &tr || *cl.transport != swapped {
		t.Fatalf("热替换后 Client 必须经同一指针看到新传输")
	}

	def, err := New(testClientConfig()) // HTTP 未注入
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if def.transport != nil {
		t.Fatalf("未注入时 transport 必须为 nil（缺省 http.DefaultTransport）")
	}
}

// TestPayURLGolden 是下单 URL 的黄金向量：时钟固定 ⇒ 待签名串与黄金内容
// 一致 ⇒ 签名与 openssl 黄金签名逐字一致；URL 可解析、参数可还原、独立
// 用商户公钥复验通过（round-trip 可解析性）。
func TestPayURLGolden(t *testing.T) {
	cl := mustClient(t)
	got, err := cl.PayURL(testPayRequest)
	if err != nil {
		t.Fatalf("PayURL: %v", err)
	}
	if !strings.HasPrefix(got, testGateway+"?") {
		t.Fatalf("URL 必须以网关基地址开头，got %s", got)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("url.Parse(%s): %v", got, err)
	}
	q := u.Query()
	wantParams := map[string]string{
		"app_id":      testAppID,
		"method":      MethodPagePay,
		"charset":     CharsetUTF8,
		"sign_type":   SignTypeRSA2,
		"timestamp":   "2026-10-15 12:00:00", // Now 注入生效（GMT+8 墙钟）
		"version":     Version,
		"biz_content": testBizContent,
		"sign":        testSignGolden, // 确定性签名 == openssl 黄金向量
	}
	for k, want := range wantParams {
		if got := q.Get(k); got != want {
			t.Fatalf("参数 %s = %q, want %q", k, got, want)
		}
	}
	if _, ok := q["notify_url"]; ok {
		t.Fatalf("未设置 notify_url 时参数必须省略")
	}
	if _, ok := q["return_url"]; ok {
		t.Fatalf("未设置 return_url 时参数必须省略")
	}
	// round-trip：从 URL 还原的参数重算规范化串必须等于黄金待签名串。
	m := make(map[string]string, len(q))
	for k, vs := range q {
		m[k] = vs[0]
	}
	if signContent(m) != testSignContent {
		t.Fatalf("round-trip 重算待签名串不符：\n got  %s\n want %s", signContent(m), testSignContent)
	}
	// 独立复验：不用 Client 内部私钥，用商户公钥验证签名。
	if err := verifyRSA(mustMerchantPub(t), []byte(testSignContent), q.Get("sign")); err != nil {
		t.Fatalf("商户公钥复验失败: %v", err)
	}
}

// TestPayURLOptionalParams 钉死 notify_url / return_url 的组装与 URL 形状把关。
func TestPayURLOptionalParams(t *testing.T) {
	cl := mustClient(t)
	req := testPayRequest
	req.NotifyURL = "https://merchant.test/notify"
	req.ReturnURL = "https://merchant.test/return"
	got, err := cl.PayURL(req)
	if err != nil {
		t.Fatalf("PayURL: %v", err)
	}
	q, err := url.Parse(got)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	if qv := q.Query(); qv.Get("notify_url") != req.NotifyURL || qv.Get("return_url") != req.ReturnURL {
		t.Fatalf("可选参数未按原样进入 query：%v", qv)
	}
}

// TestPayURLSignFailsAgainstWrongKey 钉死「换钥失败」负例：用支付宝公钥
// （而非商户公钥）复验下单签名必须失败。
func TestPayURLSignFailsAgainstWrongKey(t *testing.T) {
	cl := mustClient(t)
	got, err := cl.PayURL(testPayRequest)
	if err != nil {
		t.Fatalf("PayURL: %v", err)
	}
	q, err := url.Parse(got)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	if err := verifyRSA(mustGatewayPub(t), []byte(testSignContent), q.Query().Get("sign")); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("错误密钥对的复验必须失败，got %v", err)
	}
}

// TestPayURLValidation 钉死下单参数把关：形状非法一律 ErrInvalidRequest。
func TestPayURLValidation(t *testing.T) {
	cases := map[string]func(*PayRequest){
		"out-trade-no-empty": func(r *PayRequest) { r.OutTradeNo = "" },
		"out-trade-no-blank": func(r *PayRequest) { r.OutTradeNo = "   " },
		"out-trade-no-crlf":  func(r *PayRequest) { r.OutTradeNo = "T1\r\nX" },
		"out-trade-no-long":  func(r *PayRequest) { r.OutTradeNo = strings.Repeat("T", maxOutTradeNoLen+1) },
		"amount-empty":       func(r *PayRequest) { r.TotalAmount = "" },
		"amount-not-decimal": func(r *PayRequest) { r.TotalAmount = "三十元" },
		"amount-3-digits":    func(r *PayRequest) { r.TotalAmount = "1.234" },
		"amount-negative":    func(r *PayRequest) { r.TotalAmount = "-1.00" },
		"subject-empty":      func(r *PayRequest) { r.Subject = "" },
		"subject-crlf":       func(r *PayRequest) { r.Subject = "订阅\r\n30 天" },
		"notify-url-bad":     func(r *PayRequest) { r.NotifyURL = "notaurl" },
		"notify-url-ftp":     func(r *PayRequest) { r.NotifyURL = "ftp://merchant.test/notify" },
		"return-url-crlf":    func(r *PayRequest) { r.ReturnURL = "https://m.test/\r\nr" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			req := testPayRequest
			mutate(&req)
			if _, err := mustClient(t).PayURL(req); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("必须以 ErrInvalidRequest 拒绝，got %v", err)
			}
		})
	}
}

// TestPayURLGeneratedKeypairRoundTrip 用运行时生成的密钥对（非黄金密钥）
// 证明通用性：任意合法 RSA2 2048 密钥的签名 URL 均可解析并复验。
func TestPayURLGeneratedKeypairRoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal privkey: %v", err)
	}
	cfg := testClientConfig()
	cfg.Gateway = "https://127.0.0.1:8443/gateway.do"
	cfg.MerchantKeyPEM = pemPrivate(privDER)
	cfg.AlipayKeyPEM = pemPublic(pubDER)
	cl, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := cl.PayURL(testPayRequest)
	if err != nil {
		t.Fatalf("PayURL: %v", err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	q := u.Query()
	if u.Scheme != "https" || u.Host != "127.0.0.1:8443" || u.Path != "/gateway.do" {
		t.Fatalf("网关地址未正确承载：%s", got)
	}
	m := make(map[string]string, len(q))
	for k, vs := range q {
		m[k] = vs[0]
	}
	if err := verifyRSA(&priv.PublicKey, []byte(signContent(m)), m["sign"]); err != nil {
		t.Fatalf("生成密钥对的签名复验失败: %v", err)
	}
}

// TestClientConcurrentUse 是并发冒烟：构造后的 Client 只读，PayURL 与
// VerifyNotify 可安全并发（-race 守护）。
func TestClientConcurrentUse(t *testing.T) {
	cl := mustClient(t)
	const workers, iters = 8, 25
	var wg sync.WaitGroup
	errs := make(chan error, workers*iters*2)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				if _, err := cl.PayURL(testPayRequest); err != nil {
					errs <- err
					return
				}
				if _, err := cl.VerifyNotify(testNotifyForm); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("并发使用出错: %v", err)
	}
}
