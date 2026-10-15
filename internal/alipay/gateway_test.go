package alipay

import (
	"errors"
	"net/url"
	"testing"
	"time"
)

// mustTestClient 构建黄金密钥的网关侧助手与 merchant 侧客户端（同钥，互为
// 对手盘：Client 签出的请求交给 Gateway 验，Gateway 签出的通知交回 Client
// 验——两个方向的密钥方向性由此互证）。
func mustTestClient(t *testing.T) (*Gateway, *Client) {
	t.Helper()
	gw, err := NewGateway(GatewayConfig{
		AppID:          testAppID,
		MerchantPubPEM: []byte(testMerchantPubPEM),
		NotifyKeyPEM:   []byte(testGatewayKeyPEM),
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	cl, err := New(ClientConfig{
		Gateway:        testGateway,
		AppID:          testAppID,
		MerchantKeyPEM: []byte(testMerchantKeyPEM),
		AlipayKeyPEM:   []byte(testGatewayPubPEM),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return gw, cl
}

// cloneValues 深拷贝参数表（url.Values 无 Clone；负例需在不污染基准表的
// 前提下改写单个字段）。
func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

// TestNewGatewayRejectsBadConfig 钉死网关侧构造的 fail-closed：公钥/私钥
// 槽位错位与垃圾 PEM 一律拒绝。
func TestNewGatewayRejectsBadConfig(t *testing.T) {
	cases := map[string]GatewayConfig{
		"app-id-empty":            {AppID: ""},
		"merchant-pub-is-private": {AppID: testAppID, MerchantPubPEM: []byte(testMerchantKeyPEM)},
		"merchant-pub-garbage":    {AppID: testAppID, MerchantPubPEM: []byte("garbage")},
		"notify-key-is-public":    {AppID: testAppID, NotifyKeyPEM: []byte(testGatewayPubPEM)},
		"notify-key-garbage":      {AppID: testAppID, NotifyKeyPEM: []byte("garbage")},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			gw, err := NewGateway(cfg)
			if err == nil {
				t.Fatalf("构造必须失败")
			}
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("必须命中 ErrInvalidConfig，got %v", err)
			}
			if gw != nil {
				t.Fatalf("失败构造不得返回 Gateway")
			}
		})
	}
}

// TestGatewayVerifyPagePayRoundTrip 互证闭环：Client.PayURL 签出的请求由
// Gateway.VerifyPagePay 验签解析，业务字段与 notify_url 逐字还原。
func TestGatewayVerifyPagePayRoundTrip(t *testing.T) {
	gw, cl := mustTestClient(t)
	want := PayRequest{
		OutTradeNo:  testPayRequest.OutTradeNo,
		TotalAmount: testPayRequest.TotalAmount,
		Subject:     testPayRequest.Subject,
		NotifyURL:   "https://merchant.test/notify",
		ReturnURL:   "https://merchant.test/return",
	}
	raw, err := cl.PayURL(want)
	if err != nil {
		t.Fatalf("PayURL: %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse pay url: %v", err)
	}
	got, err := gw.VerifyPagePay(u.Query())
	if err != nil {
		t.Fatalf("VerifyPagePay: %v", err)
	}
	if got != want {
		t.Fatalf("解析结果不符:\n got  %+v\n want %+v", got, want)
	}
}

// TestGatewayVerifyPagePayRejects 钉死网关侧验签把关（保真机制的实体）：
// 篡改内容 / 换钥 / 缺 sign / 非 RSA2 / method 不符 / app_id 不符 / 参数
// 重复 / biz_content 非法，全部拒绝且错误可按集区分。
func TestGatewayVerifyPagePayRejects(t *testing.T) {
	gw, cl := mustTestClient(t)
	base, err := cl.PayURL(testPayRequest)
	if err != nil {
		t.Fatalf("PayURL: %v", err)
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse pay url: %v", err)
	}
	valid := u.Query()

	// 合法签名 + 非法 biz_content 的组合（客户端 API 产不出，手工重签）：
	// 置空 biz_content 使其退出签名串（空值不参与签名），再手工以商户私钥
	// 签出「无 biz_content」的合法请求。
	unsigned := make(map[string]string, len(valid))
	for k, vs := range valid {
		unsigned[k] = vs[0]
	}
	delete(unsigned, "biz_content")
	unsigned["sign"] = mustSignWithMerchantKey(t, unsigned)
	noBiz := make(url.Values, len(unsigned))
	for k, v := range unsigned {
		noBiz.Set(k, v)
	}

	cases := map[string]struct {
		form url.Values
		want error
	}{
		// 篡改 / 换钥 / 额外未签名参数命中签名类错误（403 语义的依据）。
		"tampered-content": {
			form: func() url.Values {
				f := cloneValues(valid)
				f.Set("timestamp", "2000-01-01 00:00:00")
				return f
			}(),
			want: ErrSignatureInvalid,
		},
		// 其余为形状类错误（400 语义的依据）。
		"missing-sign": {
			form: func() url.Values {
				f := cloneValues(valid)
				f.Del("sign")
				return f
			}(),
			want: ErrInvalidRequest,
		},
		"wrong-sign-type": {
			form: func() url.Values {
				f := cloneValues(valid)
				f.Set("sign_type", "RSA")
				return f
			}(),
			want: ErrInvalidRequest,
		},
		"wrong-method": {
			form: func() url.Values {
				f := cloneValues(valid)
				f.Set("method", "alipay.trade.wap.pay")
				return f
			}(),
			want: ErrInvalidRequest,
		},
		"app-id-mismatch": {
			form: func() url.Values {
				other, err := New(ClientConfig{
					Gateway:        testGateway,
					AppID:          "2026999999999999",
					MerchantKeyPEM: []byte(testMerchantKeyPEM),
					AlipayKeyPEM:   []byte(testGatewayPubPEM),
				})
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				raw, err := other.PayURL(testPayRequest)
				if err != nil {
					t.Fatalf("PayURL: %v", err)
				}
				parsed, err := url.Parse(raw)
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				return parsed.Query()
			}(),
			want: ErrInvalidRequest,
		},
		"duplicate-param": {
			form: func() url.Values {
				f := cloneValues(valid)
				f.Add("timestamp", f.Get("timestamp")) // 同名出现两次：网关拒绝
				return f
			}(),
			want: ErrInvalidRequest,
		},
		"biz-content-missing": {form: noBiz, want: ErrInvalidRequest},
		"biz-content-garbage": {
			form: func() url.Values {
				// biz_content 非法 JSON 且需合法签名覆盖它：手工把非法 JSON 放进
				// 签名串重签（与真实商户手搓请求等价）。
				m := make(map[string]string, len(valid))
				for k, vs := range valid {
					m[k] = vs[0]
				}
				m["biz_content"] = "not-json"
				m["sign"] = mustSignWithMerchantKey(t, m)
				f := make(url.Values, len(m))
				for k, v := range m {
					f.Set(k, v)
				}
				return f
			}(),
			want: ErrInvalidRequest,
		},
		"biz-content-shape": {
			form: func() url.Values {
				// 业务字段形状非法（金额三位小数）且签名覆盖：手工重签。
				m := make(map[string]string, len(valid))
				for k, vs := range valid {
					m[k] = vs[0]
				}
				m["biz_content"] = `{"out_trade_no":"T1","subject":"x","total_amount":"1.234"}`
				m["sign"] = mustSignWithMerchantKey(t, m)
				f := make(url.Values, len(m))
				for k, v := range m {
					f.Set(k, v)
				}
				return f
			}(),
			want: ErrInvalidRequest,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := gw.VerifyPagePay(tc.form)
			if !errors.Is(err, tc.want) {
				t.Fatalf("错误类别不符，got %v", err)
			}
		})
	}
}

// mustSignWithMerchantKey 以黄金商户私钥对参数表重签（测试专用：构造
// 「合法签名 + 非法业务内容」的网关负例输入）。
func mustSignWithMerchantKey(t *testing.T, params map[string]string) string {
	t.Helper()
	key, err := parsePrivateKey([]byte(testMerchantKeyPEM), "test merchant key")
	if err != nil {
		t.Fatalf("parse merchant key: %v", err)
	}
	sig, err := signRSA(key, []byte(signContent(params)))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sig
}

// TestGatewayBuildNotify 互证通知方向：Gateway 以支付宝私钥签出的 TRADE_SUCCESS
// 通知，被 merchant 侧 Client.VerifyNotify（支付宝公钥）验签通过，字段逐字还原。
func TestGatewayBuildNotify(t *testing.T) {
	gw, cl := mustTestClient(t)
	paidAt := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	form, err := gw.BuildNotify(TradeNotify{
		TradeNo:     "2026101522001400001234567890",
		OutTradeNo:  testPayRequest.OutTradeNo,
		TotalAmount: testPayRequest.TotalAmount,
		Subject:     testPayRequest.Subject,
		PaidAt:      paidAt,
	})
	if err != nil {
		t.Fatalf("BuildNotify: %v", err)
	}
	if form.Get("trade_status") != string(TradeStatusSuccess) {
		t.Fatalf("trade_status = %q, want %s", form.Get("trade_status"), TradeStatusSuccess)
	}
	if form.Get("sign_type") != SignTypeRSA2 || form.Get("sign") == "" {
		t.Fatalf("通知必须携带 sign_type=RSA2 与 sign: %v", form)
	}
	if form.Get("gmt_payment") != "2026-10-15 20:00:00" {
		t.Fatalf("gmt_payment 必须为 GMT+8 墙钟，got %q", form.Get("gmt_payment"))
	}
	np, err := cl.VerifyNotify(form)
	if err != nil {
		t.Fatalf("VerifyNotify: %v", err)
	}
	if np.TradeNo != "2026101522001400001234567890" || np.OutTradeNo != testPayRequest.OutTradeNo ||
		np.TotalAmount != testPayRequest.TotalAmount || np.TradeStatus != TradeStatusSuccess {
		t.Fatalf("验签后字段不符: %+v", np)
	}
}

// TestGatewayBuildNotifyRejects 钉死通知组装的把关：交易号 / 订单号缺失、
// 金额形状非法一律拒绝（trade_no 是商户侧幂等键，空值不得外发）。
func TestGatewayBuildNotifyRejects(t *testing.T) {
	gw, _ := mustTestClient(t)
	base := TradeNotify{
		TradeNo:     "2026101522001400001234567890",
		OutTradeNo:  "T1",
		TotalAmount: "30.00",
		Subject:     "x",
		PaidAt:      time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC),
	}
	cases := map[string]func(*TradeNotify){
		"trade-no-empty":     func(n *TradeNotify) { n.TradeNo = "" },
		"out-trade-no-empty": func(n *TradeNotify) { n.OutTradeNo = "" },
		"amount-bad-shape":   func(n *TradeNotify) { n.TotalAmount = "1.234" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			n := base
			mutate(&n)
			if _, err := gw.BuildNotify(n); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("必须以 ErrInvalidRequest 拒绝，got %v", err)
			}
		})
	}
}
