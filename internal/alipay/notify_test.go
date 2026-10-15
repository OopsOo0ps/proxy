package alipay

import (
	"errors"
	"net/url"
	"testing"
)

// TestVerifyNotifyGolden 是异步通知黄金向量：openssl 以网关（支付宝）私钥
// 签出的通知必须验签通过，且解码字段与通知原文逐字段一致。
func TestVerifyNotifyGolden(t *testing.T) {
	got, err := mustClient(t).VerifyNotify(testNotifyForm)
	if err != nil {
		t.Fatalf("VerifyNotify: %v", err)
	}
	want := NotifyParams{
		AppID:       testAppID,
		TradeNo:     "2026101522001400001234567890",
		OutTradeNo:  "T20261015000001",
		TradeStatus: TradeStatusSuccess,
		TotalAmount: "30.00",
		Subject:     "订阅 30 天",
		GmtPayment:  "2026-10-15 12:00:31",
		SignType:    SignTypeRSA2,
		Sign:        testNotifySignGolden,
	}
	if got != want {
		t.Fatalf("通知解码不符：\n got  %+v\n want %+v", got, want)
	}
}

// TestVerifyNotifyEmptyValueExcluded 钉死空值排除规则：空值参数不参与签名
// 串，含空值参数的通知照常验签通过；同一参数一旦有值则必须已签名。
func TestVerifyNotifyEmptyValueExcluded(t *testing.T) {
	form := url.Values{}
	for k, vs := range testNotifyForm {
		form[k] = vs
	}
	form.Set("body", "") // 空值：网关侧不会签它
	if _, err := mustClient(t).VerifyNotify(form); err != nil {
		t.Fatalf("含空值参数的通知必须验签通过: %v", err)
	}
	form.Set("body", "订单描述") // 非空：未签名 ⇒ 必须拒
	if _, err := mustClient(t).VerifyNotify(form); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("未签名的非空参数必须验签失败，got %v", err)
	}
}

// TestVerifyNotifyTampered 钉死「篡改任一签名参数 ⇒ 验签失败」：对通知的
// 每个参与签名的参数逐一做一次篡改（key/value 全覆盖）。
func TestVerifyNotifyTampered(t *testing.T) {
	for key, original := range testNotifyForm {
		if key == "sign_type" {
			continue // sign_type 篡改属形状负例（见 TestVerifyNotifyShapeRejections）
		}
		t.Run(key, func(t *testing.T) {
			form := url.Values{}
			for k, vs := range testNotifyForm {
				form[k] = vs
			}
			form.Set(key, original[0]+"-tampered")
			if _, err := mustClient(t).VerifyNotify(form); !errors.Is(err, ErrSignatureInvalid) {
				t.Fatalf("篡改 %s 必须验签失败，got %v", key, err)
			}
		})
	}
}

// TestVerifyNotifyShapeRejections 钉死通知形状负例：缺 sign、sign_type 非
// RSA2、参数重复、空通知——全部 fail-closed。
func TestVerifyNotifyShapeRejections(t *testing.T) {
	cases := map[string]func(url.Values){
		"missing-sign":      func(f url.Values) { f.Del("sign") },
		"sign-type-empty":   func(f url.Values) { f.Set("sign_type", "") },
		"sign-type-legacy":  func(f url.Values) { f.Set("sign_type", "RSA") },
		"sign-type-unknown": func(f url.Values) { f.Set("sign_type", "RSA3") },
		"multi-valued":      func(f url.Values) { f["total_amount"] = []string{"30.00", "31.00"} },
		"empty-form": func(f url.Values) {
			for k := range f {
				f.Del(k)
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			form := url.Values{}
			for k, vs := range testNotifyForm {
				form[k] = vs
			}
			mutate(form)
			if _, err := mustClient(t).VerifyNotify(form); !errors.Is(err, ErrInvalidNotify) {
				t.Fatalf("必须以 ErrInvalidNotify 拒绝，got %v", err)
			}
		})
	}
}

// TestVerifyNotifyUnreadableSign 钉死 sign 值坏（非 base64）的分类：参数形状
// 完好但签名不可解码，归签名失败（ErrSignatureInvalid）而非形状错误。
func TestVerifyNotifyUnreadableSign(t *testing.T) {
	form := url.Values{}
	for k, vs := range testNotifyForm {
		form[k] = vs
	}
	form.Set("sign", "!!!not base64!!!")
	if _, err := mustClient(t).VerifyNotify(form); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("非 base64 sign 必须以 ErrSignatureInvalid 拒绝，got %v", err)
	}
}

// TestVerifyNotifyWrongKeypair 钉死「换钥失败」负例：把支付宝公钥换成商户
// 公钥（另一对密钥）后，黄金通知签名必须验签失败。
func TestVerifyNotifyWrongKeypair(t *testing.T) {
	cfg := testClientConfig()
	cfg.AlipayKeyPEM = []byte(testMerchantPubPEM)
	cl, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := cl.VerifyNotify(testNotifyForm); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("错误密钥对必须验签失败，got %v", err)
	}
}
