package alipay

import (
	"errors"
	"net/url"
	"testing"
)

// TestSignContentRules 钉死 RSA2 规范化四规则：参数名升序、剔除空值、剔除
// sign/sign_type、值保持原文。map 迭代序随机，排序正确性由逐次运行共同证明。
func TestSignContentRules(t *testing.T) {
	got := signContent(map[string]string{
		"version":     Version,
		"timestamp":   "2026-10-15 12:00:00",
		"method":      MethodPagePay,
		"charset":     CharsetUTF8,
		"sign_type":   SignTypeRSA2,       // 自指排除
		"sign":        "must-be-excluded", // 自指排除
		"notify_url":  "",                 // 空值排除
		"return_url":  "",                 // 空值排除
		"biz_content": testBizContent,     // 含空格与中文的原文
		"app_id":      testAppID,
	})
	if got != testSignContent {
		t.Fatalf("signContent 规范化不符：\n got  %s\n want %s", got, testSignContent)
	}
}

// TestSignGoldenVector 是黄金签名向量：Go 侧 RSA-SHA256 签名必须与 openssl
// 独立算出的签名逐字节一致（PKCS#1 v1.5 确定性，口径漂移即红）。
func TestSignGoldenVector(t *testing.T) {
	sig, err := signRSA(mustMerchantKey(t), []byte(testSignContent))
	if err != nil {
		t.Fatalf("signRSA: %v", err)
	}
	if sig != testSignGolden {
		t.Fatalf("黄金签名不符（SHA256withRSA+base64 口径漂移）：\n got  %s\n want %s", sig, testSignGolden)
	}
}

// TestVerifyGoldenVector 是黄金验签向量：openssl 的签名必须被 Go 侧验签
// 接受，篡改一字节必须被拒。
func TestVerifyGoldenVector(t *testing.T) {
	if err := verifyRSA(mustGatewayPub(t), []byte(testNotifyContent), testNotifySignGolden); err != nil {
		t.Fatalf("openssl 黄金通知验签被拒: %v", err)
	}
	tampered := testNotifyContent + "!"
	if err := verifyRSA(mustGatewayPub(t), []byte(tampered), testNotifySignGolden); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("篡改内容必须验签失败，got %v", err)
	}
	if err := verifyRSA(mustGatewayPub(t), []byte(testNotifyContent), "not-base64!!"); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("非 base64 sign 必须验签失败，got %v", err)
	}
}

// TestQueryEncode 钉死 query 编码规则：与签名串同序（升序）、剔除空值、
// 键值标准 URL 转义（base64 的 + / = 与中文/空格都要转义），且可无损解码。
func TestQueryEncode(t *testing.T) {
	got := queryEncode(map[string]string{
		"sign":        "a+b/c=d",
		"empty":       "",
		"biz_content": testBizContent,
		"app_id":      testAppID,
	})
	want := "app_id=" + url.QueryEscape(testAppID) +
		"&biz_content=" + url.QueryEscape(testBizContent) +
		"&sign=" + url.QueryEscape("a+b/c=d")
	if got != want {
		t.Fatalf("queryEncode 不符：\n got  %s\n want %s", got, want)
	}
	q, err := url.ParseQuery(got)
	if err != nil {
		t.Fatalf("url.ParseQuery: %v", err)
	}
	if q.Get("sign") != "a+b/c=d" || q.Get("biz_content") != testBizContent || q.Get("app_id") != testAppID {
		t.Fatalf("query 解码后参数失真：%v", q)
	}
	if _, ok := q["empty"]; ok {
		t.Fatalf("空值参数不得进入 query：%v", q)
	}
}

// TestMarshalBizContent 钉死 biz_content 形状：紧凑 JSON、字段序稳定、
// 关闭 HTML 转义（< > & 保持原样——与真实 SDK 产出一致）。
func TestMarshalBizContent(t *testing.T) {
	got, err := marshalBizContent(bizContent{
		OutTradeNo:  "T20261015000001",
		TotalAmount: "30.00",
		Subject:     `订阅<a> & "30" 天`,
	})
	if err != nil {
		t.Fatalf("marshalBizContent: %v", err)
	}
	want := `{"out_trade_no":"T20261015000001","subject":"订阅<a> & \"30\" 天","total_amount":"30.00"}`
	if got != want {
		t.Fatalf("biz_content 不符：\n got  %s\n want %s", got, want)
	}
}
