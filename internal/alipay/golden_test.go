package alipay

import (
	"crypto/rsa"
	"encoding/pem"
	"net/url"
	"testing"
	"time"
)

// pemPublic 把 PKIX DER 公钥包成 PEM（-----BEGIN PUBLIC KEY-----）。
func pemPublic(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// pemPrivate 把 PKCS#8 DER 私钥包成 PEM（-----BEGIN PRIVATE KEY-----）。
func pemPrivate(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// 黄金向量与固定测试密钥（hermetic，设计书 §5）：密钥对是本包测试专用的
// 一次性 RSA2 2048 密钥（生成后即弃、不入任何配置，入库无风险——只用于
// 黄金签名向量与负例；与 make dev-keys 生成到 var/ 的测试密钥互不相干）。
// 期望签名由 openssl `dgst -sha256 -sign` 独立计算（非被测代码产出），钉死
// SHA256withRSA + base64 的真实对接口径；待签名串含空格与中文，钉死「值
// 保持原文、不做 URL 编码」。
const (
	testMerchantKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCbp8fYH8YTk6Rz
0stTBU1OJ6pNmYDGQjNm7cuCVkKhKr9i3Kho6E9WGX2Pq6PG33heRb/fcYe2hWTU
jAKHdRxogP1UxyQhVSVwxL9Is9emjfXmMsY+r9Z7JGK+4RrOScDs48EkEr/s5Z85
q2eRBIeosD8wnkY07MlfGUzOKJhCtT4YRg+RC3ZYYLHHeovGvdZiE3ukejtvLoxf
XGW2T/75Ba75I3CAIXyE9VRumQGq9F8vJf2TS5HyX7E8R/QnZUhdeC+FyboFUyCP
EX23ep11vVSoMMJb8IaiOaCpe6CRnmkPtWWvId53jkxgFd3KjxMW3RzgUSvNasV3
C+So80QDAgMBAAECggEAFzvzpiyT/f8XWJyZ8gIEGIruLlgf8zgVgSM0sfdbScBe
Qg0K7GHk2cbDSctGjpxz1KqXqexB5DpEIz/k7sBJ5cV/SwTQvVL+3DbaEKmbooZl
Mp/YnKnVm5sCTFjAjhNPQ2z5uv87e8qIumx98JUbBNCOFh1CAItpwZK+trUziR1W
Ff7jYaxz/8umQFFuQTgseRxzkWDGKcSeGXyPeJTSlDANIhvDG4RkEG5uPH7SbFrZ
vsWG4l29BOU+AnMBDj2SQDtdKliobNINFaGXzDTCipAmuTgd1q6EJFk9Ov+kIJvZ
e9/iWr/Kt+V6FgRbC3m9lsq6NhYJW/dRoOAcbteeCQKBgQDK1TRdWKkk+A2DxNTX
kCFRDvDakdvgT5FcqQSR6w6BeitUleD1+sBeBmIRoQMScoM/s6bvTTp0wH/64uyP
Iew2E62Ol5ZfDAA9njkDUK+L2IOLYnN6JpDAu2sPQ/7FpRheq5rUm2h8GC3J25Hb
k5spJ+oe0XrbcJ9vOH7abnZSiQKBgQDEdM3oev0rYpxfqs5ATlyfq26bUemyKTym
2EEPra1NlFj22V0qXt8YbYayAsyXRjnTK31xON/XKZ+txgzjDw+ErctFwGVllgnd
JxOb+AEnbklIsYwpN2SXwXrMYCO04Wb9CfRT2ct7KbZERj9kNaZiy36oQQyhJYvm
e9iRuHpvKwKBgQCesimCT3gnoJySWFJfRjmK/jGcETsDSb3lzafxswNqcneseofE
bShNaJkaSevpZwchtCIMYVQ3PNXlKd8ELfpuZP8J7biNLQqTK1RYL6zpscFaMPFA
xSPEZ97f1sdjRETI7WL6rY0WaqSIpu576gUgMkaPTj7dqkRT9NPreznAYQKBgHGh
qhQFR3iXwiEnt8LEUJjeXMykFYtChN1wijlaWLpdyxOE6HmAhIQpndZK/jGlof69
0gHyRq66Waz2uC+BX5V7vO6seTnIDg6H8rStP2WiSestHwgcDSgl9jROi3itQ5eq
8VKq0CJ+Hvngs/vveDz+vVTuwzJWeFQpYDvxO4gfAoGAVXH9XYU64GVL7CeBylJL
K1Cl3fyCQeW+KmeZV+owWFOLB1P4v+tkkC06XmjcHgQyetK7l6U+mGcgOiwGY/Dq
QvvvQ1VYbMD3s0jEGRnJwvUlC9iRE5NU8CxTUDfY+utuQLB5TRKACKCocvg8bF6C
31LapOb0EjQC6duCF0T84oo=
-----END PRIVATE KEY-----
`

	testMerchantPubPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm6fH2B/GE5Okc9LLUwVN
TieqTZmAxkIzZu3LglZCoSq/YtyoaOhPVhl9j6ujxt94XkW/33GHtoVk1IwCh3Uc
aID9VMckIVUlcMS/SLPXpo315jLGPq/WeyRivuEazknA7OPBJBK/7OWfOatnkQSH
qLA/MJ5GNOzJXxlMziiYQrU+GEYPkQt2WGCxx3qLxr3WYhN7pHo7by6MX1xltk/+
+QWu+SNwgCF8hPVUbpkBqvRfLyX9k0uR8l+xPEf0J2VIXXgvhcm6BVMgjxF9t3qd
db1UqDDCW/CGojmgqXugkZ5pD7VlryHed45MYBXdyo8TFt0c4FErzWrFdwvkqPNE
AwIDAQAB
-----END PUBLIC KEY-----
`

	testGatewayKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDVktVJV84DIiCF
MJtenGFRY9fypKU33FtWVlEUJn4ZI074+HDEkaBUnpYTc1FR0XAEL65erRXYQJwm
fP0XakdEKRMwKgyKbQXI2XdjChPYFEh5yvwg2lKWQer8STvD1wF3w0KRedfzYh4H
7zHEwMF38hpT/8v7w/E36ycKJFH793VQQYj50rsqyHLvrVb3W/eVcgVL+KMYZdvi
vOLc76kG7/mRFExv3freeiQdbGpGzvT3f0g4YQidTQD+Hu/ncDUv52UjPA2cS+Wi
HXKFvd11UrA7qdZgUJxQ/LywqQyF4uSgbUiJdbEiBMve70RYttDuCOOY95cpZIr1
N1cj9eKfAgMBAAECggEAIGXJN/p7VEtZforMjtIPCy8no3WpYGtraZHnc7SRHVQX
VzostQzYMu3pmyK7m7s3EFOBUnhUH31Rkp8UL3iePe8zK3O9ekQmg/zFGP9+2iDd
i6gojf1AWO2/7SxYxhD39ohmsTW39gIUxyRYOt34my7dIo/jjBoBnfdscSPoUd3F
bG3wBDFsB37l/3xB9rMd1O9wthSSo2ge1EDXzEJORsDm4gsoFu5w6edDYLi3l5R+
6lGg+4LNcK5CBqdfM1Ulsl0flvap7wrOOH85tPy9y6dPU5y/ZEYIVVbckW3zHHE6
5PFAr7eDkV77cYHc1Rr1Z4SGdDTtSN5QIdaqle380QKBgQDzmP9YK3+wa0k4IXBo
C1ipnyA4aahzCEoHz4iMtVFOuVbakjFmGE/xk6Nuz6VmD4BI0lThrQmTvB6ambcm
2ao3Be9hn3K6AcmyUQhFExg2EJOz53BlGT4BIEiSHd3KC5L+2z2iDUq+a+QCEDlm
hUGGwERGRSH8mOgXdYt5ubn+rwKBgQDgcoIHI1d6bkFtpztqUfHbkEnaPDbbOlvd
O40fmXJUw+RZGnbYvk/diHsu5hO+zCtk6Spd9zq+8FsszZy+zL58WsvxVSU/Arcc
eyKJb8BgMhrM0jHR+IJpqYVQvcIrLR2i8WIhkunN9JJ01+8j2w9bCH7r0oSKfQdt
Z6Acl3nXEQKBgHwhltzjLapEwYbs407hmUi2YcDddo1HyBG626Z4Lvqiz3OJ08pm
0TYVOc8Z2PrtIz34kHB/sMWrsxys//u4J1jqmVVx3xCSIKnRSRmJ5WiHgfzHDys1
dbc1MEXlGkP/KeTc68dMZq4qZIH4qodnmECGcUQtrmf9sydhKrXYwsLZAoGBAL47
77+TEeMALk59TpunxsGdQytInAomJZSWk99zlHcJ7bIj/xVoAJM4yYePlK7DqAgI
pFMuZ8lMOUr5HuCM8uq9nlv3GfGVIJRwPW6VnE0sSpDNm1JnOknKV+d+XmNwAs2H
n+/q8GYS5EtKdjNCyXoT8ld4f8RNgo0VJpz1OlyxAoGAKJSh/ltj8MRi/7J2w9mk
USeG4BaRHRRseKc9BG0nDn8I09FdPRXSdGxOXf7wlmCEDJ6ZBtcMcK4EXEIbIW5e
sJAUOMSu9eM/WSFzEuxBos10+4B3hkQyNUuX39B6IwRoOeaTtIzyrVSZGUwdOBdK
1mxc2LAZdKEhdyMvjFhNvIY=
-----END PRIVATE KEY-----
`

	testGatewayPubPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1ZLVSVfOAyIghTCbXpxh
UWPX8qSlN9xbVlZRFCZ+GSNO+PhwxJGgVJ6WE3NRUdFwBC+uXq0V2ECcJnz9F2pH
RCkTMCoMim0FyNl3YwoT2BRIecr8INpSlkHq/Ek7w9cBd8NCkXnX82IeB+8xxMDB
d/IaU//L+8PxN+snCiRR+/d1UEGI+dK7Kshy761W91v3lXIFS/ijGGXb4rzi3O+p
Bu/5kRRMb9363nokHWxqRs70939IOGEInU0A/h7v53A1L+dlIzwNnEvloh1yhb3d
dVKwO6nWYFCcUPy8sKkMheLkoG1IiXWxIgTL3u9EWLbQ7gjjmPeXKWSK9TdXI/Xi
nwIDAQAB
-----END PUBLIC KEY-----
`

	// testAppID 是黄金向量用的商户应用 ID。
	testAppID = "2026000000000000"

	// testGateway 是黄金向量客户端的网关基地址（测试域，不触网）。
	testGateway = "https://gateway.test/gateway.do"

	// testSignContent 是黄金下单请求的待签名串（RSA2 规范化结果：升序、
	// 无 sign/sign_type、值原文含空格与中文）。
	testSignContent = `app_id=2026000000000000&biz_content={"out_trade_no":"T20261015000001","subject":"订阅 30 天","total_amount":"30.00"}&charset=utf-8&method=alipay.trade.page.pay&timestamp=2026-10-15 12:00:00&version=1.0`

	// testSignGolden 是 openssl 以商户私钥对 testSignContent 算出的
	// RSA-SHA256 签名（base64）。
	testSignGolden = `dsRqzNzXv9t0nyhlsSmRVOkg3wmMCMMLuEEG2MAblfgekLf+DbS4Aur5nsNbjQDTcFq2p2JopyL+jDzw6O7QD4NRPKtcEQJIFPcLxeTz59qIWMwFdccUIfJb/I0lB7wHIhCIhHCTD/s7gc0d+n52rYvK2ay0Ny8hcuNpy5YnC33Ke5HdZ2aJ0CR0eiOPhYPvUXdXgU9VQ9apwBnHgXXkmMMnA8CqpxpnuEuRxtsTh7D26kEZ5yeb7Ma/cgBAuLf3k7LxQsvcFgLgYlhK9oJwOhufc4Ac9H8s31wyxVg8wSzd9z0ZeS/WV6NnHNZ0EFozgcL/71xEoUEEI4QZGkUKlg==`

	// testBizContent 是黄金下单请求的 biz_content（marshalBizContent 期望输出）。
	testBizContent = `{"out_trade_no":"T20261015000001","subject":"订阅 30 天","total_amount":"30.00"}`

	// testNotifyContent 是黄金异步通知的待签名串。
	testNotifyContent = `app_id=2026000000000000&gmt_payment=2026-10-15 12:00:31&out_trade_no=T20261015000001&subject=订阅 30 天&total_amount=30.00&trade_no=2026101522001400001234567890&trade_status=TRADE_SUCCESS`

	// testNotifySignGolden 是 openssl 以网关（支付宝）私钥对 testNotifyContent
	// 算出的 RSA-SHA256 签名（base64）。
	testNotifySignGolden = `TvcX7VIQqkAGZ0/fvMFBS2YCwDhCYSUCefrFMW7tjxrnsPp4kAazrHcUwBSScddSy6aH1m0XbUlsqH+Ml0yoqzUsyqGGAkVDHE8SwKMC2XdZzE+EOekL8J9qLWzm+6MMzRMkf4imkbHRl6reXVLqZX72raXRtI5yzam66F/7n8Mo/wL0jSdTexQkurW+uk7ghCdDrbkwZa99jjOhCqCsLmh9uj+A6dzKh9iRzc2IkX1Bv8j3/y1omTxXwW1uz4VUW2RCWCoTBlXmnN+uduT5PvTBjTpagY4KjxRNjquu7hAXLQItc4II3tZNfLi7QNDABe+71Y9RDsu/pHXSgLe8aQ==`
)

// testFixedNow 是黄金向量对应的固定时刻（GMT+8 墙钟 2026-10-15 12:00:00，
// 与 testSignContent 的 timestamp 一致）。
var testFixedNow = time.Date(2026, 10, 15, 12, 0, 0, 0, gmt8)

// testPayRequest 对应 testSignContent 的下单参数（无 notify_url / return_url）。
var testPayRequest = PayRequest{
	OutTradeNo:  "T20261015000001",
	TotalAmount: "30.00",
	Subject:     "订阅 30 天",
}

// testNotifyForm 是黄金异步通知的完整 POST form（已按 form 语义解码）。
var testNotifyForm = url.Values{
	"app_id":       {testAppID},
	"trade_no":     {"2026101522001400001234567890"},
	"out_trade_no": {"T20261015000001"},
	"trade_status": {string(TradeStatusSuccess)},
	"total_amount": {"30.00"},
	"subject":      {"订阅 30 天"},
	"gmt_payment":  {"2026-10-15 12:00:31"},
	"sign_type":    {SignTypeRSA2},
	"sign":         {testNotifySignGolden},
}

// testClientConfig 用黄金密钥构建合法构造参数（alipay 公钥 = 网关公钥）。
func testClientConfig() ClientConfig {
	return ClientConfig{
		Gateway:        testGateway,
		AppID:          testAppID,
		MerchantKeyPEM: []byte(testMerchantKeyPEM),
		AlipayKeyPEM:   []byte(testGatewayPubPEM),
	}
}

// mustClient 用黄金密钥构建测试客户端（时钟固定在 testFixedNow）。
func mustClient(t *testing.T) *Client {
	t.Helper()
	cl, err := New(testClientConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cl.Now = func() time.Time { return testFixedNow }
	return cl
}

// mustMerchantKey / mustMerchantPub / mustGatewayPub 解析黄金 PEM（解析失败
// 直接 Fatal）。网关私钥不出现在辅助函数里：签名方向由 openssl 黄金向量覆盖，
// 私钥 PEM 仅用于负例（错放槽位 / 换钥）。
func mustMerchantKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	return mustParsePrivateKey(t, testMerchantKeyPEM)
}

func mustParsePrivateKey(t *testing.T, pemStr string) *rsa.PrivateKey {
	t.Helper()
	key, err := parsePrivateKey([]byte(pemStr), "test key")
	if err != nil {
		t.Fatalf("parsePrivateKey: %v", err)
	}
	return key
}

func mustMerchantPub(t *testing.T) *rsa.PublicKey {
	t.Helper()
	return mustParsePublicKey(t, testMerchantPubPEM)
}

func mustGatewayPub(t *testing.T) *rsa.PublicKey {
	t.Helper()
	return mustParsePublicKey(t, testGatewayPubPEM)
}

func mustParsePublicKey(t *testing.T, pemStr string) *rsa.PublicKey {
	t.Helper()
	key, err := parsePublicKey([]byte(pemStr), "test key")
	if err != nil {
		t.Fatalf("parsePublicKey: %v", err)
	}
	return key
}
