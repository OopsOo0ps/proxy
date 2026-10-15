package alipay

import (
	"crypto/rsa"
	"fmt"
	"net/url"
	"time"
)

// GatewayConfig 是 Gateway 的构造参数：网关侧（收单侧）只持有两把钥匙——
// 商户公钥（验签入站请求）与支付宝私钥（签名异步通知）。
type GatewayConfig struct {
	// AppID 是受理的商户应用 ID：请求的 app_id 与此不符即拒绝（真实网关按
	// 应用受理请求的口径）。
	AppID string
	// MerchantPubPEM 是商户 RSA2 公钥 PEM（PKIX「PUBLIC KEY」优先，兼容
	// PKCS#1「RSA PUBLIC KEY」），用于验签 alipay.trade.page.pay 请求。
	MerchantPubPEM []byte
	// NotifyKeyPEM 是支付宝 RSA2 私钥 PEM（PKCS#8「PRIVATE KEY」优先，兼容
	// PKCS#1「RSA PRIVATE KEY」），用于签名异步通知。
	NotifyKeyPEM []byte
}

// Gateway 是网关侧（收单侧）线格式助手：与 Client 共用同一套编解码与签名
// 实现（signContent / verifyRSA / signRSA / biz_content / GMT+8 时间格式），
// 只是钥匙方向相反——Client 以商户私钥签请求、支付宝公钥验通知；Gateway
// 以商户公钥验请求、支付宝私钥签通知。设计书 §1.3 的保真机制「假网关用与
// 真实网关相同的验签逻辑拒绝坏签名」因此落在同一份代码上：假网关
// （alipaymock）经本类型复用方言实现，仓内不存在第二份验签/签名逻辑。
//
// 构造后只读，可安全并发使用。本类型服务网关形态的对接方（假网关与测试）；
// proxy 生产侧只消费 Client。
type Gateway struct {
	appID    string
	merchant *rsa.PublicKey  // 商户公钥：验签入站 alipay.trade.page.pay 请求
	notify   *rsa.PrivateKey // 支付宝私钥：签名异步通知
}

// NewGateway 按 cfg 构建网关侧助手。任何形状非法（非法 PEM / 非法 app_id）
// 都返回包装 ErrInvalidConfig 的错误——构造期 fail-closed，与 New 同口径。
func NewGateway(cfg GatewayConfig) (*Gateway, error) {
	appID, err := normalizeAppID(cfg.AppID)
	if err != nil {
		return nil, err
	}
	merchant, err := parsePublicKey(cfg.MerchantPubPEM, "merchant public key")
	if err != nil {
		return nil, err
	}
	notify, err := parsePrivateKey(cfg.NotifyKeyPEM, "alipay notify key")
	if err != nil {
		return nil, err
	}
	return &Gateway{appID: appID, merchant: merchant, notify: notify}, nil
}

// VerifyPagePay 验签并解析 alipay.trade.page.pay 请求表单（GET query 或
// POST body，值已按 form 语义解码）：method 必须是 page.pay、app_id 必须
// 与受理应用一致、sign_type 必须是 RSA2；除 sign/sign_type 外的参数按名
// 升序拼串（与签发侧同一规范化）后用商户公钥做 RSA-SHA256 验签，通过再
// 解析 biz_content 并按下单参数口径把关形状。通过则返回下单业务参数；
// 形状非法返回包装 ErrInvalidRequest 的错误，签名不符返回
// ErrSignatureInvalid——调用方（假网关）对两类失败一律显式拒绝。
func (g *Gateway) VerifyPagePay(form url.Values) (PayRequest, error) {
	if len(form) == 0 {
		return PayRequest{}, errInvalidRequest("empty page.pay request")
	}
	params := make(map[string]string, len(form))
	for k, vs := range form {
		if len(vs) != 1 {
			return PayRequest{}, errInvalidRequest("parameter %q appears %d times", k, len(vs))
		}
		params[k] = vs[0]
	}
	if params["method"] != MethodPagePay {
		return PayRequest{}, errInvalidRequest("unsupported method %q (want %s)", params["method"], MethodPagePay)
	}
	if params["app_id"] != g.appID {
		return PayRequest{}, errInvalidRequest("app_id %q does not match accepted app %q", params["app_id"], g.appID)
	}
	if params["sign"] == "" {
		return PayRequest{}, errInvalidRequest("missing sign")
	}
	if st := params["sign_type"]; st != SignTypeRSA2 {
		return PayRequest{}, errInvalidRequest("unsupported sign_type %q (want %s)", st, SignTypeRSA2)
	}
	if err := verifyRSA(g.merchant, []byte(signContent(params)), params["sign"]); err != nil {
		return PayRequest{}, err
	}
	biz, err := unmarshalBizContent(params["biz_content"])
	if err != nil {
		return PayRequest{}, err
	}
	req := PayRequest{
		OutTradeNo:  biz.OutTradeNo,
		TotalAmount: biz.TotalAmount,
		Subject:     biz.Subject,
		NotifyURL:   params["notify_url"],
		ReturnURL:   params["return_url"],
	}
	if err := validatePayRequest(req); err != nil {
		return PayRequest{}, err
	}
	return req, nil
}

// TradeNotify 是网关侧组装异步通知的输入：订单事实 + 支付完成时刻。
// gmt_payment 由本包按线格式约定（GMT+8 墙钟，yyyy-MM-dd HH:mm:ss）格式化，
// 调用方不接触方言时间格式。
type TradeNotify struct {
	// TradeNo 是支付宝交易号（trade_no；商户侧幂等落地的键）。
	TradeNo string
	// OutTradeNo 是商户订单号（out_trade_no）。
	OutTradeNo string
	// TotalAmount 是订单金额（total_amount；十进制、最多两位小数）。
	TotalAmount string
	// Subject 是订单标题（subject）。
	Subject string
	// PaidAt 是支付完成时刻（gmt_payment 的取值来源）。
	PaidAt time.Time
}

// BuildNotify 组装 TRADE_SUCCESS 异步通知表单并以支付宝私钥按 RSA2 规范化
// 签名：字段集与真实网关通知对齐（app_id / charset / gmt_payment /
// out_trade_no / subject / total_amount / trade_no / trade_status），返回
// 含 sign_type=RSA2 与 sign 的完整表单，可直接 form-POST 到 notify_url，
// 且能被 Client.VerifyNotify（以支付宝公钥）验签通过。
func (g *Gateway) BuildNotify(n TradeNotify) (url.Values, error) {
	switch {
	case n.TradeNo == "":
		return nil, errInvalidRequest("notify trade_no must not be empty")
	case n.OutTradeNo == "":
		return nil, errInvalidRequest("notify out_trade_no must not be empty")
	case !amountRE.MatchString(n.TotalAmount):
		return nil, errInvalidRequest("notify total_amount %q must be a decimal amount with at most 2 fraction digits", n.TotalAmount)
	}
	params := map[string]string{
		"app_id":       g.appID,
		"charset":      CharsetUTF8,
		"gmt_payment":  formatTimestamp(n.PaidAt),
		"out_trade_no": n.OutTradeNo,
		"subject":      n.Subject,
		"total_amount": n.TotalAmount,
		"trade_no":     n.TradeNo,
		"trade_status": string(TradeStatusSuccess),
	}
	sig, err := signRSA(g.notify, []byte(signContent(params)))
	if err != nil {
		return nil, err
	}
	params["sign"] = sig
	params["sign_type"] = SignTypeRSA2
	form := make(url.Values, len(params))
	for k, v := range params {
		if v == "" {
			continue // 发送集 = 签名集 ∪ {sign, sign_type}，与 queryEncode 同口径
		}
		form.Set(k, v)
	}
	return form, nil
}

// errInvalidRequest 构造包装 ErrInvalidRequest 的下单请求形状错误。
func errInvalidRequest(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidRequest, fmt.Sprintf(format, args...))
}
