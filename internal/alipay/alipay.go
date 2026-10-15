// Package alipay 是支付宝线格式方言的唯一 owner（L2）：alipay.trade.page.pay
// 请求的线格式编解码 + RSA2 签名/验签 + 网关客户端。
//
// 职责边界（设计书 §2.1）：
//   - 方言词汇隔离：仓内唯一知晓支付宝参数名与规范化规则（参数名升序、剔除
//     空值与 sign/sign_type、k=v&k=v 原文拼接、RSA-SHA256 + base64）的包，
//     「零代码切真支付宝」的物理载体——其余代码只消费本包的类型；
//   - 集成保真：与真实支付宝开放平台的对接口径逐字对齐（集成侧按真实方式
//     对接）；网关地址与 http.RoundTripper 注入，本地假网关（alipaymock）
//     复用同一编解码与验签逻辑，坏签名同被拒；
//   - 依赖纪律：仅 stdlib（不 import core / gin / config / metrics），无新增
//     导出接口——网关传输以 *http.RoundTripper 具体类型注入，时间以
//     Now func() time.Time 字段注入（镜像 accounts.Store 的手法）；
//   - fail-closed：非 HTTPS 网关地址在构造期拒绝（设计书 §5）。
//
// 签名 HTTP 网关调用路径（签名请求 → 收银台）由迭代③ payment 接线；本包
// 收口注入点与全部线格式语义，同一迭代②的假网关（alipaymock）经 Gateway
// 复用网关侧的请求验签与通知签名——仓内不存在第二份签名/验签实现。
//
// 密钥以 PEM 字节注入而非文件路径：读取与分发归组装根（控制面配置，后续
// 迭代接入），本包保持文件系统无关。
package alipay

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// 错误集（调用方以 errors.Is 区分；细节由包装错误携带）。
var (
	// ErrInvalidConfig 客户端构造参数非法（网关地址 / 密钥 PEM / app_id）。
	ErrInvalidConfig = errors.New("alipay: invalid client config")
	// ErrInvalidRequest 支付下单请求参数形状非法。
	ErrInvalidRequest = errors.New("alipay: invalid pay request")
	// ErrInvalidNotify 异步通知形状非法（缺 sign / sign_type 不支持 / 参数重复）。
	ErrInvalidNotify = errors.New("alipay: invalid notify")
	// ErrSignatureInvalid 验签失败（内容被篡改、密钥不符、sign 非 base64）。
	ErrSignatureInvalid = errors.New("alipay: signature verification failed")
)

// 支付宝线格式方言常量（真实网关约定值；alipaymock 复用同一取值）。
const (
	// MethodPagePay 是 PC 网页收银台下单的 method 参数（接口形式已定为
	// alipay.trade.page.pay）。
	MethodPagePay = "alipay.trade.page.pay"
	// SignTypeRSA2 是签名算法参数（SHA256withRSA）。
	SignTypeRSA2 = "RSA2"
	// CharsetUTF8 是请求/通知编码参数。
	CharsetUTF8 = "utf-8"
	// Version 是网关协议版本参数。
	Version = "1.0"
)

// maxOutTradeNoLen 是网关对商户订单号（out_trade_no）的长度上限（真实约定
// 为 64 字符；此处按真实口径把关）。
const maxOutTradeNoLen = 64

// amountRE 把关订单金额形状：十进制正数、最多两位小数（total_amount 的真实
// 约定；金额语义核对归上层 payment）。
var amountRE = regexp.MustCompile(`^[0-9]+(\.[0-9]{1,2})?$`)

// ClientConfig 是 Client 的构造参数（设计书 §2.1：gateway URL 与
// http.RoundTripper 注入）。
type ClientConfig struct {
	// Gateway 是支付宝网关基地址（真支付宝为 https://openapi.alipay.com/gateway.do；
	// 本地 mock 指向回环 HTTPS 地址）。必须是绝对 https URL 且不携带
	// query/fragment（下单参数经 query 追加，基地址混入即语义不明），否则
	// 构造失败（fail-closed）。
	Gateway string
	// AppID 是商户应用 ID（app_id 请求参数；通知验签通过后由调用方核对该值）。
	AppID string
	// MerchantKeyPEM 是商户 RSA2 私钥 PEM（PKCS#8「PRIVATE KEY」优先，兼容
	// PKCS#1「RSA PRIVATE KEY」；RSA ≥ 2048 位），用于请求签名。
	MerchantKeyPEM []byte
	// AlipayKeyPEM 是支付宝公钥 PEM（PKIX「PUBLIC KEY」优先，兼容 PKCS#1
	// 「RSA PUBLIC KEY」），用于异步通知验签。
	AlipayKeyPEM []byte
	// HTTP 是网关调用的传输注入点（迭代③ payment 消费）。指针语义 = 持有方
	// 可热替换传输；nil 指针或 nil 接口 = http.DefaultTransport。
	HTTP *http.RoundTripper
}

// Client 是支付宝网关客户端：持有网关地址与商户/支付宝密钥对，承担下单
// 请求签名（PayURL）与异步通知验签（VerifyNotify）。构造后只读，可安全
// 并发使用。
type Client struct {
	// Now 是时间注入点：timestamp 参数用它取当前时刻（具体类型字段，
	// 非接口；New 缺省 time.Now，测试注入假时钟）。
	Now func() time.Time

	gateway   *url.URL
	appID     string
	merchant  *rsa.PrivateKey // 商户私钥：签名 alipay.trade.page.pay 请求
	peer      *rsa.PublicKey  // 支付宝公钥：验签异步通知
	transport *http.RoundTripper
}

// New 按 cfg 构建网关客户端。任何形状非法（非 https 网关 / 非法 PEM /
// 非法 app_id）都返回包装 ErrInvalidConfig 的错误——构造期 fail-closed。
func New(cfg ClientConfig) (*Client, error) {
	gateway, err := parseGateway(cfg.Gateway)
	if err != nil {
		return nil, err
	}
	appID, err := normalizeAppID(cfg.AppID)
	if err != nil {
		return nil, err
	}
	merchant, err := parsePrivateKey(cfg.MerchantKeyPEM, "merchant key")
	if err != nil {
		return nil, err
	}
	peer, err := parsePublicKey(cfg.AlipayKeyPEM, "alipay key")
	if err != nil {
		return nil, err
	}
	return &Client{
		Now:       time.Now,
		gateway:   gateway,
		appID:     appID,
		merchant:  merchant,
		peer:      peer,
		transport: cfg.HTTP,
	}, nil
}

// PayRequest 是 alipay.trade.page.pay 的下单业务参数（PC 网页收银台请求；
// 金额语义与订单归属由上层 payment 校验，本包只把关线格式形状）。
type PayRequest struct {
	// OutTradeNo 是商户订单号（out_trade_no；网关侧唯一，≤ 64 字符）。
	OutTradeNo string
	// TotalAmount 是订单金额（total_amount；单位元、最多两位小数的十进制串，
	// 如 "30.00"——用字符串承载避免浮点格式化歧义）。
	TotalAmount string
	// Subject 是订单标题（subject；展示在收银台）。
	Subject string
	// NotifyURL 是异步通知回调地址（notify_url；空 = 省略该参数）。
	NotifyURL string
	// ReturnURL 是支付完成后的同步跳转地址（return_url；空 = 省略该参数）。
	ReturnURL string
}

// PayURL 构建已签名的 alipay.trade.page.pay 收银台跳转 URL：公共参数 +
// biz_content 组参 → 按 RSA2 规范化签名 → 以 query 追加到网关地址。调用方
// （控制面的支付下单）把它交给浏览器做 302 跳转（真支付宝），或由服务端
// 注入的 RoundTripper 发起 GET（mock 闭环，迭代③）。
func (c *Client) PayURL(req PayRequest) (string, error) {
	if err := validatePayRequest(req); err != nil {
		return "", err
	}
	biz, err := marshalBizContent(bizContent{
		OutTradeNo:  req.OutTradeNo,
		TotalAmount: req.TotalAmount,
		Subject:     req.Subject,
	})
	if err != nil {
		return "", err
	}
	params := map[string]string{
		"app_id":      c.appID,
		"method":      MethodPagePay,
		"charset":     CharsetUTF8,
		"sign_type":   SignTypeRSA2,
		"timestamp":   formatTimestamp(c.now()),
		"version":     Version,
		"biz_content": biz,
	}
	if req.NotifyURL != "" {
		params["notify_url"] = req.NotifyURL
	}
	if req.ReturnURL != "" {
		params["return_url"] = req.ReturnURL
	}
	sig, err := signRSA(c.merchant, []byte(signContent(params)))
	if err != nil {
		return "", err
	}
	params["sign"] = sig
	return c.gateway.String() + "?" + queryEncode(params), nil
}

// validatePayRequest 把关下单参数的线格式形状（CR/LF 过关在前，防参数沿
// 签名串与 query 两个出口走私控制字符）。
func validatePayRequest(req PayRequest) error {
	switch {
	case strings.TrimSpace(req.OutTradeNo) == "":
		return fmt.Errorf("%w: out_trade_no must not be empty", ErrInvalidRequest)
	case len(req.OutTradeNo) > maxOutTradeNoLen:
		return fmt.Errorf("%w: out_trade_no longer than %d characters", ErrInvalidRequest, maxOutTradeNoLen)
	case strings.ContainsAny(req.OutTradeNo, "\r\n"):
		return fmt.Errorf("%w: out_trade_no %q must not contain CR or LF", ErrInvalidRequest, req.OutTradeNo)
	case !amountRE.MatchString(req.TotalAmount):
		return fmt.Errorf("%w: total_amount %q must be a decimal amount with at most 2 fraction digits", ErrInvalidRequest, req.TotalAmount)
	case strings.TrimSpace(req.Subject) == "" || strings.ContainsAny(req.Subject, "\r\n"):
		return fmt.Errorf("%w: subject must be non-empty without CR or LF", ErrInvalidRequest)
	}
	for _, raw := range [...]string{req.NotifyURL, req.ReturnURL} {
		if raw == "" {
			continue
		}
		if strings.ContainsAny(raw, "\r\n") {
			return fmt.Errorf("%w: url %q must not contain CR or LF", ErrInvalidRequest, raw)
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("%w: url %q must be an absolute http(s) URL", ErrInvalidRequest, raw)
		}
	}
	return nil
}

// parseGateway 校验并解析网关基地址：绝对 https URL、host 非空、不携带
// query/fragment（设计书 §5：非 HTTPS 网关构造期拒绝）。
func parseGateway(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("%w: gateway must not be empty", ErrInvalidConfig)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: gateway %q: %v", ErrInvalidConfig, raw, err)
	}
	switch {
	case u.Scheme != "https":
		return nil, fmt.Errorf("%w: gateway %q must use https", ErrInvalidConfig, raw)
	case u.Host == "":
		return nil, fmt.Errorf("%w: gateway %q must have a host", ErrInvalidConfig, raw)
	case u.RawQuery != "" || u.Fragment != "" || u.RawFragment != "":
		return nil, fmt.Errorf("%w: gateway %q must not carry a query or fragment", ErrInvalidConfig, raw)
	}
	return u, nil
}

// normalizeAppID 校验 app_id（非空且不含 CR/LF——拼进签名串与 query 前把关）。
func normalizeAppID(appID string) (string, error) {
	if strings.TrimSpace(appID) == "" || strings.ContainsAny(appID, "\r\n") {
		return "", fmt.Errorf("%w: app_id must be non-empty without CR or LF", ErrInvalidConfig)
	}
	return appID, nil
}

// now 返回当前时刻（Now 注入点；nil 回退 time.Now）。
func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
