package alipay

import (
	"fmt"
	"net/url"
)

// TradeStatus 是异步通知的交易状态（trade_status）。已支付 = Success /
// Finished 两种；等待付款、交易关闭等其余状态由上层按订单状态机语义处理。
type TradeStatus string

const (
	// TradeStatusSuccess 支付成功（资金已到账，可退款期内）。
	TradeStatusSuccess TradeStatus = "TRADE_SUCCESS"
	// TradeStatusFinished 交易结束（不可退款；同样视为已支付）。
	TradeStatusFinished TradeStatus = "TRADE_FINISHED"
)

// NotifyParams 是验签通过后的异步通知参数（payment 落地所需字段的并集，
// 真实网关参数名）。除签名字段外的值均为网关原文；调用方（payment）仍须
// 自行核对 app_id、out_trade_no、total_amount、trade_status 的业务语义
// （金额不符拒落地、trade_no 幂等——设计书 §1.1 I4）。
type NotifyParams struct {
	// AppID 是通知归属的商户应用（app_id；调用方核对与本 Client 一致）。
	AppID string
	// TradeNo 是支付宝交易号（trade_no；幂等落地的键）。
	TradeNo string
	// OutTradeNo 是商户订单号（out_trade_no）。
	OutTradeNo string
	// TradeStatus 是交易状态。
	TradeStatus TradeStatus
	// TotalAmount 是通知口径的订单金额（total_amount）。
	TotalAmount string
	// Subject 是订单标题（subject）。
	Subject string
	// GmtPayment 是付款完成时刻（gmt_payment；yyyy-MM-dd HH:mm:ss，GMT+8 墙钟）。
	GmtPayment string
	// SignType 是通知签名算法（恒 RSA2，验签的前置条件）。
	SignType string
	// Sign 是通知签名（base64；审计留存用）。
	Sign string
}

// VerifyNotify 校验支付宝异步通知（POST form，值已按 form 语义解码）：
// 除 sign/sign_type 外的参数按名升序、剔除空值拼成 k=v&k=v，用支付宝公钥
// 做 RSA-SHA256 验签（SHA256withRSA）。通过则返回解码后的通知参数；任何
// 形状或签名问题都返回错误——调用方对失败一律不落地并回 fail（fail-closed）。
func (c *Client) VerifyNotify(form url.Values) (NotifyParams, error) {
	if len(form) == 0 {
		return NotifyParams{}, errInvalidNotify("empty notify")
	}
	params := make(map[string]string, len(form))
	for k, vs := range form {
		if len(vs) != 1 {
			return NotifyParams{}, errInvalidNotify("parameter %q appears %d times", k, len(vs))
		}
		params[k] = vs[0]
	}
	if params["sign"] == "" {
		return NotifyParams{}, errInvalidNotify("missing sign")
	}
	if st := params["sign_type"]; st != SignTypeRSA2 {
		return NotifyParams{}, errInvalidNotify("unsupported sign_type %q (want %s)", st, SignTypeRSA2)
	}
	if err := verifyRSA(c.peer, []byte(signContent(params)), params["sign"]); err != nil {
		return NotifyParams{}, err
	}
	return NotifyParams{
		AppID:       params["app_id"],
		TradeNo:     params["trade_no"],
		OutTradeNo:  params["out_trade_no"],
		TradeStatus: TradeStatus(params["trade_status"]),
		TotalAmount: params["total_amount"],
		Subject:     params["subject"],
		GmtPayment:  params["gmt_payment"],
		SignType:    params["sign_type"],
		Sign:        params["sign"],
	}, nil
}

// errInvalidNotify 构造包装 ErrInvalidNotify 的通知形状错误。
func errInvalidNotify(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidNotify, fmt.Sprintf(format, args...))
}
