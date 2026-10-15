package alipay

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
)

// gmt8 是支付宝线格式的约定时区：timestamp / gmt_payment 等墙钟字段一律
// GMT+8（真实网关约定，与服务器本地时区无关）。
var gmt8 = time.FixedZone("GMT+8", 8*3600)

// formatTimestamp 把时刻格式化为网关约定的 timestamp（GMT+8 墙钟）。
func formatTimestamp(t time.Time) string {
	return t.In(gmt8).Format("2006-01-02 15:04:05")
}

// signContent 按 RSA2 规范构造待签名串（「集成侧按真实方式对接」的保真核心）：
//   - 剔除 sign 与 sign_type（签名自指排除）与值为空的参数（空值不参与签名）；
//   - 其余参数按参数名字节序升序；
//   - 以 k=v 用 & 连接，值保持原文（不做 URL 编码）。
//
// 对请求侧与通知侧（验签串）对称适用。
func signContent(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k, v := range params {
		if v == "" || k == "sign" || k == "sign_type" {
			continue
		}
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(params[k])
	}
	return b.String()
}

// queryEncode 把含签名的参数表编码为网关 query：与 signContent 同序同集
// （升序、剔除空值——发送集 = 签名集 ∪ {sign, sign_type}），键值做标准
// URL 转义（签名串保持原文，转义只发生在传输编码这一步）。
func queryEncode(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k, v := range params {
		if v == "" {
			continue
		}
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape(k))
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(params[k]))
	}
	return b.String()
}

// signRSA 以商户私钥做 RSA-SHA256（PKCS#1 v1.5，即网关的 SHA256withRSA）
// 签名并 base64 编码。PKCS#1 v1.5 签名是确定性的——同钥同文恒同签，黄金
// 向量可复现。
func signRSA(key *rsa.PrivateKey, content []byte) (string, error) {
	digest := sha256.Sum256(content)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("alipay: rsa sign: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// verifyRSA 是 signRSA 的对称验签：base64 解码后用公钥校验 RSA-SHA256。
func verifyRSA(key *rsa.PublicKey, content []byte, sigB64 string) error {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("%w: sign is not valid base64", ErrSignatureInvalid)
	}
	digest := sha256.Sum256(content)
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return ErrSignatureInvalid
	}
	return nil
}

// bizContent 是 alipay.trade.page.pay 的业务参数（biz_content JSON 内层；
// 字段序即序列化序——与真实 SDK 的字典序产出一致，黄金向量按此钉死）。
type bizContent struct {
	OutTradeNo  string `json:"out_trade_no"`
	Subject     string `json:"subject"`
	TotalAmount string `json:"total_amount"`
}

// unmarshalBizContent 解析 biz_content JSON（网关侧验签后的请求解析；紧凑
// UTF-8 文本）：只认本包词汇的三个业务字段，未知字段忽略（真实网关对新
// 字段向后兼容的口径）。解析失败按请求形状非法拒绝。
func unmarshalBizContent(s string) (bizContent, error) {
	var b bizContent
	dec := json.NewDecoder(strings.NewReader(s))
	if err := dec.Decode(&b); err != nil {
		return bizContent{}, errInvalidRequest("biz_content %q: %v", s, err)
	}
	return b, nil
}

// marshalBizContent 序列化 biz_content：紧凑 JSON 且关闭 HTML 转义——真实
// 网关的 biz_content 是原样 UTF-8 文本（json.Marshal 默认把 < > & 转成
// \u003c 等，会让签名与真实 SDK 产出不一致）。
func marshalBizContent(b bizContent) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(b); err != nil {
		return "", fmt.Errorf("alipay: encode biz_content: %w", err)
	}
	return strings.TrimRight(buf.String(), "\n"), nil
}
