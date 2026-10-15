// Package alipaymock 是假支付宝网关（L3）：以 http.Handler 形态宿主收银台
// 页、请求验签与异步通知投递，线格式语义全部复用 internal/alipay 的网关侧
// 助手（Gateway）——「mock 用与真实网关相同的验签逻辑拒绝坏签名」因此落在
// 同一份实现上（设计书 §1.3 保真机制）。
//
// 职责边界（设计书 §2.1）：
//   - 假件活在生产依赖链之外：proxy 生产侧只消费 internal/alipay 的 Client，
//     本包仅供 cmd/mockpay 与测试触达（ProtocolPkgs 收口）；
//   - 纯 net/http，不 import gin（gin 属 control）；
//   - 无持久化：订单与支付事实在内存中按 out_trade_no 幂等（单进程测试
//     假件，重启即清零；真实网关的持久性不在假件保真范围）。
//
// 与真实网关的有意偏差（测试确定性优先，均显式声明）：
//   - 「确认支付」在 confirm 请求内同步投递异步通知，不做失败重试（真实
//     网关为异步多轮重试）；
//   - 通知字段为真实通知的最小对齐子集（trade_status / trade_no / ...）；
//   - 支付后不向 return_url 做同步跳转（return_url 仅验签把关，不消费）。
package alipaymock

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/OopsOo0ps/proxy/internal/alipay"
)

// Options 是 New 的构造参数。
type Options struct {
	// AppID 是受理的商户应用 ID（app_id 核对；不符即拒绝）。
	AppID string
	// MerchantPubPEM 是商户 RSA2 公钥 PEM：验签入站 alipay.trade.page.pay
	// 请求（保真验收：坏签名一律显式拒绝——无收银台页、无通知）。
	MerchantPubPEM []byte
	// NotifyKeyPEM 是支付宝 RSA2 私钥 PEM：签名投递给商户的异步通知。
	NotifyKeyPEM []byte
	// Now 是时间注入点：gmt_payment 取自此（缺省 time.Now，测试注入假时钟
	// ——镜像 alipay.Client.Now 的手法）。
	Now func() time.Time
	// NotifyTimeout 是投递异步通知的 HTTP 超时（0 = 缺省值；负值 = 构造
	// 失败）。
	NotifyTimeout time.Duration
}

// defaultNotifyTimeout 是通知投递的缺省超时（真实网关通知超时为秒级，假件
// 取宽裕值）。
const defaultNotifyTimeout = 10 * time.Second

// confirmAction / confirmValue 是收银台确认动作的标记参数：只出现在
// confirm POST 的 query 上、不进 form，因此不进入签名串——用户确认是网关
// 侧事件，不是商户签名内容；回传的 form 与原始已签名参数逐字一致。
const (
	confirmAction = "mockpay_action"
	confirmValue  = "confirm"
)

// gateway 是假网关 handler：持有网关侧线格式助手与按 out_trade_no 幂等的
// 内存订单表。零值不可用，经 New 构造。
type gateway struct {
	gw      *alipay.Gateway
	now     func() time.Time
	client  *http.Client
	timeout time.Duration

	mu     sync.Mutex
	orders map[string]*order // 键 = out_trade_no
}

// order 是一笔已受理订单的假件内存态：受理时建立，确认后携带支付事实
// （trade_no 与 gmt_payment 按 out_trade_no 幂等固定）。
type order struct {
	req     alipay.PayRequest
	tradeNo string
	paidAt  time.Time
	paid    bool
}

// New 按 opts 构建假支付宝网关 handler。密钥形状非法（构造期 fail-closed，
// 与真实网关同口径：无钥不受理）或 NotifyTimeout 为负时返回错误。
func New(opts Options) (http.Handler, error) {
	gw, err := alipay.NewGateway(alipay.GatewayConfig{
		AppID:          opts.AppID,
		MerchantPubPEM: opts.MerchantPubPEM,
		NotifyKeyPEM:   opts.NotifyKeyPEM,
	})
	if err != nil {
		return nil, fmt.Errorf("alipaymock: %w", err)
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	timeout := opts.NotifyTimeout
	switch {
	case timeout < 0:
		return nil, fmt.Errorf("alipaymock: notify timeout must not be negative, got %v", timeout)
	case timeout == 0:
		timeout = defaultNotifyTimeout
	}
	return &gateway{
		gw:      gw,
		now:     now,
		client:  &http.Client{Timeout: timeout},
		timeout: timeout,
		orders:  make(map[string]*order),
	}, nil
}

// ServeHTTP 分派两类请求：POST 且 query 带 confirm 动作标记的走确认支付，
// 其余一律按 alipay.trade.page.pay 网关端点受理（GET query / POST form 均
// 可——真实网关两种介质都收）。
func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.Query().Get(confirmAction) == confirmValue {
		g.serveConfirm(w, r)
		return
	}
	g.servePagePay(w, r)
}

// servePagePay 受理下单请求：验签通过则登记订单并渲染收银台页；验签或
// 形状失败一律显式拒绝（无收银台页、无通知——保真验收的核心负例）。
func (g *gateway) servePagePay(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "alipaymock: invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	req, err := g.gw.VerifyPagePay(r.Form)
	if err != nil {
		g.reject(w, err)
		return
	}
	g.accept(req)
	if err := cashierTmpl.Execute(w, cashierData{
		OutTradeNo:  req.OutTradeNo,
		Subject:     req.Subject,
		TotalAmount: req.TotalAmount,
		Action:      confirmTarget(r.URL.Path),
		Fields:      formFields(r.Form),
	}); err != nil {
		http.Error(w, "alipaymock: render cashier: "+err.Error(), http.StatusInternalServerError)
	}
}

// serveConfirm 受理确认支付：回传 form 重走同一验签（只有商户私钥的持有者
// 能驱动确认），幂等落账后同步投递一次已签名异步通知。
func (g *gateway) serveConfirm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "alipaymock: invalid form: "+err.Error(), http.StatusBadRequest)
		return
	}
	// 验签只认 POST body：query 上的动作标记不参与签名（见 confirmAction）。
	req, err := g.gw.VerifyPagePay(r.PostForm)
	if err != nil {
		g.reject(w, err)
		return
	}
	o, first := g.pay(req)
	if !first {
		g.renderPaid(w, o, "重复确认：订单已支付，通知只投递一次")
		return
	}
	note := "商户通知：已投递"
	switch req.NotifyURL {
	case "":
		note = "商户通知：请求未携带 notify_url，跳过投递"
	default:
		if err := g.deliverNotify(o); err != nil {
			note = "商户通知投递失败：" + err.Error()
		}
	}
	g.renderPaid(w, o, note)
}

// reject 把验签/形状错误落成显式拒绝响应：签名不符 403（坏签名同被拒），
// 其余形状非法 400。
func (g *gateway) reject(w http.ResponseWriter, err error) {
	code := http.StatusBadRequest
	if errors.Is(err, alipay.ErrSignatureInvalid) {
		code = http.StatusForbidden
	}
	http.Error(w, "alipaymock: "+err.Error(), code)
}

// accept 按 out_trade_no 幂等受理订单：首次受理登记订单与确定性交易号；
// 重复受理返回既有订单（同单同 trade_no，重复下单不产生新交易）。
func (g *gateway) accept(req alipay.PayRequest) *order {
	g.mu.Lock()
	defer g.mu.Unlock()
	if o, ok := g.orders[req.OutTradeNo]; ok {
		return o
	}
	o := &order{req: req, tradeNo: tradeNoFor(req.OutTradeNo)}
	g.orders[req.OutTradeNo] = o
	return o
}

// pay 幂等落账：首笔确认置位 paid 并固定支付时刻（gmt_payment 由此唯一）；
// 后续确认（含并发重放）不再产生第二次支付事实。返回值为本次调用是否为
// 新支付，驱动通知是否投递。
func (g *gateway) pay(req alipay.PayRequest) (*order, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	o, ok := g.orders[req.OutTradeNo]
	if !ok {
		o = &order{req: req, tradeNo: tradeNoFor(req.OutTradeNo)}
		g.orders[req.OutTradeNo] = o
	}
	if o.paid {
		return o, false
	}
	o.paid = true
	o.paidAt = g.now()
	return o, true
}

// deliverNotify 组装已签名异步通知并 form-POST 到商户 notify_url（与真实
// 网关通知同一介质；签名由 alipay.Gateway 构建，商户侧以支付宝公钥经
// Client.VerifyNotify 可验）。2xx 视为投递成功。
func (g *gateway) deliverNotify(o *order) error {
	form, err := g.gw.BuildNotify(alipay.TradeNotify{
		TradeNo:     o.tradeNo,
		OutTradeNo:  o.req.OutTradeNo,
		TotalAmount: o.req.TotalAmount,
		Subject:     o.req.Subject,
		PaidAt:      o.paidAt,
	})
	if err != nil {
		return fmt.Errorf("build notify: %w", err)
	}
	resp, err := g.client.PostForm(o.req.NotifyURL, form)
	if err != nil {
		return fmt.Errorf("post notify: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("notify endpoint status %s", resp.Status)
	}
	return nil
}

// renderPaid 渲染支付结果页（模板失败按 500 显式报错——浏览器可见的假件
// 内部故障不该伪装成成功页）。
func (g *gateway) renderPaid(w http.ResponseWriter, o *order, note string) {
	if err := paidTmpl.Execute(w, paidData{
		TradeNo:    o.tradeNo,
		OutTradeNo: o.req.OutTradeNo,
		Note:       note,
	}); err != nil {
		http.Error(w, "alipaymock: render paid page: "+err.Error(), http.StatusInternalServerError)
	}
}

// tradeNoFor 生成假交易号：真实 trade_no 是网关侧交易流水（28 位）；假件
// 以 out_trade_no 的 SHA-256 摘要派生同长度确定性串——同单恒同号，进程
// 重启不漂移（重放幂等的组成部分）。
func tradeNoFor(outTradeNo string) string {
	sum := sha256.Sum256([]byte("mockpay trade_no:" + outTradeNo))
	return hex.EncodeToString(sum[:14])
}

// confirmTarget 构建收银台确认动作的目标 URL：原路径 + query 上的动作标记
// （标记在 query、签名参数在 form，二者互不污染）。
func confirmTarget(path string) string {
	q := url.Values{confirmAction: {confirmValue}}.Encode()
	return path + "?" + q
}

// formField 是收银台确认表单的隐藏域（原样回传已验签参数）。
type formField struct{ Name, Value string }

// formFields 把已验签的请求参数展开为确定顺序的隐藏域列表（升序；验签已
// 排除重复键）。
func formFields(form url.Values) []formField {
	fields := make([]formField, 0, len(form))
	for _, k := range slices.Sorted(maps.Keys(form)) {
		fields = append(fields, formField{Name: k, Value: form.Get(k)})
	}
	return fields
}

// cashierData 是收银台页模板的数据。
type cashierData struct {
	OutTradeNo  string
	Subject     string
	TotalAmount string
	Action      string
	Fields      []formField
}

// cashierTmpl 是收银台页模板：展示订单要素（out_trade_no / subject /
// total_amount）与确认支付动作；确认表单以隐藏域原样回传已验签参数。
// html/template 自动转义——已签名参数中的任何 HTML 元字符都不会逃逸成标记。
var cashierTmpl = template.Must(template.New("cashier").Parse(`<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>支付宝收银台（mockpay）</title></head>
<body>
<h1>支付宝收银台（本地假网关）</h1>
<dl>
<dt>商户订单号</dt><dd>{{.OutTradeNo}}</dd>
<dt>商品标题</dt><dd>{{.Subject}}</dd>
<dt>订单金额</dt><dd>{{.TotalAmount}} 元</dd>
</dl>
<form method="POST" action="{{.Action}}">
{{range .Fields}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">
{{end}}<button type="submit">确认支付</button>
</form>
</body>
</html>
`))

// paidData 是支付结果页模板的数据。
type paidData struct {
	TradeNo    string
	OutTradeNo string
	Note       string
}

// paidTmpl 是支付结果页模板：展示交易号与通知投递结果。
var paidTmpl = template.Must(template.New("paid").Parse(`<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>支付结果（mockpay）</title></head>
<body>
<h1>支付成功</h1>
<dl>
<dt>支付宝交易号</dt><dd>{{.TradeNo}}</dd>
<dt>商户订单号</dt><dd>{{.OutTradeNo}}</dd>
</dl>
<p>{{.Note}}</p>
</body>
</html>
`))
