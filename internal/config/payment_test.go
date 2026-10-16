package config_test

import (
	"strings"
	"testing"
)

// paymentBase 是启用支付的服务端配置骨架：accounts + control 在场（payment
// 的前置条件），trojan 入站不带静态 users（accounts 模式互斥校验的前提）。
const paymentBase = `
accounts:
  file: var/accounts.json
control:
  listen: "127.0.0.1:9300"
payment:
  gateway_url: "https://127.0.0.1:9400/gateway.do"
  app_id: "2026000000000000"
  merchant_key_file: configs/example-alipay-merchant-key.pem
  alipay_public_key_file: configs/example-alipay-gateway-pub.pem
  notify_url: "http://127.0.0.1:9300/notify/alipay"
  orders_file: var/orders.json
  period_days: 30
  price_cents: 3000
inbounds:
  - type: trojan
    listen: "0.0.0.0:8443"
    params:
      cert-file: server.crt
      key-file: server.key
`

func TestPaymentModeParses(t *testing.T) {
	cfg := mustParse(t, paymentBase, serverProtocols)
	p := cfg.Payment
	if p == nil {
		t.Fatal("payment = nil, want section parsed")
	}
	if p.GatewayURL != "https://127.0.0.1:9400/gateway.do" || p.AppID != "2026000000000000" ||
		p.MerchantKeyFile != "configs/example-alipay-merchant-key.pem" ||
		p.AlipayPublicKeyFile != "configs/example-alipay-gateway-pub.pem" ||
		p.NotifyURL != "http://127.0.0.1:9300/notify/alipay" ||
		p.OrdersFile != "var/orders.json" ||
		p.PeriodDays != 30 || p.PriceCents != 3000 {
		t.Fatalf("payment = %+v", p)
	}
	// 前置条件段必须原样在场。
	if cfg.Accounts == nil || cfg.Accounts.File != "var/accounts.json" || cfg.Control == nil || cfg.Control.Listen != "127.0.0.1:9300" {
		t.Fatalf("accounts/control = %+v %+v", cfg.Accounts, cfg.Control)
	}
}

func TestPaymentAbsentKeepsBehavior(t *testing.T) {
	// 段缺省 = nil 指针，存量配置（无 payment）行为逐字不变。
	cfg := mustParse(t, minimalServer, serverProtocols)
	if cfg.Payment != nil {
		t.Fatalf("absent payment must stay nil, got %+v", cfg.Payment)
	}
}

func TestPaymentRequiresAccountsAndControl(t *testing.T) {
	// 无 accounts（也无 control）：payment 前置条件直接报错。
	mustFail(t, paymentWithoutSection("accounts"), serverProtocols,
		"payment: requires both accounts and control sections")

	// 有 accounts、无 control：accounts⇒control 的既有校验先于 payment 报错
	//（同一不变量的另一条观察路径——payment⇒accounts+control 仍被强制）。
	mustFail(t, paymentWithoutSection("control"), serverProtocols,
		"control.listen: required when accounts is configured")
}

func TestPaymentGatewayHTTPSOnly(t *testing.T) {
	for _, gateway := range []string{
		"http://127.0.0.1:9400/gateway.do", // 明文 http 一律拒绝（环回也不例外）
		"127.0.0.1:9400",                   // 无 scheme
		"ftp://127.0.0.1:9400",             // 非 http(s) scheme
		"https:///gateway.do",              // 缺 host
	} {
		mustFail(t, strings.Replace(paymentBase, "https://127.0.0.1:9400/gateway.do", gateway, 1),
			serverProtocols, "payment.gateway_url")
	}
}

func TestPaymentPeriodAndPriceMustBePositive(t *testing.T) {
	for _, tc := range []struct{ field, value, want string }{
		{"period_days", "0", "payment.period_days: must be positive"},
		{"period_days", "-1", "payment.period_days: must be positive"},
		{"price_cents", "0", "payment.price_cents: must be positive"},
		{"price_cents", "-100", "payment.price_cents: must be positive"},
	} {
		mustFail(t, paymentWithLine(tc.field, tc.value), serverProtocols, tc.want)
	}
}

func TestPaymentPathsRequiredNoImplicitPath(t *testing.T) {
	for _, field := range []string{
		"merchant_key_file",
		"alipay_public_key_file",
		"notify_url",
		"orders_file",
	} {
		mustFail(t, paymentWithoutField(field), serverProtocols, "payment."+field+": must not be empty")
	}
}

func TestPaymentNormalization(t *testing.T) {
	// 规范化仅去空白，不派生隐式路径/URL。
	cfg := mustParse(t, `
accounts:
  file: var/accounts.json
control:
  listen: "127.0.0.1:9300"
payment:
  gateway_url: "  https://127.0.0.1:9400/gateway.do  "
  merchant_key_file: "  configs/example-alipay-merchant-key.pem  "
  alipay_public_key_file: "  configs/example-alipay-gateway-pub.pem  "
  notify_url: "  http://127.0.0.1:9300/notify/alipay  "
  orders_file: "  var/orders.json  "
  period_days: 30
  price_cents: 3000
inbounds:
  - type: trojan
    listen: "0.0.0.0:8443"
    params: { cert-file: server.crt, key-file: server.key }
`, serverProtocols)
	p := cfg.Payment
	if p.GatewayURL != "https://127.0.0.1:9400/gateway.do" ||
		p.MerchantKeyFile != "configs/example-alipay-merchant-key.pem" ||
		p.AlipayPublicKeyFile != "configs/example-alipay-gateway-pub.pem" ||
		p.NotifyURL != "http://127.0.0.1:9300/notify/alipay" ||
		p.OrdersFile != "var/orders.json" {
		t.Fatalf("normalization failed: %+v", p)
	}
}

// paymentWithLine 返回把骨架 payment 段中 field 行整行替换为
// "field: value" 的配置（避免 YAML 重复键；field 必须已在骨架中）。
func paymentWithLine(field, value string) string {
	lines := strings.Split(paymentBase, "\n")
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), field+":") {
			lines[i] = "  " + field + ": " + value
			return strings.Join(lines, "\n")
		}
	}
	panic("paymentWithLine: field not present in paymentBase: " + field)
}

// paymentWithoutField 返回删除骨架 payment 段中 field 行的配置。
func paymentWithoutField(field string) string {
	lines := strings.Split(paymentBase, "\n")
	var out []string
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), field+":") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// paymentWithoutSection 返回删除骨架中某个顶层段（accounts / control）的
// 配置（段名行 + 其后一行缩进的字段行一并删除）。
func paymentWithoutSection(section string) string {
	lines := strings.Split(paymentBase, "\n")
	var out []string
	skip := 0
	for _, l := range lines {
		if skip > 0 {
			skip--
			continue
		}
		if strings.HasPrefix(l, section+":") {
			skip = 1
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}
