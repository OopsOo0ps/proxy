package serverapp_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/accounts"
	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/payment"
	"github.com/OopsOo0ps/proxy/internal/serverapp"
	"github.com/OopsOo0ps/proxy/internal/testutil"
	"gopkg.in/yaml.v3"
)

// certOnlyParams 构造不带静态凭据的服务端 trojan 参数（accounts 模式：凭据
// 归动态账户库，静态 users 与之互斥）。
func certOnlyParams(t *testing.T, certFile, keyFile string) yaml.Node {
	t.Helper()
	body := "cert-file: " + quote(certFile) + "\nkey-file: " + quote(keyFile) + "\n"
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	return *doc.Content[0]
}

// paymentTestCfg 构造启用支付的完整服务端配置：TempDir 真实文件（账户库 /
// 订单库 / 商户私钥 / 支付宝公钥——由 testutil 生成，与 make dev-keys 同格式），
// 全部监听 127.0.0.1:0（端口冲突免疫）。
func paymentTestCfg(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile, err := testutil.WriteTLSCertFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	accountsPath := filepath.Join(dir, "accounts.json")
	if err := os.WriteFile(accountsPath, []byte("{\"version\":1,\"users\":[]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	merchantKey, _, err := testutil.NewRSAKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	_, gatewayPub, err := testutil.NewRSAKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	merchantKeyPath := filepath.Join(dir, "alipay-merchant-key.pem")
	if err := os.WriteFile(merchantKeyPath, merchantKey, 0o600); err != nil {
		t.Fatal(err)
	}
	gatewayPubPath := filepath.Join(dir, "alipay-gateway-pub.pem")
	if err := os.WriteFile(gatewayPubPath, gatewayPub, 0o600); err != nil {
		t.Fatal(err)
	}
	return &config.Config{
		Inbounds: []config.Inbound{{
			Type:   config.TypeTrojan,
			Listen: "127.0.0.1:0",
			Params: certOnlyParams(t, certFile, keyFile),
		}},
		Accounts: &config.Accounts{File: accountsPath},
		Control:  &config.Control{Listen: "127.0.0.1:0"},
		Payment: &config.Payment{
			GatewayURL:          "https://127.0.0.1:9400/gateway.do",
			AppID:               "2026000000000000",
			MerchantKeyFile:     merchantKeyPath,
			AlipayPublicKeyFile: gatewayPubPath,
			NotifyURL:           "http://127.0.0.1:9300/notify/alipay",
			OrdersFile:          filepath.Join(dir, "orders.json"),
			PeriodDays:          30,
			PriceCents:          3000,
		},
		Timeouts: config.Timeouts{
			Dial:      config.Duration(3 * time.Second),
			Handshake: config.Duration(3 * time.Second),
			Idle:      config.Duration(30 * time.Second),
		},
		Log: config.Log{Level: "error", Format: "json"},
	}
}

// serveControl 启动已构建运行时的控制面（Build 已绑定监听），测试结束关停。
func serveControl(t *testing.T, rt *serverapp.Runtime) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rt.Control.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("control serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("control serve did not stop")
		}
	})
	return "http://" + rt.Control.Addr()
}

// controlDo 发送请求并返回状态码与响应体原文。
func controlDo(t *testing.T, method, url, contentType, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s: read response: %v", method, url, err)
	}
	return resp.StatusCode, string(raw)
}

// TestBuildWiresPaymentEndpoints 组装根接线验收（设计书 §2.1 迭代③）：payment
// 模式下 Build 构建支付组件并注入控制面——真实密钥加载、下单出已签名收银台
// URL、订单落盘 orders_file、未启用支付时路由不存在。
func TestBuildWiresPaymentEndpoints(t *testing.T) {
	cfg := paymentTestCfg(t)
	rt, err := serverapp.Build(cfg, serverapp.BuildOptions{})
	if err != nil {
		t.Fatalf("serverapp.Build: %v", err)
	}
	// Cleanup 是 LIFO：先登记 rt.Close（最后执行），serveControl 的 cancel 排空
	// 先行——控制面经 ctx 关停（优雅 Shutdown）而非监听被硬关。
	t.Cleanup(func() { rt.Close() })
	if rt.Control == nil {
		t.Fatal("payment mode: rt.Control must be built")
	}
	base := serveControl(t, rt)

	// 建用户 → 下单：201，返回 order_id + 指向配置网关的 pay_url。
	if code, body := controlDo(t, http.MethodPost, base+"/users", "application/json",
		`{"username":"alice","password":"pw-alice"}`); code != http.StatusCreated {
		t.Fatalf("create user: got status %d (body: %s), want 201", code, body)
	}
	code, body := controlDo(t, http.MethodPost, base+"/orders", "application/json", `{"username":"alice"}`)
	if code != http.StatusCreated {
		t.Fatalf("create order: got status %d (body: %s), want 201", code, body)
	}
	var order struct {
		OrderID string `json:"order_id"`
		PayURL  string `json:"pay_url"`
	}
	if err := json.Unmarshal([]byte(body), &order); err != nil {
		t.Fatalf("decode order response %q: %v", body, err)
	}
	if order.OrderID == "" || !strings.HasPrefix(order.PayURL, "https://127.0.0.1:9400/gateway.do?") {
		t.Fatalf("order response = %+v, want order_id and gateway pay_url", order)
	}

	// 未知用户 ⇒ 404。
	if code, _ := controlDo(t, http.MethodPost, base+"/orders", "application/json", `{"username":"ghost"}`); code != http.StatusNotFound {
		t.Fatalf("unknown user order: got status %d, want 404", code)
	}

	// 订单确实落在配置的 orders_file（组装根接线的文件路径生效）。
	store, err := accounts.Open(cfg.Accounts.File)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := payment.Open(cfg.Payment.OrdersFile, store, cfg.Payment.PeriodDays, cfg.Payment.PriceCents)
	if err != nil {
		t.Fatalf("reopen orders file: %v", err)
	}
	orders := svc.List()
	if len(orders) != 1 || orders[0].OrderID != order.OrderID || orders[0].Status != payment.OrderPending {
		t.Fatalf("persisted orders = %+v, want the created pending order", orders)
	}

	// 通知端点在场且 fail-closed：空表单（无法验签）⇒ 纯文本 fail。
	code, body = controlDo(t, http.MethodPost, base+"/notify/alipay", "application/x-www-form-urlencoded", "")
	if code == http.StatusOK || body == "success" {
		t.Fatalf("empty notify: got (%d, %q), want rejection", code, body)
	}
}

// TestBuildPaymentFailsClosedOnBadInputs 组装期 fail-closed（设计书 §5）：
// 密钥文件缺失 / 订单库损坏 = 构建失败，进程不起。
func TestBuildPaymentFailsClosedOnBadInputs(t *testing.T) {
	// 商户私钥文件缺失。
	cfg := paymentTestCfg(t)
	cfg.Payment.MerchantKeyFile = filepath.Join(t.TempDir(), "missing-key.pem")
	if _, err := serverapp.Build(cfg, serverapp.BuildOptions{}); err == nil {
		t.Fatal("Build with missing merchant key must fail")
	} else if !strings.Contains(err.Error(), "merchant key") {
		t.Fatalf("Build error = %v, want it to name the merchant key", err)
	}

	// 支付宝公钥不可解析。
	cfg = paymentTestCfg(t)
	if err := os.WriteFile(cfg.Payment.AlipayPublicKeyFile, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := serverapp.Build(cfg, serverapp.BuildOptions{}); err == nil {
		t.Fatal("Build with unparsable alipay public key must fail")
	}

	// 订单库损坏（orders_file 严格加载）。
	cfg = paymentTestCfg(t)
	if err := os.WriteFile(cfg.Payment.OrdersFile, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := serverapp.Build(cfg, serverapp.BuildOptions{}); err == nil {
		t.Fatal("Build with corrupt orders file must fail")
	}
}
