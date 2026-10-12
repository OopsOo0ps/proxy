package serverapp_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/serverapp"
	"github.com/OopsOo0ps/proxy/internal/testutil"
	"github.com/OopsOo0ps/proxy/internal/trojan"
)

// startReloadApp 启动 serverapp 并在测试结束时优雅关停。
func startReloadApp(t *testing.T, cfg *config.Server) *serverapp.App {
	t.Helper()
	app, err := serverapp.New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("serverapp.New: %v", err)
	}
	if err := app.Listen(); err != nil {
		t.Fatalf("serverapp.Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("server Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("server Serve did not stop")
		}
	})
	return app
}

// startEchoTarget 启动回显 TCP 服务（把收到的内容原样写回）。
func startEchoTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// tunnelRoundTrip 经 Trojan 隧道把 payload 发往 target 并读取响应。
func tunnelRoundTrip(t *testing.T, app *serverapp.App, password, target, payload string) string {
	t.Helper()
	host, portString, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := trojan.Dial(ctx, trojan.ClientConfig{
		ServerAddr:       app.TunnelAddr(),
		Password:         password,
		TLSConfig:        &tls.Config{InsecureSkipVerify: true},
		DialTimeout:      3 * time.Second,
		HandshakeTimeout: 3 * time.Second,
	}, core.Target{Host: host, Port: uint16(port)})
	if err != nil {
		t.Fatalf("trojan dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("tunnel write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("tunnel read: %v", err)
	}
	return string(buf[:n])
}

// tlsPeerSerial 做一次 TLS 握手并返回服务端证书序列号。
func tlsPeerSerial(t *testing.T, addr string) *big.Int {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber
}

// TestReloadSwapsTunnelUsers 验证热加载后隧道凭据原子替换：
// 新口令立即可用，旧口令立即失效（收到伪装页面而非数据）。
func TestReloadSwapsTunnelUsers(t *testing.T) {
	cfg := baseServerCfg(t)
	app := startReloadApp(t, cfg)
	target := startEchoTarget(t)

	if got := tunnelRoundTrip(t, app, "secret", target, "ping-1"); got != "ping-1" {
		t.Fatalf("initial password: echo = %q", got)
	}

	next := *cfg
	next.Users = []config.User{{Username: "alice", Password: "new-secret"}}
	if err := app.Reload(&next); err != nil {
		t.Fatalf("reload: %v", err)
	}

	if got := tunnelRoundTrip(t, app, "new-secret", target, "ping-2"); got != "ping-2" {
		t.Fatalf("new password after reload: echo = %q", got)
	}
	// 认证失败时服务端回放伪装页面（HTTP 响应头先行），而非向目标转发数据。
	if got := tunnelRoundTrip(t, app, "secret", target, "ping-3"); !strings.HasPrefix(got, "HTTP/1.1 200 OK") {
		t.Fatalf("old password after reload: response = %q, want decoy response", got)
	}
}

// TestReloadRotatesCertificate 验证证书文件热重载：新证书立即用于新握手；
// 证书路径无效时拒绝重载并保持旧证书继续服务。
func TestReloadRotatesCertificate(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	certA, keyA, err := testutil.WriteTLSCertFiles(dirA)
	if err != nil {
		t.Fatal(err)
	}
	certB, keyB, err := testutil.WriteTLSCertFiles(dirB)
	if err != nil {
		t.Fatal(err)
	}

	cfg := baseServerCfg(t)
	cfg.TLS = config.ServerTLS{CertFile: certA, KeyFile: keyA}
	app := startReloadApp(t, cfg)
	serialA := tlsPeerSerial(t, app.TunnelAddr())

	next := *cfg
	next.TLS = config.ServerTLS{CertFile: certB, KeyFile: keyB}
	if err := app.Reload(&next); err != nil {
		t.Fatalf("reload: %v", err)
	}
	serialB := tlsPeerSerial(t, app.TunnelAddr())
	if serialA.Cmp(serialB) == 0 {
		t.Fatal("certificate did not rotate after reload")
	}

	// 无效证书路径：拒绝重载，旧证书（serialB）继续服务。
	bad := *cfg
	bad.TLS = config.ServerTLS{CertFile: filepath.Join(dirA, "missing.crt"), KeyFile: keyB}
	if err := app.Reload(&bad); err == nil {
		t.Fatal("reload with missing certificate must fail")
	}
	if got := tlsPeerSerial(t, app.TunnelAddr()); got.Cmp(serialB) != 0 {
		t.Fatal("failed reload changed the serving certificate")
	}
}

// TestReloadRejectsListenChangeAndCountsMetrics 验证监听地址变更被拒绝
// （旧配置继续服务），且成功 / 失败都计入 config_reloads_total 指标。
func TestReloadRejectsListenChangeAndCountsMetrics(t *testing.T) {
	cfg := baseServerCfg(t)
	cfg.Metrics.Listen = "127.0.0.1:0"
	app := startReloadApp(t, cfg)
	target := startEchoTarget(t)

	// 监听地址变更：明确拒绝，隧道不受影响。
	moved := *cfg
	moved.Listen = "127.0.0.1:18443"
	if err := app.Reload(&moved); err == nil || !strings.Contains(err.Error(), "restart required") {
		t.Fatalf("listen change must be rejected with restart hint, got %v", err)
	}
	if got := tunnelRoundTrip(t, app, "secret", target, "ping-ok"); got != "ping-ok" {
		t.Fatalf("tunnel after rejected reload: echo = %q", got)
	}

	// 成功重载：凭据更新计数为 success。
	next := *cfg
	next.Users = []config.User{{Username: "alice", Password: "new-secret"}}
	if err := app.Reload(&next); err != nil {
		t.Fatalf("reload: %v", err)
	}
	body := scrapeMetricsBody(t, app.MetricsAddr())
	for _, want := range []string{`config_reloads_total{result="success"} 1`, `config_reloads_total{result="error"} 1`} {
		if !strings.Contains(body, want) {
			t.Fatalf("/metrics missing %q:\n%s", want, body)
		}
	}
}

func scrapeMetricsBody(t *testing.T, addr string) string {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("scrape metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestReloadFileCountsParseFailures 验证 ReloadFile 的计数口径：
// 文件解析失败与构建成功都恰好各计入一次 config_reloads_total。
func TestReloadFileCountsParseFailures(t *testing.T) {
	cfg := baseServerCfg(t)
	cfg.Metrics.Listen = "127.0.0.1:0"
	app := startReloadApp(t, cfg)

	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	if err := os.WriteFile(path, []byte("unknown_field: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := app.ReloadFile(path, ""); err == nil {
		t.Fatal("config with unknown field must fail to reload")
	}

	good := fmt.Sprintf("listen: %q\ntls: { cert_file: %q, key_file: %q }\nusers: [{ username: bob, password: new-secret }]\nmetrics: { listen: %q }\n",
		cfg.Listen, cfg.TLS.CertFile, cfg.TLS.KeyFile, cfg.Metrics.Listen)
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := app.ReloadFile(path, ""); err != nil {
		t.Fatalf("reload: %v", err)
	}

	body := scrapeMetricsBody(t, app.MetricsAddr())
	for _, want := range []string{
		`config_reloads_total{result="success"} 1`,
		`config_reloads_total{result="error"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/metrics missing %q:\n%s", want, body)
		}
	}
}
