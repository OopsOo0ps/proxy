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
func startReloadApp(t *testing.T, cfg *config.Config) *serverapp.App {
	t.Helper()
	app, err := serverapp.New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("serverapp.New: %v", err)
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

// withUsers 返回换了凭据的配置副本（同监听地址：同端口重载）。
func withUsers(t *testing.T, cfg *config.Config, users ...[2]string) *config.Config {
	t.Helper()
	next := *cfg
	next.Inbounds = append([]config.Inbound(nil), cfg.Inbounds...)
	old := map[string]any{}
	if err := next.Inbounds[0].Params.Decode(&old); err != nil {
		t.Fatal(err)
	}
	certFile, _ := old["cert-file"].(string)
	keyFile, _ := old["key-file"].(string)
	pairs := make([][2]string, 0, len(users))
	pairs = append(pairs, users...)
	next.Inbounds[0].Params = usersOf(t, certFile, keyFile, pairs...)
	return &next
}

// withCert 返回换了证书的配置副本。
func withCert(t *testing.T, cfg *config.Config, certFile, keyFile string) *config.Config {
	t.Helper()
	next := *cfg
	next.Inbounds = append([]config.Inbound(nil), cfg.Inbounds...)
	old := map[string]any{}
	if err := next.Inbounds[0].Params.Decode(&old); err != nil {
		t.Fatal(err)
	}
	users, _ := old["users"].([]any)
	pairs := make([][2]string, 0, len(users))
	for _, u := range users {
		m, _ := u.(map[string]any)
		pairs = append(pairs, [2]string{fmt.Sprint(m["username"]), fmt.Sprint(m["password"])})
	}
	next.Inbounds[0].Params = usersOf(t, certFile, keyFile, pairs...)
	return &next
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

	next := withUsers(t, cfg, [2]string{"alice", "new-secret"})
	if err := app.Reload(next); err != nil {
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
	cfg.Inbounds[0].Params = trojanParams(t, certA, keyA, "alice", "secret")
	app := startReloadApp(t, cfg)
	serialA := tlsPeerSerial(t, app.TunnelAddr())

	next := withCert(t, cfg, certB, keyB)
	if err := app.Reload(next); err != nil {
		t.Fatalf("reload: %v", err)
	}
	serialB := tlsPeerSerial(t, app.TunnelAddr())
	if serialA.Cmp(serialB) == 0 {
		t.Fatal("certificate did not rotate after reload")
	}

	// 无效证书路径：拒绝重载，旧证书（serialB）继续服务。
	bad := withCert(t, cfg, filepath.Join(dirA, "missing.crt"), keyB)
	if err := app.Reload(bad); err == nil {
		t.Fatal("reload with missing certificate must fail")
	}
	if got := tlsPeerSerial(t, app.TunnelAddr()); got.Cmp(serialB) != 0 {
		t.Fatal("failed reload changed the serving certificate")
	}
}

// TestReloadMovesTunnelListener 验证重载支持监听变更（§8.2：快照重建默认，
// "需重启字段"不存在）：隧道监听在重载后原子迁移——新端口立即服务，
// 旧端口停止接受，且成功 / 失败计数口径不变。
func TestReloadMovesTunnelListener(t *testing.T) {
	cfg := baseServerCfg(t)
	cfg.API.Listen = "127.0.0.1:0"
	app := startReloadApp(t, cfg)
	target := startEchoTarget(t)
	oldAddr := app.TunnelAddr()

	newAddr := "127.0.0.1:" + portOfFree(t)
	next := *cfg
	next.Inbounds = append([]config.Inbound(nil), cfg.Inbounds...)
	next.Inbounds[0].Listen = newAddr
	if err := app.Reload(&next); err != nil {
		t.Fatalf("reload with moved listener: %v", err)
	}
	if got := app.TunnelAddr(); got != newAddr {
		t.Fatalf("listener did not move: addr = %q, want %q", got, newAddr)
	}
	if got := tunnelRoundTrip(t, app, "secret", target, "ping-moved"); got != "ping-moved" {
		t.Fatalf("tunnel via new listener: echo = %q", got)
	}
	if conn, err := net.DialTimeout("tcp", oldAddr, 300*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("old listener must stop accepting after the reload")
	}
}

// portOfFree 返回一个刚释放端口的端口段。
func portOfFree(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// TestReloadCountsMetrics 验证成功 / 失败重载都计入 config_reloads_total，
// 且关停期重载被拒绝。
func TestReloadCountsMetrics(t *testing.T) {
	cfg := baseServerCfg(t)
	cfg.API.Listen = "127.0.0.1:0"
	app := startReloadApp(t, cfg)
	target := startEchoTarget(t)

	// 构建失败：证书路径无效。
	bad := withCert(t, cfg, filepath.Join(t.TempDir(), "missing.crt"), "missing.key")
	if err := app.Reload(bad); err == nil {
		t.Fatal("reload with missing certificate must fail")
	}
	// 失败后隧道不受影响。
	if got := tunnelRoundTrip(t, app, "secret", target, "ping-ok"); got != "ping-ok" {
		t.Fatalf("tunnel after rejected reload: echo = %q", got)
	}

	// 成功重载：凭据更新计数为 success。
	next := withUsers(t, cfg, [2]string{"alice", "new-secret"})
	if err := app.Reload(next); err != nil {
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
	cfg.API.Listen = "127.0.0.1:0"
	app := startReloadApp(t, cfg)

	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	if err := os.WriteFile(path, []byte("unknown_field: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := app.ReloadFile(path, ""); err == nil {
		t.Fatal("config with unknown field must fail to reload")
	}

	old := map[string]any{}
	if err := cfg.Inbounds[0].Params.Decode(&old); err != nil {
		t.Fatal(err)
	}
	certFile, _ := old["cert-file"].(string)
	keyFile, _ := old["key-file"].(string)
	good := fmt.Sprintf("inbounds:\n  - type: trojan\n    listen: %q\n    params:\n      cert-file: %q\n      key-file: %q\n      users:\n        - username: bob\n          password: new-secret\napi: { listen: %q }\n",
		cfg.Inbounds[0].Listen, certFile, keyFile, cfg.API.Listen)
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

// TestReloadRejectsDuringShutdown 验证关停期拒绝重载（§8.2）：
// 排空已开始时收到重载请求，明确拒绝且不启动半死的新运行时。
func TestReloadRejectsDuringShutdown(t *testing.T) {
	cfg := baseServerCfg(t)
	app, err := serverapp.New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("serverapp.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})

	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		err := app.Reload(withUsers(t, cfg, [2]string{"alice", "late-secret"}))
		if err != nil {
			if !strings.Contains(err.Error(), "shutting down; reload ignored") {
				t.Fatalf("reload during shutdown: got %v", err)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("reload during shutdown must be rejected")
}
