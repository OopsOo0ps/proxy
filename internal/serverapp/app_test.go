package serverapp_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/serverapp"
	"github.com/OopsOo0ps/proxy/internal/testutil"
	"gopkg.in/yaml.v3"
)

// baseServerCfg 构造测试用服务端配置：单 trojan 入站（自签证书）。
func baseServerCfg(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile, err := testutil.WriteTLSCertFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &config.Config{
		Inbounds: []config.Inbound{{
			Type:   config.TypeTrojan,
			Listen: "127.0.0.1:0",
			Params: trojanParams(t, certFile, keyFile, "alice", "secret"),
		}},
		Timeouts: config.Timeouts{
			Dial:      config.Duration(3 * time.Second),
			Handshake: config.Duration(3 * time.Second),
			Idle:      config.Duration(30 * time.Second),
		},
		Log: config.Log{Level: "error", Format: "json"},
	}
}

// trojanParams 把服务端 trojan 入站的协议参数编码为 yaml.Node
// （与严格解码路径一致）。
func trojanParams(t *testing.T, certFile, keyFile, username, password string) yaml.Node {
	t.Helper()
	body := "cert-file: " + quote(certFile) + "\n" +
		"key-file: " + quote(keyFile) + "\n" +
		"users:\n  - username: " + quote(username) + "\n    password: " + quote(password) + "\n"
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	return *doc.Content[0]
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// usersOf 返回服务端入站的凭据参数（测试改动用户时重建 params）。
func usersOf(t *testing.T, certFile, keyFile string, users ...[2]string) yaml.Node {
	t.Helper()
	body := "cert-file: " + quote(certFile) + "\nkey-file: " + quote(keyFile) + "\nusers:\n"
	for _, u := range users {
		body += "  - username: " + quote(u[0]) + "\n    password: " + quote(u[1]) + "\n"
	}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	return *doc.Content[0]
}

func TestNewRejectsMissingCert(t *testing.T) {
	cfg := baseServerCfg(t)
	cfg.Inbounds[0].Params = trojanParams(t, filepath.Join(t.TempDir(), "missing.pem"), filepath.Join(t.TempDir(), "missing.key"), "alice", "secret")
	if _, err := serverapp.New(cfg, nil, nil); err == nil {
		t.Fatal("missing certificate should be rejected")
	}
}

func TestNewRejectsMissingDecoyFile(t *testing.T) {
	cfg := baseServerCfg(t)
	var doc yaml.Node
	// 在原 params 基础上追加 decoy-file 字段：直接重新编码完整参数。
	params := map[string]any{}
	if err := cfg.Inbounds[0].Params.Decode(&params); err != nil {
		t.Fatal(err)
	}
	params["decoy-file"] = filepath.Join(t.TempDir(), "missing.html")
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	cfg.Inbounds[0].Params = *doc.Content[0]
	if _, err := serverapp.New(cfg, nil, nil); err == nil {
		t.Fatal("missing decoy file should be rejected")
	}
}

func TestListenServeShutdown(t *testing.T) {
	cfg := baseServerCfg(t)
	cfg.API.Listen = "127.0.0.1:0"
	app, err := serverapp.New(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if app.TunnelAddr() == "" || app.MetricsAddr() == "" {
		t.Fatal("addresses should be reported after New")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.Serve(ctx) }()

	// 无流量时 /metrics 也应暴露核心指标名。
	resp, err := http.Get("http://" + app.MetricsAddr() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	for _, name := range []string{"requests_total", "request_duration_seconds", "active_connections"} {
		if !strings.Contains(string(body), name) {
			t.Fatalf("/metrics missing %q", name)
		}
	}

	// /health：证书有效期内应为 200 + status ok。
	healthResp, err := http.Get("http://" + app.MetricsAddr() + "/health")
	if err != nil {
		t.Fatal(err)
	}
	var health struct {
		Status string  `json:"status"`
		Uptime float64 `json:"uptime"`
	}
	if err := json.NewDecoder(healthResp.Body).Decode(&health); err != nil {
		t.Fatal(err)
	}
	_ = healthResp.Body.Close()
	if healthResp.StatusCode != http.StatusOK || health.Status != "ok" || health.Uptime < 0 {
		t.Fatalf("/health = %d %+v", healthResp.StatusCode, health)
	}

	// /stats：应包含连接数与内存占用；服务端无节点池，不输出 upstreams。
	statsResp, err := http.Get("http://" + app.MetricsAddr() + "/stats")
	if err != nil {
		t.Fatal(err)
	}
	statsBody, err := io.ReadAll(statsResp.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = statsResp.Body.Close()
	if statsResp.StatusCode != http.StatusOK {
		t.Fatalf("/stats status = %d, want 200", statsResp.StatusCode)
	}
	for _, want := range []string{`"connections"`, `"memory"`} {
		if !strings.Contains(string(statsBody), want) {
			t.Fatalf("/stats missing %q:\n%s", want, statsBody)
		}
	}
	if strings.Contains(string(statsBody), `"upstreams"`) {
		t.Fatalf("服务端 /stats 不应包含 upstreams：\n%s", statsBody)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop after cancel")
	}
}

func TestHealthReportsExpiredCertificate(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, err := testutil.WriteTLSCertFilesWithValidity(
		dir, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cfg := baseServerCfg(t)
	cfg.Inbounds[0].Params = trojanParams(t, certFile, keyFile, "alice", "secret")
	cfg.API.Listen = "127.0.0.1:0"

	// 过期证书不影响启动（TLS 握手时客户端自会拒绝），由 /health 暴露依赖状态。
	app, err := serverapp.New(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.Serve(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Serve did not stop after cancel")
		}
	}()

	resp, err := http.Get("http://" + app.MetricsAddr() + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var health struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/health status = %d, want 503", resp.StatusCode)
	}
	if health.Status != "unavailable" || !strings.Contains(health.Reason, "tls certificate expired") {
		t.Fatalf("/health = %+v", health)
	}
}
