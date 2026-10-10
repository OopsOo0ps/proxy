package serverapp_test

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/serverapp"
	"github.com/OopsOo0ps/proxy/internal/testutil"
)

func baseServerCfg(t *testing.T) *config.Server {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile, err := testutil.WriteTLSCertFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &config.Server{
		Listen: "127.0.0.1:0",
		TLS:    config.ServerTLS{CertFile: certFile, KeyFile: keyFile},
		Users:  []config.User{{Username: "alice", Password: "secret"}},
		Timeouts: config.Timeouts{
			Dial:      config.Duration(3 * time.Second),
			Handshake: config.Duration(3 * time.Second),
			Idle:      config.Duration(30 * time.Second),
		},
		Log: config.Log{Level: "error", Format: "json"},
	}
}

func TestNewRejectsMissingCert(t *testing.T) {
	cfg := baseServerCfg(t)
	cfg.TLS.CertFile = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := serverapp.New(cfg, nil); err == nil {
		t.Fatal("missing certificate should be rejected")
	}
}

func TestNewRejectsMissingDecoyFile(t *testing.T) {
	cfg := baseServerCfg(t)
	cfg.DecoyFile = filepath.Join(t.TempDir(), "missing.html")
	if _, err := serverapp.New(cfg, nil); err == nil {
		t.Fatal("missing decoy file should be rejected")
	}
}

func TestListenServeShutdown(t *testing.T) {
	cfg := baseServerCfg(t)
	cfg.Metrics.Listen = "127.0.0.1:0"
	app, err := serverapp.New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Listen(); err != nil {
		t.Fatal(err)
	}
	if app.TunnelAddr() == "" || app.MetricsAddr() == "" {
		t.Fatal("addresses should be reported after Listen")
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
