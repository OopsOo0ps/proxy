package clientapp

import (
	"testing"

	"github.com/OopsOo0ps/proxy/internal/trojan"
)

// TestClientTLSConfigClientSessionCache 验证出口 TLS 配置默认启用会话恢复
// 缓存（ClientSessionCache，LRU 1024）：不缓存时每条新隧道都要与出口节点
// 做完整 TLS 握手。仅断言配置组装结果，不做真实握手（避免 flaky）。
func TestClientTLSConfigClientSessionCache(t *testing.T) {
	cfg, err := clientTLSConfig(trojan.Params{Addr: "node.example.com:443"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("cfg = nil, want non-nil")
	}
	if cfg.ClientSessionCache == nil {
		t.Fatal("ClientSessionCache = nil, want LRU session cache")
	}
}

// TestClientTLSConfigInsecureSkipVerifyRemoteRejected 复核既有护栏：
// insecure-skip-verify 仅允许环回地址，远程节点 fail-closed（组装失败）。
func TestClientTLSConfigInsecureSkipVerifyRemoteRejected(t *testing.T) {
	if _, err := clientTLSConfig(trojan.Params{Addr: "203.0.113.10:443", InsecureSkipVerify: true}); err == nil {
		t.Fatal("non-loopback insecure-skip-verify: expected error, got nil")
	}
}
