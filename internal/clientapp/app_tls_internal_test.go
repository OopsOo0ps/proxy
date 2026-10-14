package clientapp

import (
	"strings"
	"testing"

	"github.com/OopsOo0ps/proxy/internal/trojan"
)

// TestClientTLSConfigInsecureSkipVerifyLoopbackGuard 验证 P2-1 护栏：
// insecure-skip-verify 仅允许环回地址；非环回节点组装失败（fail-closed）
// 且错误可读（提示改用 ca-file）。
func TestClientTLSConfigInsecureSkipVerifyLoopbackGuard(t *testing.T) {
	// 环回 IPv4 / IPv6 / localhost：insecure 允许，正常构造。
	for _, addr := range []string{"127.0.0.1:443", "[::1]:443", "localhost:8443"} {
		cfg, err := clientTLSConfig(trojan.Params{Addr: addr, Password: "secret", InsecureSkipVerify: true})
		if err != nil {
			t.Fatalf("loopback %s: unexpected error: %v", addr, err)
		}
		if !cfg.InsecureSkipVerify {
			t.Fatalf("loopback %s: InsecureSkipVerify = false, want true", addr)
		}
	}

	// 环回节点关闭 insecure：同样正常。
	if _, err := clientTLSConfig(trojan.Params{Addr: "127.0.0.1:443", Password: "secret"}); err != nil {
		t.Fatalf("loopback without insecure: unexpected error: %v", err)
	}

	// 非环回（远程节点 / 主机名）：组装失败且错误提示 ca-file。
	for _, addr := range []string{"node.example.com:443", "10.0.0.8:443", "example.com:443"} {
		_, err := clientTLSConfig(trojan.Params{Addr: addr, Password: "secret", InsecureSkipVerify: true})
		if err == nil {
			t.Fatalf("non-loopback %s: expected error, got nil", addr)
		}
		if !strings.Contains(err.Error(), "insecure-skip-verify is only allowed for loopback addresses") ||
			!strings.Contains(err.Error(), "ca-file") {
			t.Fatalf("non-loopback %s: unexpected error text: %v", addr, err)
		}
	}
}
