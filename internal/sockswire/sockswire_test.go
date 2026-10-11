package sockswire

import (
	"bytes"
	"strings"
	"testing"
)

func TestAddrRoundTrip(t *testing.T) {
	cases := []struct {
		host string
		port uint16
	}{
		{"1.2.3.4", 80},
		{"::1", 443},
		{"2001:db8::1", 8443},
		{"example.com", 8080},
		{"xn--fiqs8s.example", 1234},
	}
	for _, tc := range cases {
		encoded, err := EncodeAddr(tc.host, tc.port)
		if err != nil {
			t.Fatalf("EncodeAddr(%q): %v", tc.host, err)
		}
		host, port, err := DecodeAddr(bytes.NewReader(encoded))
		if err != nil {
			t.Fatalf("DecodeAddr(%q): %v", tc.host, err)
		}
		if host != tc.host || port != tc.port {
			t.Fatalf("round trip = (%q, %d), want (%q, %d)", host, port, tc.host, tc.port)
		}
	}
}

func TestEncodeAddrRejects(t *testing.T) {
	if _, err := EncodeAddr("", 80); err == nil {
		t.Fatal("empty host should be rejected")
	}
	if _, err := EncodeAddr(strings.Repeat("a", 256), 80); err == nil {
		t.Fatal("oversized domain should be rejected")
	}
}

func TestDecodeAddrRejects(t *testing.T) {
	// 未知地址类型。
	if _, _, err := DecodeAddr(bytes.NewReader([]byte{0x02, 1, 2, 3, 4})); err == nil {
		t.Fatal("unsupported atyp should be rejected")
	}
	// 空域名。
	if _, _, err := DecodeAddr(bytes.NewReader([]byte{ATYPDomain, 0x00})); err == nil {
		t.Fatal("empty domain should be rejected")
	}
	// 截断的 IPv4。
	if _, _, err := DecodeAddr(bytes.NewReader([]byte{ATYPIPv4, 1, 2})); err == nil {
		t.Fatal("truncated ipv4 should be rejected")
	}
	// 缺少端口。
	if _, _, err := DecodeAddr(bytes.NewReader([]byte{ATYPIPv4, 1, 2, 3, 4})); err == nil {
		t.Fatal("missing port should be rejected")
	}
}
