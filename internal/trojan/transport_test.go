package trojan

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/outbound"
)

// newTestTransport 启动回环 Trojan 服务端（自签证书 + 回显目标）并返回
// 与之配套的传输实例，钉住「传输构造时封闭协议参数、口令派生不出包」的契约。
func newTestTransport(t *testing.T) (*Transport, core.Target) {
	t.Helper()
	echoAddr := startEcho(t)
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port, _ := strconv.ParseUint(portStr, 10, 16)

	store, err := auth.NewStore([]auth.User{{Username: "alice", Password: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Verifier: store,
		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
			return net.Dial("tcp", addr)
		},
	}
	nodeAddr, clientTLS := startTLSServer(t, srv, 3*time.Second)

	tr, err := NewTransport(ClientConfig{
		ServerAddr: nodeAddr,
		Password:   "secret",
		TLSConfig:  clientTLS,
	})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	return tr, core.Target{Host: host, Port: uint16(port)}
}

// echoThrough 验证连接可用作原始字节转发（回显目标）。
func echoThrough(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte("transport payload")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

func TestNewTransportRejectsBadPassword(t *testing.T) {
	cases := []struct {
		name     string
		password string
	}{
		{"empty password", ""},
		{"lf password", "a\nb"},
		{"cr password", "a\rb"},
	}
	for _, tc := range cases {
		if _, err := NewTransport(ClientConfig{ServerAddr: "127.0.0.1:443", Password: tc.password}); err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
	}
}

// TestTransportConformance 把 Trojan 传输跑一遍 outbound 一致性验收
// （回环 TLS 服务端 + 回显目标；dial / prewarm-bind / probe 全部三项能力，
// 断言由 internal/outbound 统一持有：未来协议接入即跑同一套验收）。
func TestTransportConformance(t *testing.T) {
	tr, target := newTestTransport(t)

	// 不可达端点（端口无人监听）：探测失败路径。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := ln.Addr().String()
	_ = ln.Close()
	dead, err := NewTransport(ClientConfig{ServerAddr: closedAddr, Password: "x", TLSConfig: &tls.Config{InsecureSkipVerify: true}})
	if err != nil {
		t.Fatal(err)
	}

	outbound.RunConformance(t, outbound.ConformanceSpec{
		Transport:  tr,
		Target:     target,
		RoundTrip:  echoThrough,
		Prewarmer:  tr,
		Prober:     tr,
		DeadProber: dead,
	})
}
