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

// TestTransportDialTunnel 钉住 outbound.Transport 能力：一次调用建立绑定到
// 目标的就绪隧道。
func TestTransportDialTunnel(t *testing.T) {
	tr, target := newTestTransport(t)

	conn, err := tr.DialTunnel(context.Background(), target)
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}
	defer func() { _ = conn.Close() }()
	echoThrough(t, conn)
}

// TestTransportConnectIdleThenBind 钉住 outbound.Prewarmer 契约：先建立空闲
// 隧道（connect），停留片刻后再补发绑定请求（bind）——SHA-224 派生在 Bind
// 内部完成，调用方不接触口令摘要。
func TestTransportConnectIdleThenBind(t *testing.T) {
	tr, target := newTestTransport(t)

	conn, err := tr.ConnectIdle(context.Background())
	if err != nil {
		t.Fatalf("ConnectIdle: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// 模拟在池中停留（小于服务端握手超时）后领取。
	time.Sleep(50 * time.Millisecond)
	if err := tr.Bind(context.Background(), conn, target); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	echoThrough(t, conn)
}

// TestTransportProbe 钉住 outbound.Prober 契约：健康节点探测成功（握手后
// 立即关闭），不可达节点返回错误。
func TestTransportProbe(t *testing.T) {
	tr, _ := newTestTransport(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := tr.Probe(ctx); err != nil {
		t.Fatalf("Probe against healthy node: %v", err)
	}

	// 端口无人监听。
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
	if err := dead.Probe(ctx); err == nil {
		t.Fatal("expected probe error for closed port")
	}
}
