package outbound

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/core"
)

// fakeTransport 是进程内回环传输：直连本地回显服务端，「绑定」为空操作
// （直连即绑定）。用于在协议无关的层面验证 RunConformance 自身的断言逻辑。
type fakeTransport struct {
	addr string // 回显服务端地址
}

// dead 标记连接已作废（预热连接的关闭状态；真实协议中对应
// 「在已失效连接上补发请求必然失败」的线级行为，此处显式建模）。
type fakeConn struct {
	net.Conn
	dead atomic.Bool
}

func (c *fakeConn) Close() error {
	c.dead.Store(true)
	return c.Conn.Close()
}

func newFakeTransport(t *testing.T) *fakeTransport {
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
			go func(c net.Conn) {
				_, _ = io.Copy(c, c) // 回显
				_ = c.Close()
			}(conn)
		}
	}()
	return &fakeTransport{addr: ln.Addr().String()}
}

func (f *fakeTransport) DialTunnel(ctx context.Context, target core.Target) (net.Conn, error) {
	return net.Dial("tcp", f.addr)
}

func (f *fakeTransport) ConnectIdle(ctx context.Context) (net.Conn, error) {
	conn, err := net.Dial("tcp", f.addr)
	if err != nil {
		return nil, err
	}
	return &fakeConn{Conn: conn}, nil
}

func (f *fakeTransport) Bind(ctx context.Context, conn net.Conn, target core.Target) error {
	if fc, ok := conn.(*fakeConn); ok && fc.dead.Load() {
		return errors.New("fake: bind on discarded connection")
	}
	return nil // 直连即绑定：回显目标不需要补发请求
}

func (f *fakeTransport) Probe(ctx context.Context) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", f.addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

// deadProber 指向不可达端点（端口无人监听）。
type deadProber struct {
	addr string
}

func (p *deadProber) Probe(ctx context.Context) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", p.addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

// echoRoundTrip 断言连接可做原始字节往返（回显）。
func echoRoundTrip(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("conformance payload")
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

// TestRunConformanceWithFakeTransport 用协议无关的进程内传输验证一致性
// 验收助手本身：三项子验收（dial / prewarm-bind / probe）全部通过。
func TestRunConformanceWithFakeTransport(t *testing.T) {
	f := newFakeTransport(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := ln.Addr().String()
	_ = ln.Close()

	RunConformance(t, ConformanceSpec{
		Transport:  f,
		Target:     core.Target{Host: "echo.example", Port: 443},
		RoundTrip:  echoRoundTrip,
		Prewarmer:  f,
		Prober:     f,
		DeadProber: &deadProber{addr: closedAddr},
	})
}
