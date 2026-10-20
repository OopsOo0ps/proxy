package trojan

import (
	"errors"
	"net"
	"testing"
)

// 回归断言（修复缺陷前编写，用于证明缺陷存在）：预热句柄 idleConn 必须
// 透传半关闭能力。否则预热池命中的连接与 DialTunnel 新建的 *tls.Conn 语义
// 不等价——relay.halfClose（internal/relay/relay.go）只对实现 closeWriter 的
// 连接生效，缺失方法会静默 no-op，客户端 FIN 传不到节点，转发要等到
// timeouts.idle 超时才结束，预热名额也被整段占住。
var (
	_ interface{ CloseWrite() error } = idleConn{}
	_ interface{ CloseRead() error }  = idleConn{}
)

// halfCloseRecorder 包装一条内存管道连接，记录半关闭调用是否真正透传到底层。
type halfCloseRecorder struct {
	net.Conn
	closeWriteCalls int
	closeReadCalls  int
	closeWriteErr   error
}

func (c *halfCloseRecorder) CloseWrite() error {
	c.closeWriteCalls++
	return c.closeWriteErr
}

func (c *halfCloseRecorder) CloseRead() error {
	c.closeReadCalls++
	return nil
}

// TestIdleConnCloseWriteDelegatesToUnderlying 验证 idleConn 把 CloseWrite/
// CloseRead 透传到底层连接（含错误值原样返回），而非静默吞掉。
func TestIdleConnCloseWriteDelegatesToUnderlying(t *testing.T) {
	base, _ := net.Pipe()
	defer func() { _ = base.Close() }()

	wantErr := errors.New("underlying close write failed")
	rec := &halfCloseRecorder{Conn: base, closeWriteErr: wantErr}
	c := idleConn{Conn: rec}

	cw, ok := any(c).(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("idleConn must implement CloseWrite (prewarm-claimed tunnels must match *tls.Conn from DialTunnel)")
	}
	if err := cw.CloseWrite(); !errors.Is(err, wantErr) {
		t.Fatalf("CloseWrite() error = %v, want %v", err, wantErr)
	}
	if rec.closeWriteCalls != 1 {
		t.Fatalf("CloseWrite delegated to underlying %d times, want 1", rec.closeWriteCalls)
	}

	cr, ok := any(c).(interface{ CloseRead() error })
	if !ok {
		t.Fatal("idleConn must implement CloseRead")
	}
	if err := cr.CloseRead(); err != nil {
		t.Fatalf("CloseRead() error = %v, want nil", err)
	}
	if rec.closeReadCalls != 1 {
		t.Fatalf("CloseRead delegated to underlying %d times, want 1", rec.closeReadCalls)
	}
}

// TestIdleConnCloseWriteUnsupportedUnderlyingReturnsNil 验证底层不支持半关闭时
// 透传退化为 no-op 并返回 nil，与 relay.halfClose 对不支持连接的容忍语义一致。
func TestIdleConnCloseWriteUnsupportedUnderlyingReturnsNil(t *testing.T) {
	base, _ := net.Pipe()
	defer func() { _ = base.Close() }()
	// 前置条件：net.Pipe 的连接自身不实现半关闭。
	if _, ok := base.(interface{ CloseWrite() error }); ok {
		t.Fatal("precondition broken: net.Pipe conn unexpectedly implements CloseWrite")
	}

	c := idleConn{Conn: base}
	if err := c.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite() on unsupported underlying = %v, want nil", err)
	}
	if err := c.CloseRead(); err != nil {
		t.Fatalf("CloseRead() on unsupported underlying = %v, want nil", err)
	}
}
