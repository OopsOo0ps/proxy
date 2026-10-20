package nodes

import (
	"errors"
	"net"
	"testing"
)

// 回归断言（修复缺陷前编写，用于证明缺陷存在）：bind 阶段句柄 pooledPrepared
// 必须透传半关闭能力，与 DialTunnel 返回的 *tls.Conn 语义等价。否则
// relay.halfClose（internal/relay/relay.go）对预热链路上的包装类型静默 no-op，
// 客户端 FIN 传不到节点，连接名额要等到 timeouts.idle 超时才释放。
var (
	_ interface{ CloseWrite() error } = pooledPrepared{}
	_ interface{ CloseRead() error }  = pooledPrepared{}
)

// poolHalfCloseRecorder 包装一条内存管道连接，记录半关闭调用是否真正透传到底层。
type poolHalfCloseRecorder struct {
	net.Conn
	closeWriteCalls int
	closeReadCalls  int
	closeWriteErr   error
}

func (c *poolHalfCloseRecorder) CloseWrite() error {
	c.closeWriteCalls++
	return c.closeWriteErr
}

func (c *poolHalfCloseRecorder) CloseRead() error {
	c.closeReadCalls++
	return nil
}

// TestPooledPreparedCloseWriteDelegatesToUnderlying 验证 pooledPrepared 把
// CloseWrite/CloseRead 透传到底层连接（含错误值原样返回），而非静默吞掉。
func TestPooledPreparedCloseWriteDelegatesToUnderlying(t *testing.T) {
	base, _ := net.Pipe()
	defer func() { _ = base.Close() }()

	wantErr := errors.New("underlying close write failed")
	rec := &poolHalfCloseRecorder{Conn: base, closeWriteErr: wantErr}
	c := pooledPrepared{Conn: rec}

	cw, ok := any(c).(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("pooledPrepared must implement CloseWrite (bind-stage handle must match *tls.Conn from DialTunnel)")
	}
	if err := cw.CloseWrite(); !errors.Is(err, wantErr) {
		t.Fatalf("CloseWrite() error = %v, want %v", err, wantErr)
	}
	if rec.closeWriteCalls != 1 {
		t.Fatalf("CloseWrite delegated to underlying %d times, want 1", rec.closeWriteCalls)
	}

	cr, ok := any(c).(interface{ CloseRead() error })
	if !ok {
		t.Fatal("pooledPrepared must implement CloseRead")
	}
	if err := cr.CloseRead(); err != nil {
		t.Fatalf("CloseRead() error = %v, want nil", err)
	}
	if rec.closeReadCalls != 1 {
		t.Fatalf("CloseRead delegated to underlying %d times, want 1", rec.closeReadCalls)
	}
}

// TestPooledPreparedCloseWriteUnsupportedUnderlyingReturnsNil 验证底层不支持
// 半关闭时透传退化为 no-op 并返回 nil，与 relay.halfClose 的容忍语义一致。
func TestPooledPreparedCloseWriteUnsupportedUnderlyingReturnsNil(t *testing.T) {
	base, _ := net.Pipe()
	defer func() { _ = base.Close() }()
	// 前置条件：net.Pipe 的连接自身不实现半关闭。
	if _, ok := base.(interface{ CloseWrite() error }); ok {
		t.Fatal("precondition broken: net.Pipe conn unexpectedly implements CloseWrite")
	}

	c := pooledPrepared{Conn: base}
	if err := c.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite() on unsupported underlying = %v, want nil", err)
	}
	if err := c.CloseRead(); err != nil {
		t.Fatalf("CloseRead() on unsupported underlying = %v, want nil", err)
	}
}
