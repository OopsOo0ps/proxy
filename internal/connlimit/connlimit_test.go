package connlimit

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestLimiterDisabled(t *testing.T) {
	l := New(0)
	if l.Max() != 0 || l.Active() != 0 || l.Rejected() != 0 {
		t.Fatalf("fresh limiter: max=%d active=%d rejected=%d, want 0/0/0", l.Max(), l.Active(), l.Rejected())
	}
	if !l.TryAcquire() || l.Active() != 1 {
		t.Fatal("limiter with max=0 must behave as unlimited")
	}
	if !l.TryAcquire() {
		t.Fatal("unlimited limiter must always acquire")
	}
	l.Release()
	l.Release()
	if l.Active() != 0 {
		t.Fatalf("active=%d, want 0", l.Active())
	}
	if l.Rejected() != 0 {
		t.Fatalf("rejected=%d, want 0", l.Rejected())
	}
	// nil 接收者语义仍然安全（仅作为防御）。
	var nilLimiter *Limiter
	if !nilLimiter.TryAcquire() || nilLimiter.Max() != 0 {
		t.Fatal("nil limiter must behave as unlimited")
	}
	nilLimiter.Release()
	nilLimiter.SetMax(10)
}

func TestLimiterSetMax(t *testing.T) {
	l := New(0) // 初始不限制
	if !l.TryAcquire() {
		t.Fatal("acquire under unlimited must succeed")
	}
	if !l.TryAcquire() {
		t.Fatal("second acquire under unlimited must succeed")
	}

	// 调低上限：不中断已占用名额，只拒绝新的占用。
	l.SetMax(2)
	if l.Max() != 2 || l.Active() != 2 {
		t.Fatalf("max=%d active=%d, want 2/2", l.Max(), l.Active())
	}
	if l.TryAcquire() {
		t.Fatal("acquire at limit must fail")
	}
	if l.Rejected() != 1 {
		t.Fatalf("rejected=%d, want 1", l.Rejected())
	}

	// 活跃数回落到新上限以下后恢复接受。
	l.Release()
	if !l.TryAcquire() {
		t.Fatal("acquire after release must succeed")
	}

	// 调高上限与解除上限（0）立即生效。
	l.SetMax(10)
	for i := l.Active(); i < 10; i++ {
		if !l.TryAcquire() {
			t.Fatalf("acquire #%d under raised limit must succeed", i+1)
		}
	}
	if l.TryAcquire() {
		t.Fatal("acquire at raised limit must fail")
	}
	l.SetMax(0)
	if !l.TryAcquire() {
		t.Fatal("acquire after removing limit must succeed")
	}
}

func TestLimiterCountsAndRejects(t *testing.T) {
	l := New(2)
	if !l.TryAcquire() {
		t.Fatal("first acquire must succeed")
	}
	if !l.TryAcquire() {
		t.Fatal("second acquire must succeed")
	}
	if l.TryAcquire() {
		t.Fatal("third acquire must fail")
	}
	if l.Active() != 2 || l.Rejected() != 1 {
		t.Fatalf("active=%d rejected=%d, want 2/1", l.Active(), l.Rejected())
	}
	l.Release()
	if l.Active() != 1 {
		t.Fatalf("active=%d, want 1", l.Active())
	}
	if !l.TryAcquire() {
		t.Fatal("acquire after release must succeed")
	}
}

func TestListenerRejectsOverLimit(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })

	var rejected int
	rejectCh := make(chan struct{}, 8)
	ln := WrapListener(raw, New(1), func(conn net.Conn) {
		rejected++
		_ = conn.Close()
		rejectCh <- struct{}{}
	})

	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()

	c1, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c1.Close() }()
	var s1 net.Conn
	select {
	case s1 = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("first connection was not accepted")
	}

	// 第二、第三个连接超限：被拒绝且回调触发。
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", raw.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
		select {
		case <-rejectCh:
		case <-time.After(2 * time.Second):
			t.Fatalf("over-limit connection %d was not rejected", i+1)
		}
	}
	if rejected != 2 {
		t.Fatalf("rejected = %d, want 2", rejected)
	}

	// 释放名额后，新连接再次被接受（超限不是永久熔断）。
	_ = s1.Close()
	c4, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c4.Close() }()
	select {
	case s4 := <-accepted:
		_ = s4.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("connection after release was not accepted")
	}
}

// stubConn 是满足 net.Conn 的空连接，供包装测试使用。
type stubConn struct{}

func (stubConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (stubConn) Write(b []byte) (int, error)      { return len(b), nil }
func (stubConn) Close() error                     { return nil }
func (stubConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (stubConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (stubConn) SetDeadline(time.Time) error      { return nil }
func (stubConn) SetReadDeadline(time.Time) error  { return nil }
func (stubConn) SetWriteDeadline(time.Time) error { return nil }

// halfCloseConn 是支持半关闭的测试连接，并记录调用次数。
type halfCloseConn struct {
	stubConn
	closeWrites int
	closeReads  int
}

func (c *halfCloseConn) CloseWrite() error { c.closeWrites++; return nil }
func (c *halfCloseConn) CloseRead() error  { c.closeReads++; return nil }

// TestLimitedConnPreservesHalfClose 验证包装连接仍透传半关闭能力：
// relay 层依赖 CloseWrite 把 EOF 传播为对侧 FIN（见 relay.halfClose），
// 包装丢失该能力会让对端等不到 EOF 而挂到空闲超时。
func TestLimitedConnPreservesHalfClose(t *testing.T) {
	base := &halfCloseConn{}
	limiter := New(1)
	if !limiter.TryAcquire() {
		t.Fatal("acquire")
	}
	wrapped := &limitedConn{Conn: base, limiter: limiter}

	// 包装后必须仍可被 relay 断言为 closeWriter。
	cw, ok := any(wrapped).(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("limitedConn 必须支持 CloseWrite，否则半关闭会被静默吞掉")
	}
	if err := cw.CloseWrite(); err != nil || base.closeWrites != 1 {
		t.Fatalf("CloseWrite 透传: err=%v calls=%d, want nil/1", err, base.closeWrites)
	}
	if err := wrapped.CloseRead(); err != nil || base.closeReads != 1 {
		t.Fatalf("CloseRead 透传: err=%v calls=%d, want nil/1", err, base.closeReads)
	}

	// Close 仍归还名额。
	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if limiter.Active() != 0 {
		t.Fatalf("active=%d after Close, want 0", limiter.Active())
	}

	// 底层不支持半关闭时安全 no-op，不 panic。
	plain := &limitedConn{Conn: stubConn{}, limiter: New(1)}
	if err := plain.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite on plain underlying: %v", err)
	}
	if err := plain.CloseRead(); err != nil {
		t.Fatalf("CloseRead on plain underlying: %v", err)
	}
}
