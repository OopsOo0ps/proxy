// Package connlimit 提供进程级并发连接上限（背压）与超限拒绝原语。
//
// 设计要点：
//   - Limiter 是计数信号量：TryAcquire 成功即占用一个名额，连接 Close 时释放；
//   - 上限 <= 0 表示不限制（New 返回 nil；所有方法对 nil 接收者安全）；
//   - 超限后的协议层应答由调用方决定（HTTP 503 / SOCKS5 失败回复 / 隧道直接关闭），
//     WrapListener 负责在 Accept 阶段执行拒绝动作，并在拒绝后继续接受后续连接。
package connlimit

import (
	"net"
	"sync"
	"sync/atomic"
)

// Limiter 是并发连接计数上限；nil 表示不限制。
type Limiter struct {
	max      int
	sem      chan struct{}
	active   atomic.Int64
	rejected atomic.Uint64
}

// New 创建上限为 max 的连接限制器；max <= 0 时返回 nil（不限制）。
func New(max int) *Limiter {
	if max <= 0 {
		return nil
	}
	return &Limiter{max: max, sem: make(chan struct{}, max)}
}

// TryAcquire 尝试占用一个连接名额；超限时返回 false 并累计拒绝计数。
func (l *Limiter) TryAcquire() bool {
	if l == nil {
		return true
	}
	select {
	case l.sem <- struct{}{}:
		l.active.Add(1)
		return true
	default:
		l.rejected.Add(1)
		return false
	}
}

// Release 归还一个连接名额。
func (l *Limiter) Release() {
	if l == nil {
		return
	}
	select {
	case <-l.sem:
		l.active.Add(-1)
	default:
	}
}

// Max 返回配置上限；0 表示不限制。
func (l *Limiter) Max() int {
	if l == nil {
		return 0
	}
	return l.max
}

// Active 返回当前占用数。
func (l *Limiter) Active() int {
	if l == nil {
		return 0
	}
	return int(l.active.Load())
}

// Rejected 返回累计拒绝数。
func (l *Limiter) Rejected() uint64 {
	if l == nil {
		return 0
	}
	return l.rejected.Load()
}

// Listener 包装底层监听：Accept 时占用名额；超限连接交给 reject 处理后
// 继续接受下一个；返回的连接在 Close 时自动归还名额。
type Listener struct {
	net.Listener
	limiter *Limiter
	reject  func(net.Conn)
}

// WrapListener 包装监听以应用连接上限。limiter 为 nil（不限制）时返回原监听。
// reject 对每个超限连接调用一次，用于写协议层拒绝响应；为 nil 时直接关闭连接。
func WrapListener(ln net.Listener, limiter *Limiter, reject func(net.Conn)) net.Listener {
	if limiter == nil {
		return ln
	}
	return &Listener{Listener: ln, limiter: limiter, reject: reject}
}

// Accept 返回持有名额的连接；超限连接被拒绝后不会阻塞后续接受。
func (l *Listener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.limiter.TryAcquire() {
			return &limitedConn{Conn: conn, limiter: l.limiter}, nil
		}
		if l.reject != nil {
			l.reject(conn)
		} else {
			_ = conn.Close()
		}
	}
}

// limitedConn 在关闭时归还名额（重复 Close 只归还一次）。
type limitedConn struct {
	net.Conn
	limiter *Limiter
	once    sync.Once
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.limiter.Release)
	return err
}
