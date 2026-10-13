// Package connlimit 提供进程级并发连接上限（背压）与超限拒绝原语。
//
// 设计要点：
//   - Limiter 是计数信号量：TryAcquire 成功即占用一个名额，连接 Close 时释放；
//   - 上限 <= 0 表示不限制；上限可在运行期通过 SetMax 调整（配置热加载），
//     调整不会中断已有连接，只约束之后新的占用；
//   - 所有方法对 nil 接收者安全（便于测试中省略构造）；
//   - 超限后的协议层应答由调用方决定（HTTP 503 / SOCKS5 失败回复 / 隧道直接关闭），
//     WrapListener 负责在 Accept 阶段执行拒绝动作，并在拒绝后继续接受后续连接；
//   - 闸也可按“一次处理”粒度使用（不必是整条连接）：例如 DNS 网关让 TCP 连接
//     与 UDP 在途查询共用同一份预算（dnsgw），此时拒绝语义（回 REFUSED /
//     静默丢弃）同样由调用方决定。
package connlimit

import (
	"net"
	"sync"
	"sync/atomic"
)

// Limiter 是并发连接计数上限；nil 表示不限制。
type Limiter struct {
	mu       sync.Mutex
	max      int
	active   int
	rejected atomic.Uint64
}

// New 创建上限为 max 的连接限制器；max <= 0 表示不限制。
// 返回的实例总是可用的，便于后续通过 SetMax 动态调整上限。
func New(max int) *Limiter {
	return &Limiter{max: max}
}

// TryAcquire 尝试占用一个连接名额；超限时返回 false 并累计拒绝计数。
func (l *Limiter) TryAcquire() bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.max > 0 && l.active >= l.max {
		l.rejected.Add(1)
		return false
	}
	l.active++
	return true
}

// Release 归还一个连接名额。
func (l *Limiter) Release() {
	if l == nil {
		return
	}
	l.mu.Lock()
	if l.active > 0 {
		l.active--
	}
	l.mu.Unlock()
}

// SetMax 调整运行期连接上限（0 或负值表示不限制）。
// 调低上限不中断已有连接，只约束新的占用：活跃连接数回落到新上限
// 以下之前，新连接会被拒绝；调高或解除上限立即生效。
func (l *Limiter) SetMax(max int) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.max = max
	l.mu.Unlock()
}

// Max 返回配置上限；0 表示不限制。
func (l *Limiter) Max() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.max
}

// Active 返回当前占用数。
func (l *Limiter) Active() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.active
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
//
// 同时透传半关闭能力：relay 层用 CloseWrite 把一侧的 EOF 传播为对侧的 FIN，
// 包装类型若只实现 Close，halfClose 的类型断言会静默失败（no-op），
// 对端将等不到 EOF 而挂到空闲超时。CloseRead 同理。
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

// CloseWrite 透传底层连接的半关闭写方向；底层不支持时是安全的 no-op。
func (c *limitedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// CloseRead 透传底层连接的半关闭读方向；底层不支持时是安全的 no-op。
func (c *limitedConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}
