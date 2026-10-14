// Package throttle 提供认证失败按来源 IP 的指数退避（纯 stdlib，L0）。
//
// 语义参考 nodes.Pool 的被动冷却：第 n 次连续失败的延迟 = base * 2^(n-1)，
// 封顶 max；认证成功（Success）即清除该 IP 的记录从头计。记录按容量上限
// FIFO 淘汰，防止攻击者用大量伪造来源 IP 撑爆内存。
package throttle

import (
	"sync"
	"time"
)

// 缺省退避参数（开箱即用）：首次失败 100ms 级延迟不打断正常使用，
// 连续失败快速升级到 2s 封顶。
const (
	DefaultBase     = 100 * time.Millisecond
	DefaultMax      = 2 * time.Second
	DefaultCapacity = 4096
)

// IPThrottle 是并发安全的按 IP 退避器。零值不可用，请使用 NewIPThrottle
// 或 NewDefaultIPThrottle 构造。
type IPThrottle struct {
	mu       sync.Mutex
	base     time.Duration
	max      time.Duration
	capacity int
	fails    map[string]int
	queue    []string // 插入序 FIFO（与 fails 同生命周期：淘汰即删除，防内存膨胀）
}

// NewIPThrottle 构造退避器。base/max/capacity 非法时归一：base < 0 按 0
// 处理（延迟恒为 0）；max < base 按 base 处理；capacity <= 0 取缺省 4096。
func NewIPThrottle(base, max time.Duration, capacity int) *IPThrottle {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	if base < 0 {
		base = 0
	}
	if max < base {
		max = base
	}
	return &IPThrottle{
		base:     base,
		max:      max,
		capacity: capacity,
		fails:    make(map[string]int, capacity),
		queue:    make([]string, 0, capacity),
	}
}

// NewDefaultIPThrottle 用缺省参数构造：base=100ms、max=2s、capacity=4096。
func NewDefaultIPThrottle() *IPThrottle {
	return NewIPThrottle(DefaultBase, DefaultMax, DefaultCapacity)
}

// Delay 记录 ip 一次认证失败并返回本次应延迟时长：第 n 次连续失败 =
// base * 2^(n-1)，封顶 max。调用方在 d > 0 时自行有界睡眠后再走既有拒绝
// 响应（响应语义保持不变）。
func (t *IPThrottle) Delay(ip string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.fails[ip]; !ok {
		// 容量满：淘汰最旧的 IP 记录（FIFO），内存使用有界。
		if len(t.queue) >= t.capacity {
			delete(t.fails, t.queue[0])
			t.queue = t.queue[1:]
		}
		t.queue = append(t.queue, ip)
	}
	t.fails[ip]++
	return t.delayFor(t.fails[ip])
}

// Success 清除 ip 的失败记录（认证成功后调用）；无记录时为空操作。
func (t *IPThrottle) Success(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.fails, ip)
}

// delayFor 返回第 n 次连续失败的延迟（倍增封顶；溢出安全：达到 max 即返回）。
func (t *IPThrottle) delayFor(n int) time.Duration {
	d := t.base
	for i := 1; i < n; i++ {
		d *= 2
		if d >= t.max {
			return t.max
		}
	}
	return d
}
