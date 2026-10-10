// Package shutdown 提供优雅关停的排空原语。
//
// 关停流程统一为两阶段：先停止接受新连接，让存量请求在期限内自然结束；
// 超过期限后调用 force 中断阻塞中的连接，并等待协程全部退出后返回。
package shutdown

import (
	"sync"
	"time"
)

// DefaultTimeout 是关停排空的默认超时（可被配置覆盖）。
const DefaultTimeout = 15 * time.Second

// Wait 等待 wg 归零，返回是否在 timeout 内自然排空。
//
// 超时后调用 force 强制中断仍阻塞的连接，并继续等待 wg 归零后返回 false。
// force 必须能解除所有阻塞（例如取消 ctx 让转发循环关闭连接），
// 否则 Wait 会在强制阶段之后仍然等待。
func Wait(wg *sync.WaitGroup, timeout time.Duration, force func()) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		force()
		<-done
		return false
	}
}
