package throttle

import (
	"sync"
	"testing"
	"time"
)

// TestDelayExponentialGrowthAndCap 验证指数增长与封顶：第 n 次失败 =
// base * 2^(n-1)，封顶 max。
func TestDelayExponentialGrowthAndCap(t *testing.T) {
	th := NewIPThrottle(10*time.Millisecond, 80*time.Millisecond, 64)
	want := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		40 * time.Millisecond,
		80 * time.Millisecond,
		80 * time.Millisecond,
		80 * time.Millisecond,
	}
	for i, w := range want {
		if got := th.Delay("1.2.3.4"); got != w {
			t.Fatalf("call %d: delay = %v, want %v", i+1, got, w)
		}
	}
	// 不同 IP 互不影响。
	if got := th.Delay("5.6.7.8"); got != want[0] {
		t.Fatalf("other ip first delay = %v, want %v", got, want[0])
	}
}

// TestSuccessClearsRecord 验证认证成功清除记录：延迟从头计。
func TestSuccessClearsRecord(t *testing.T) {
	th := NewIPThrottle(10*time.Millisecond, time.Second, 64)
	_ = th.Delay("1.2.3.4")
	_ = th.Delay("1.2.3.4")
	th.Success("1.2.3.4")
	if got := th.Delay("1.2.3.4"); got != 10*time.Millisecond {
		t.Fatalf("delay after success = %v, want base", got)
	}
	// 无记录时 Success 为空操作（不 panic、不影响后续）。
	th.Success("no-such-ip")
	if got := th.Delay("no-such-ip"); got != 10*time.Millisecond {
		t.Fatalf("delay for unknown ip = %v, want base", got)
	}
}

// TestCapacityEviction 验证容量淘汰：超出容量后最旧的 IP 记录被 FIFO
// 淘汰，内存使用有界。
func TestCapacityEviction(t *testing.T) {
	th := NewIPThrottle(10*time.Millisecond, time.Second, 4)
	// 用满容量。
	for _, ip := range []string{"ip1", "ip2", "ip3", "ip4"} {
		_ = th.Delay(ip)
	}
	// 再进一个：ip1 被淘汰，从头计。
	if got := th.Delay("ip5"); got != 10*time.Millisecond {
		t.Fatalf("ip5 first delay = %v, want base", got)
	}
	// ip1 重新失败：记录已被淘汰，延迟从头计。
	if got := th.Delay("ip1"); got != 10*time.Millisecond {
		t.Fatalf("ip1 delay after eviction = %v, want base", got)
	}
	// 仍在容量的 ip3 保留累计：第 2 次 = 20ms（此时 ip2 已被 FIFO 淘汰）。
	if got := th.Delay("ip3"); got != 20*time.Millisecond {
		t.Fatalf("ip3 delay = %v, want 20ms", got)
	}
}

// TestNormalization 验证构造参数归一：非法 base/max/capacity 不产生异常行为。
func TestNormalization(t *testing.T) {
	th := NewIPThrottle(-1, -2, 0)
	if got := th.Delay("1.2.3.4"); got != 0 {
		t.Fatalf("negative base delay = %v, want 0", got)
	}
	th2 := NewIPThrottle(10*time.Millisecond, 5*time.Millisecond, 0) // max < base → 按 base
	if got := th2.Delay("1.2.3.4"); got != 10*time.Millisecond {
		t.Fatalf("delay = %v, want base", got)
	}
	if got := th2.Delay("1.2.3.4"); got != 10*time.Millisecond {
		t.Fatalf("capped delay = %v, want base (max < base)", got)
	}
}

// TestConcurrentAccess 并发调用必须安全（-race 下运行）。
func TestConcurrentAccess(t *testing.T) {
	th := NewDefaultIPThrottle()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ip := "10.0.0.1"
			for j := 0; j < 50; j++ {
				_ = th.Delay(ip)
				th.Success(ip)
			}
		}(i)
	}
	wg.Wait()
}
