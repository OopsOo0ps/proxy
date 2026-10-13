package nodes

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// observerRecorder 记录 Observer 的全部事件（事件序列断言用）：
// 探测结果记 "probe <addr> <success|failure>"，健康状态变化记
// "health <addr> <removed|rejoined>"。
type observerRecorder struct {
	mu     sync.Mutex
	events []string
}

func (r *observerRecorder) ProbeResult(addr string, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	status := ProbeSuccess
	if !ok {
		status = ProbeFailure
	}
	r.events = append(r.events, "probe "+addr+" "+status)
}

func (r *observerRecorder) HealthChanged(addr string, healthy bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := "rejoined"
	if !healthy {
		state = "removed"
	}
	r.events = append(r.events, "health "+addr+" "+state)
}

func (r *observerRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

// TestObserverEventSequenceOnRemoveAndRejoin 钉住摘除/加回的观测事件序列
// （§8.4 测试纪律：组件测试直接断言事件序列，不靠 e2e /metrics 兜底）：
// 连续探测失败记 ProbeResult(failure)，达阈值摘除记 HealthChanged(removed)；
// 摘除后的成功探测继续记 ProbeResult(success)，连续成功达阈值加回记
// HealthChanged(rejoined)。探测结果事件先于状态变化事件。
func TestObserverEventSequenceOnRemoveAndRejoin(t *testing.T) {
	obs := &observerRecorder{}
	pool, err := New(testNodes(), newRecorder().dial, Options{
		Health:   HealthOptions{Interval: time.Minute, Timeout: time.Second, Failures: 2, Successes: 2},
		Probe:    func(context.Context, Node) error { return nil }, // 事件由 recordProbe 手动驱动
		Observer: obs,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	st := findState(t, pool, "node1.example.com:443")
	pool.recordProbe(st, errors.New("probe failed"))
	pool.recordProbe(st, errors.New("probe failed"))
	pool.recordProbe(st, nil)
	pool.recordProbe(st, nil)

	want := []string{
		"probe node1.example.com:443 failure",
		"probe node1.example.com:443 failure",
		"health node1.example.com:443 removed",
		"probe node1.example.com:443 success",
		"probe node1.example.com:443 success",
		"health node1.example.com:443 rejoined",
	}
	if got := obs.snapshot(); len(got) != len(want) {
		t.Fatalf("events = %v, want %v", got, want)
	} else {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("events[%d] = %q, want %q（全部事件 = %v）", i, got[i], want[i], got)
			}
		}
	}
}
