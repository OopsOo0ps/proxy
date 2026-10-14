package status

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// newTestServer 组装一个最小可用 Server（无注入处理器，端点走默认 404/200 路径）。
func newTestServer(t *testing.T) *Server {
	t.Helper()
	return NewServer(ServerOptions{Version: "test"})
}

// TestServeAfterCloseDoesNotPanic 确定性复现原缺陷：
// 热加载 switchTo 链路是 cancel → Close 零间隔执行，Serve 入口与 ctx 关停协程
// 会与 Close 的字段置 nil 并发——修复前对 *http.Server / net.Listener 的无同步
// 读取为进程级 panic（或 -race 数据竞争致命报告）。要求：Serve 在数秒内返回
// 且无 panic、无 hang。
func TestServeAfterCloseDoesNotPanic(t *testing.T) {
	s := newTestServer(t)
	if err := s.Bind("127.0.0.1:0"); err != nil {
		t.Fatalf("bind: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 先 cancel：ctx.Done 已关闭，Serve 启动后关停协程立即执行 Shutdown。
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Serve(ctx)
	}()
	// 模拟 switchTo 的零间隔链：cancel 后立刻 Close，与 Serve 入口及关停协程
	// 对 s.srv / s.ln 的读取并发。
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case err := <-errCh:
		// 外部 Close 与 ctx 取消零间隔时存在竞争：若本 Serve 自身的
		// Shutdown 尚未把 http.Server 置为 inShutdown，accept 报错会以
		// net.ErrClosed 包装原样返回（status.Serve 仅把 ErrServerClosed
		// 归一为 nil）；是否命中取决于微秒级调度，两者皆可接受。
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("serve = %v, want nil 或 net.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve 未在 5s 内返回（疑似 hang）")
	}
}

// TestCloseIdempotentAndAddrAfterClose 验证 Close 幂等与 Addr 归零语义。
func TestCloseIdempotentAndAddrAfterClose(t *testing.T) {
	s := newTestServer(t)
	if err := s.Bind("127.0.0.1:0"); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if addr := s.Addr(); addr == "" {
		t.Fatal("绑定后 Addr() 为空, want 非空")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("first close = %v, want nil", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second close = %v, want nil（幂等）", err)
	}
	if addr := s.Addr(); addr != "" {
		t.Fatalf("close 后 Addr() = %q, want 空串", addr)
	}
	if err := s.Serve(context.Background()); err != nil {
		t.Fatalf("close 后 serve = %v, want nil", err)
	}
}

// TestConcurrentCloseServeAddr 并发压 Close/Serve/Addr/真实 HTTP 请求，
// 必须在 -race 下通过：无数据竞争、无 panic、无 hang。
func TestConcurrentCloseServeAddr(t *testing.T) {
	s := newTestServer(t)
	if err := s.Bind("127.0.0.1:0"); err != nil {
		t.Fatalf("bind: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deadline := time.Now().Add(200 * time.Millisecond)
	var wg sync.WaitGroup
	wg.Add(4)
	go func() {
		defer wg.Done()
		_ = s.Serve(ctx)
	}()
	go func() {
		defer wg.Done()
		for time.Now().Before(deadline) {
			_ = s.Close()
			time.Sleep(time.Millisecond)
		}
	}()
	go func() {
		defer wg.Done()
		for time.Now().Before(deadline) {
			_ = s.Addr()
		}
	}()
	go func() {
		defer wg.Done()
		for time.Now().Before(deadline) {
			addr := s.Addr()
			if addr == "" {
				continue
			}
			resp, err := http.Get("http://" + addr + "/health") //nolint:noctx // 并发压测探测，错误忽略
			if err == nil {
				_ = resp.Body.Close()
			}
		}
	}()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("并发用例未在 5s 内结束（疑似 hang/deadlock）")
	}
}

// TestRebindAfterCloseServesNewListener 覆盖 restore 回滚对同一 Server 实例
// 重新 Bind 的等价路径：Close 后重绑同地址，新监听真实在服务。
func TestRebindAfterCloseServesNewListener(t *testing.T) {
	s := newTestServer(t)
	if err := s.Bind("127.0.0.1:0"); err != nil {
		t.Fatalf("bind: %v", err)
	}
	addr1 := s.Addr()

	ctx1, cancel1 := context.WithCancel(context.Background())
	errCh1 := make(chan error, 1)
	go func() {
		errCh1 <- s.Serve(ctx1)
	}()
	cancel1()
	// 不等待 Serve 返回，立刻 Close（复刻 switchTo 零间隔链）。
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// 重绑同地址（restore 回滚路径）。
	if err := s.Bind(addr1); err != nil {
		t.Fatalf("rebind %s: %v", addr1, err)
	}
	addr2 := s.Addr()

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	errCh2 := make(chan error, 1)
	go func() {
		errCh2 <- s.Serve(ctx2)
	}()

	// (i) 新监听真实在服务：/health 返回 200。
	resp, err := http.Get("http://" + addr2 + "/health")
	if err != nil {
		t.Fatalf("GET /health via %s: %v", addr2, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /health via %s: status = %d, want 200", addr2, resp.StatusCode)
	}

	cancel2()
	// (ii) 两个 Serve 都返回：errCh1 允许 nil 或 net.ErrClosed（见下），errCh2 严格 nil。
	select {
	case err := <-errCh1:
		// cancel1 后立即 Close（零间隔链）：关停协程的 Shutdown 与
		// accept 报错存在竞争——Serve 可能返回 nil 或 net.ErrClosed
		// 包装错误，取决于 µs 级调度，两者皆可接受。
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("serve1 = %v, want nil 或 net.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve1 未在 5s 内返回（疑似 hang）")
	}
	select {
	case err := <-errCh2:
		if err != nil {
			t.Fatalf("serve2 = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve2 未在 5s 内返回（疑似 hang）")
	}
	// (iii) 地址解析稳定：重绑同地址得到相同监听地址。
	if addr1 != addr2 {
		t.Fatalf("addr1 = %q, addr2 = %q, want 相同", addr1, addr2)
	}
}
