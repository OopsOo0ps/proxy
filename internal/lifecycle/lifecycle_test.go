package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// —— stdlib 假体：fakeRT + 记录型 Port ——

// fakeRT 是最小运行时快照（可比较，Clone 语义可直接断言）。
type fakeRT struct{ name string }

// event 记录一次钩子调用：rt / other 是钩子的两个 *RT 参数（ nil = 未传）。
type event struct {
	op    string
	rt    *fakeRT
	other *fakeRT
}

type recorder struct {
	mu     sync.Mutex
	events []event
}

func (r *recorder) record(op string, rt, other *fakeRT) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event{op: op, rt: rt, other: other})
}

func (r *recorder) snapshot() []event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]event(nil), r.events...)
}

func (r *recorder) ops() []string {
	evs := r.snapshot()
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.op)
	}
	return out
}

func (r *recorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = nil
}

// harness 是生命周期核心的测试台：bindErrs 是 Bind 的 FIFO 失败注入队列
// （按调用顺序消费，耗尽后恒成功）；inboundErr 只让首个代际的入站 Serve
// 立即失败（复现「致命服务错误 → fail」路径）。
type harness struct {
	rec recorder

	bindErrsMu sync.Mutex
	bindErrs   []error

	inboundErr  error
	inboundFail sync.Once
	assembleErr error
	loadErr     error
}

func newHarness(bindErrs []error) *harness { return &harness{bindErrs: bindErrs} }

func (h *harness) nextBindErr() error {
	h.bindErrsMu.Lock()
	defer h.bindErrsMu.Unlock()
	if len(h.bindErrs) == 0 {
		return nil
	}
	err := h.bindErrs[0]
	h.bindErrs = h.bindErrs[1:]
	return err
}

// options 组装被测 Options：钩子只做记录与最小行为模拟，错误文本经 Name
// 前缀由核心拼装（与 clientapp / serverapp 的既有文案同构）。
func (h *harness) options() Options[fakeRT, string] {
	return Options[fakeRT, string]{
		Name: "testapp",
		Assemble: func(cfg string, reuse *fakeRT) (*fakeRT, error) {
			if h.assembleErr != nil {
				h.rec.record("Assemble:"+cfg, nil, nil)
				return nil, h.assembleErr
			}
			rt := &fakeRT{name: cfg}
			h.rec.record("Assemble:"+cfg, rt, reuse)
			return rt, nil
		},
		Load: func(path, levelOverride string) (string, error) {
			if h.loadErr != nil {
				h.rec.record("Load:"+path+":"+levelOverride, nil, nil)
				return "", h.loadErr
			}
			cfg := path
			if levelOverride != "" {
				cfg = path + "@" + levelOverride
			}
			h.rec.record("Load:"+path+":"+levelOverride, nil, nil)
			return cfg, nil
		},
		Port: Port[fakeRT]{
			Clone: func(rt *fakeRT) *fakeRT {
				h.rec.record("Clone", rt, nil)
				c := *rt
				return &c
			},
			Services: func(rt *fakeRT) Services {
				h.rec.record("Services", rt, nil)
				return Services{
					Inbounds: []Service{{
						Kind: "http",
						Serve: func(ctx context.Context) error {
							h.rec.record("Serve:http", rt, nil)
							var err error
							h.inboundFail.Do(func() { err = h.inboundErr })
							if err != nil {
								return err
							}
							<-ctx.Done()
							return nil
						},
					}},
					Admin: Service{Serve: func(ctx context.Context) error {
						h.rec.record("Serve:admin", rt, nil)
						<-ctx.Done()
						return nil
					}},
				}
			},
			Bind: func(rt, previous *fakeRT) error {
				h.rec.record("Bind", rt, previous)
				return h.nextBindErr()
			},
			CloseListeners:  func(rt *fakeRT) { h.rec.record("CloseListeners", rt, nil) },
			CloseOwned:      func(cur, next *fakeRT) { h.rec.record("CloseOwned", cur, next) },
			ReleaseReplaced: func(cur, next *fakeRT) { h.rec.record("ReleaseReplaced", cur, next) },
			StartResources:  func(rt *fakeRT, _ context.Context) { h.rec.record("StartResources", rt, nil) },
			CloseResources:  func(rt *fakeRT) { h.rec.record("CloseResources", rt, nil) },
		},
		OnReloaded: func(cfg string) { h.rec.record("OnReloaded:"+cfg, nil, nil) },
		OnReloadResult: func(success bool) {
			h.rec.record(fmt.Sprintf("OnReloadResult:%v", success), nil, nil)
		},
		OnRollbackFailed: func(error) { h.rec.record("OnRollbackFailed", nil, nil) },
	}
}

// —— 断言与等待辅助 ——

func assertOps(t *testing.T, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("钩子序列不符：\n got: %v\nwant: %v", got, want)
	}
}

// opsThrough 返回到首个 op（含）为止的确定性序列：过滤掉服务协程的
// Serve 记录（spawn 后异步落账，可能插在任意钩子之间），并把窗口截断在
// op（Reload 的终点钩子）处。
func opsThrough(t *testing.T, ops []string, op string) []string {
	t.Helper()
	end := slices.Index(ops, op)
	if end < 0 {
		t.Fatalf("钩子序列缺少 %s：%v", op, ops)
	}
	ops = ops[:end+1]
	out := make([]string, 0, len(ops))
	for _, o := range ops {
		if strings.HasPrefix(o, "Serve:") {
			continue
		}
		out = append(out, o)
	}
	return out
}

// firstEvent 返回快照中首个 op 匹配的事件：服务协程的 Serve 记录异步落账，
// 可能插在任意钩子之间，因此对钩子事件的参数断言必须按 op 名首次匹配，
// 不能对原始快照用固定下标。
func firstEvent(t *testing.T, events []event, op string) event {
	t.Helper()
	for _, e := range events {
		if e.op == op {
			return e
		}
	}
	t.Fatalf("事件快照缺少 %s：%v", op, events)
	return event{}
}

func startServing(t *testing.T, app *App[fakeRT, string]) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- app.Serve(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for !app.Serving() {
		if time.Now().After(deadline) {
			t.Fatal("app did not start serving")
		}
		time.Sleep(time.Millisecond)
	}
	return cancel, served
}

func waitServesStarted(t *testing.T, r *recorder) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		ops := r.ops()
		if slices.Contains(ops, "Serve:http") && slices.Contains(ops, "Serve:admin") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("services did not start: %v", ops)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitServeReturn(t *testing.T, served <-chan error) error {
	t.Helper()
	select {
	case err := <-served:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return")
		return nil
	}
}

// —— 用例 ——

// TestReloadSwitchSequence 验证 switchTo 成功序列与关停路径：停旧（关旧
// 监听）→ 绑新 → 上线新代际（先 StartResources 后 Services）→ 释放被替换
// → 运行期热更回调 → 恰一次成功记账；应用级关停对当前 live 调
// CloseResources，Serve 返回首个错误（无错则 nil）。
func TestReloadSwitchSequence(t *testing.T) {
	h := newHarness(nil)
	live := &atomic.Pointer[fakeRT]{}
	app, rt1, err := New(h.options(), "v1", live)
	if err != nil {
		t.Fatal(err)
	}
	if live.Load() != rt1 {
		t.Fatal("New must store the assembled runtime into the caller's live pointer")
	}

	cancel, served := startServing(t, app)
	defer cancel()
	waitServesStarted(t, &h.rec)
	h.rec.reset()

	if err := app.Reload("v2"); err != nil {
		t.Fatalf("reload: %v", err)
	}

	ops := h.rec.ops()
	assertOps(t, opsThrough(t, ops, "OnReloadResult:true"), []string{
		"Assemble:v2",
		"CloseListeners",  // 停旧：关旧监听
		"Bind",            // 绑新（previous = 旧运行时）
		"StartResources",  // 新代际：先后台资源
		"Services",        // 再读取服务端点
		"ReleaseReplaced", // 最后释放被替换资源
		"OnReloaded:v2",
		"OnReloadResult:true",
	})

	evs := h.rec.snapshot()
	rt2 := live.Load()
	if rt2 == rt1 || rt2.name != "v2" {
		t.Fatalf("live not switched: %v", rt2)
	}
	if e := firstEvent(t, evs, "Bind"); e.rt != rt2 || e.other != rt1 {
		t.Fatalf("bind must target the new runtime with the old one as hint: %+v", e)
	}
	if e := firstEvent(t, evs, "ReleaseReplaced"); e.rt != rt1 || e.other != rt2 {
		t.Fatalf("release must run on the old runtime: %+v", e)
	}

	cancel()
	if err := waitServeReturn(t, served); err != nil {
		t.Fatalf("serve: %v", err)
	}
	closed := false
	for _, e := range h.rec.snapshot() {
		if e.op == "CloseResources" {
			closed = true
			if e.rt != rt2 {
				t.Fatalf("close resources on %v, want the current runtime", e.rt)
			}
		}
	}
	if !closed {
		t.Fatal("shutdown must close background resources of the current runtime")
	}
}

// TestSwitchBindFailureRollsBack 验证切换阶段绑定失败的回滚序列与语义：
// 关新监听 → CloseOwned（只关新运行时新建资源）→ restore 重绑旧监听 →
// Clone 浅拷贝上线恢复代际；live 持有克隆而非原指针；旧配置继续服务。
func TestSwitchBindFailureRollsBack(t *testing.T) {
	h := newHarness([]error{nil, errors.New("boom"), nil})
	live := &atomic.Pointer[fakeRT]{}
	app, rt1, err := New(h.options(), "v1", live)
	if err != nil {
		t.Fatal(err)
	}
	cancel, served := startServing(t, app)
	defer cancel()
	waitServesStarted(t, &h.rec)
	h.rec.reset()

	err = app.Reload("v2")
	if err == nil || err.Error() != "testapp: bind new configuration: boom" {
		t.Fatalf("reload error = %v, want bind failure", err)
	}

	ops := h.rec.ops()
	assertOps(t, opsThrough(t, ops, "OnReloadResult:false"), []string{
		"Assemble:v2",
		"CloseListeners", // 停旧
		"Bind",           // 绑新失败
		"CloseListeners", // 关新监听
		"CloseOwned",     // 关新运行时新建资源
		"Bind",           // restore：重绑旧监听
		"Clone",          // restore：浅拷贝上线
		"StartResources", // 恢复代际上线
		"Services",
		"OnReloadResult:false",
	})

	evs := h.rec.snapshot()
	var restored *fakeRT
	for _, e := range evs {
		switch e.op {
		case "CloseOwned": // (cur=旧, next=新)：只清新运行时新建资源
			if e.rt != rt1 || e.other == nil || e.other.name != "v2" {
				t.Fatalf("rollback cleanup must close the new runtime's owned resources: %+v", e)
			}
		case "StartResources":
			restored = e.rt
		}
	}
	if restored == nil {
		t.Fatal("restored generation did not start")
	}
	// restore 走 Clone：恢复对象 != 原 cur 指针，但值相等；live 持克隆。
	if restored == rt1 {
		t.Fatal("restore must not re-serve the original runtime pointer")
	}
	if *restored != *rt1 {
		t.Fatalf("restore clone must be value-equal: %+v vs %+v", *restored, *rt1)
	}
	if live.Load() != restored {
		t.Fatal("live must hold the restored clone")
	}

	// 回滚成功：旧配置继续服务，Serve 不退出。
	select {
	case err := <-served:
		t.Fatalf("serve exited on a rolled-back reload: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	if err := waitServeReturn(t, served); err != nil {
		t.Fatalf("serve after rollback: %v", err)
	}
}

// TestRollbackFailureFailsClosed 验证回滚也失败的 fail-closed 路径：
// OnRollbackFailed 被调用、首个致命错误触发应用级关停、Serve 返回组合错误。
func TestRollbackFailureFailsClosed(t *testing.T) {
	h := newHarness([]error{nil, errors.New("boom"), errors.New("bang")})
	live := &atomic.Pointer[fakeRT]{}
	app, _, err := New(h.options(), "v1", live)
	if err != nil {
		t.Fatal(err)
	}
	cancel, served := startServing(t, app)
	defer cancel()
	waitServesStarted(t, &h.rec)
	h.rec.reset()

	err = app.Reload("v2")
	if err == nil || err.Error() != "testapp: bind new configuration: boom; rollback failed: bang" {
		t.Fatalf("reload error = %v, want combined rollback failure", err)
	}
	if !slices.Contains(h.rec.ops(), "OnRollbackFailed") {
		t.Fatalf("rollback failure hook not called: %v", h.rec.ops())
	}
	cancel()
	if serr := waitServeReturn(t, served); serr == nil || !strings.Contains(serr.Error(), "testapp: reload rollback failed: bang") {
		t.Fatalf("serve error should surface the rollback failure: %v", serr)
	}
}

// TestServeReturnsFirstError 验证 fail 路径：入站致命错误成为 Serve 的
// 返回值（首个错误触发应用级关停）。
func TestServeReturnsFirstError(t *testing.T) {
	h := newHarness(nil)
	h.inboundErr = errors.New("boom")
	live := &atomic.Pointer[fakeRT]{}
	app, _, err := New(h.options(), "v1", live)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- app.Serve(ctx) }()

	select {
	case err := <-served:
		if err == nil || err.Error() != "testapp: inbound http: boom" {
			t.Fatalf("serve error = %v, want first fatal error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return on fatal inbound error")
	}
}

// TestReloadRejectedWhileShuttingDown 验证关停期拒绝重载：拒绝文案带
// Name 前缀、不进入组装、且恰好记账一次失败。
func TestReloadRejectedWhileShuttingDown(t *testing.T) {
	h := newHarness(nil)
	live := &atomic.Pointer[fakeRT]{}
	app, _, err := New(h.options(), "v1", live)
	if err != nil {
		t.Fatal(err)
	}
	cancel, served := startServing(t, app)
	waitServesStarted(t, &h.rec)
	cancel()
	if err := waitServeReturn(t, served); err != nil {
		t.Fatalf("serve: %v", err)
	}
	h.rec.reset()

	err = app.Reload("v2")
	if err == nil || err.Error() != "testapp: shutting down; reload ignored" {
		t.Fatalf("reload during shutdown = %v, want rejection", err)
	}
	assertOps(t, h.rec.ops(), []string{"OnReloadResult:false"})
}

// TestReloadFileAccountsExactlyOnce 验证 ReloadFile 记账恰一次：Load 失败
// / 组装失败 / 成功三种路径各计一次；levelOverride 非空时优先于文件值。
func TestReloadFileAccountsExactlyOnce(t *testing.T) {
	t.Run("load-failure", func(t *testing.T) {
		h := newHarness(nil)
		live := &atomic.Pointer[fakeRT]{}
		app, _, err := New(h.options(), "v1", live)
		if err != nil {
			t.Fatal(err)
		}
		h.loadErr = errors.New("bad yaml")
		h.rec.reset()
		if err := app.ReloadFile("v2", ""); !errors.Is(err, h.loadErr) {
			t.Fatalf("reload file error = %v, want load error", err)
		}
		assertOps(t, h.rec.ops(), []string{"Load:v2:", "OnReloadResult:false"})
		if rt := live.Load(); rt.name != "v1" {
			t.Fatalf("failed load must keep the old runtime: %v", rt)
		}
	})

	t.Run("assemble-failure", func(t *testing.T) {
		h := newHarness(nil)
		live := &atomic.Pointer[fakeRT]{}
		app, _, err := New(h.options(), "v1", live)
		if err != nil {
			t.Fatal(err)
		}
		h.assembleErr = errors.New("bad node")
		h.rec.reset()
		err = app.ReloadFile("v2", "")
		if err == nil || !strings.Contains(err.Error(), "testapp: build new configuration") {
			t.Fatalf("reload file error = %v, want build failure", err)
		}
		assertOps(t, h.rec.ops(), []string{"Load:v2:", "Assemble:v2", "OnReloadResult:false"})
	})

	t.Run("success", func(t *testing.T) {
		h := newHarness(nil)
		live := &atomic.Pointer[fakeRT]{}
		app, _, err := New(h.options(), "v1", live)
		if err != nil {
			t.Fatal(err)
		}
		h.rec.reset()
		if err := app.ReloadFile("v2", "debug"); err != nil {
			t.Fatalf("reload file: %v", err)
		}
		assertOps(t, h.rec.ops(), []string{
			"Load:v2:debug",
			"Assemble:v2@debug", // levelOverride 优先于文件值
			"CloseListeners",
			"Bind",
			"ReleaseReplaced",
			"OnReloaded:v2@debug",
			"OnReloadResult:true",
		})
		if rt := live.Load(); rt.name != "v2@debug" {
			t.Fatalf("live after reload = %v, want v2@debug", rt)
		}
	})
}

// TestNewAndBuildFailureCleanupArgs 验证构建 / 绑定失败的清理传参：关闭的
// 是新组装的运行时（CloseOwned(nil, rt)），live 不被污染。
func TestNewAndBuildFailureCleanupArgs(t *testing.T) {
	for name, build := range map[string]func(h *harness, live *atomic.Pointer[fakeRT]) error{
		"New": func(h *harness, live *atomic.Pointer[fakeRT]) error {
			_, _, err := New(h.options(), "v1", live)
			return err
		},
		"Build": func(h *harness, live *atomic.Pointer[fakeRT]) error {
			_, err := Build(h.options(), "v1", live)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness([]error{errors.New("port busy")})
			live := &atomic.Pointer[fakeRT]{}
			err := build(h, live)
			if err == nil || err.Error() != "port busy" {
				t.Fatalf("build error = %v, want bind failure", err)
			}
			evs := h.rec.snapshot()
			assertOps(t, h.rec.ops(), []string{"Assemble:v1", "Bind", "CloseOwned"})
			var assembled *fakeRT
			for _, e := range evs {
				if e.op == "Assemble:v1" {
					assembled = e.rt
				}
			}
			if assembled == nil {
				t.Fatal("assembled runtime not recorded")
			}
			cleanup := evs[len(evs)-1]
			if cleanup.rt != nil || cleanup.other != assembled {
				t.Fatalf("cleanup must close the assembled runtime with no previous: %+v", cleanup)
			}
			if live.Load() != nil {
				t.Fatal("failed build must not publish a runtime")
			}
		})
	}
}

// TestNewValidatesRequiredHooks 验证漏配防护：必填钩子缺失在构造期报错。
func TestNewValidatesRequiredHooks(t *testing.T) {
	live := &atomic.Pointer[fakeRT]{}
	if _, _, err := New(Options[fakeRT, string]{}, "v1", live); err == nil {
		t.Fatal("New with empty options must fail")
	}
	if _, err := Build(Options[fakeRT, string]{}, "v1", live); err == nil {
		t.Fatal("Build with empty options must fail")
	}
}
