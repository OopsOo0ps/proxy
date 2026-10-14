package ruleset

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/routing"
)

// 规则文档的解码由组装根注入（生产为 config.ParseRules）；本包测试注入
// 一个极简行式解码器，保持 ruleset 测试零 yaml。格式：每行一条规则
// “<action> <match 条目...>”，“#” 开头为注释。
const (
	rulesV1 = "direct *.example.com\n"
	rulesV2 = "direct *.example.net\n"
)

func testParse(data []byte) (*routing.Rules, error) {
	var rules routing.Rules
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		action, err := routing.ParseAction(fields[0])
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		rules.Rules = append(rules.Rules, routing.Rule{Action: action, Match: fields[1:]})
	}
	return &rules, nil
}

// fakeTransport 按预设状态码与内容回复请求，不触碰网络。
type fakeTransport struct {
	mu     sync.Mutex
	status int
	body   string
	count  int
}

func (f *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.count++
	return &http.Response{
		StatusCode: f.status,
		Status:     fmt.Sprintf("%d fake", f.status),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(f.body)),
		Request:    req,
	}, nil
}

func (f *fakeTransport) set(status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.body = status, body
}

func (f *fakeTransport) requests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.count
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// fakeObserver 记录规则源发出的遥测事件（替代 prometheus registry，测试零构造）。
type fakeObserver struct {
	mu      sync.Mutex
	results []string
	rules   int
}

func (f *fakeObserver) Refresh(result string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results = append(f.results, result)
}

func (f *fakeObserver) SetLastSuccess(time.Time) {}

func (f *fakeObserver) SetRules(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = n
}

// refreshCount 返回某结果的刷新次数；rulesOf 返回最后上报的规则条数。
func (f *fakeObserver) refreshCount(result string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.results {
		if r == result {
			n++
		}
	}
	return n
}

func (f *fakeObserver) rulesOf() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rules
}

func newURLProvider(t *testing.T, tr *fakeTransport, obs Observer, interval time.Duration) *Provider {
	t.Helper()
	p, err := New(Options{
		URL:             "http://rules.test/rules.yaml",
		RefreshInterval: interval,
		Parse:           testParse,
		Default:         core.RouteProxy,
		Logger:          discardLogger(),
		Observer:        obs,
		fetchClient:     &http.Client{Transport: tr},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func waitFor(t *testing.T, timeout time.Duration, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %v: %s", timeout, msg)
}

func TestNewNoneSource(t *testing.T) {
	p, err := New(Options{Default: core.RouteDirect, PrivateDirect: true, Logger: discardLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := p.Decide("anything.example"); got != core.RouteDirect {
		t.Fatalf("decide = %v, want direct (configured default)", got)
	}
	if snap := p.Snapshot(); snap.Source != SourceNone || snap.Loaded {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}
	if err := p.Recheck(context.Background()); err != nil {
		t.Fatalf("recheck without source: %v", err)
	}
}

func TestNewRejectsBothSources(t *testing.T) {
	_, err := New(Options{FilePath: "a.yaml", URL: "http://rules.test/r.yaml", Parse: testParse})
	if err == nil || !strings.Contains(err.Error(), "at most one") {
		t.Fatalf("err = %v, want mutual exclusion error", err)
	}
}

// TestNewRequiresParse 钉住解码注入约束：配置了规则源而未注入解码函数
// 必须在构造期报错（本包零序列化格式知识）。
func TestNewRequiresParse(t *testing.T) {
	if _, err := New(Options{FilePath: "rules.yaml"}); err == nil {
		t.Fatal("expected error for missing parse function")
	}
	if _, err := New(Options{URL: "http://rules.test/r.yaml"}); err == nil {
		t.Fatal("expected error for missing parse function")
	}
}

func TestFileSourceLifecycle(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(rulesV1), 0o600); err != nil {
		t.Fatal(err)
	}
	obs := &fakeObserver{}
	p, err := New(Options{
		FilePath: rulesPath,
		Parse:    testParse,
		Default:  core.RouteProxy,
		Logger:   discardLogger(),
		Observer: obs,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := p.Decide("a.example.com"); got != core.RouteDirect {
		t.Fatalf("decide = %v, want direct", got)
	}
	snap := p.Snapshot()
	if snap.Source != SourceFile || snap.Target != rulesPath || !snap.Loaded || snap.Rules != 1 {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}
	if snap.LastSuccess.IsZero() {
		t.Fatal("LastSuccess should be set after initial load")
	}

	// 内容变化：Recheck 重读并原子切换。
	if err := os.WriteFile(rulesPath, []byte(rulesV2), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.Recheck(context.Background()); err != nil {
		t.Fatalf("recheck: %v", err)
	}
	if got := p.Decide("a.example.net"); got != core.RouteDirect {
		t.Fatalf("new rules not applied: decide = %v", got)
	}
	if got := p.Decide("a.example.com"); got != core.RouteProxy {
		t.Fatalf("old rules leaked: decide = %v", got)
	}

	// 文件缺失：Recheck 返回错误（调用方应拒绝重载），现有规则保持不变。
	if err := os.Remove(rulesPath); err != nil {
		t.Fatal(err)
	}
	if err := p.Recheck(context.Background()); err == nil {
		t.Fatal("recheck with missing file must fail")
	}
	if got := p.Decide("a.example.net"); got != core.RouteDirect {
		t.Fatalf("rules changed after failed recheck: decide = %v", got)
	}
	if got := obs.refreshCount(RefreshError); got != 1 {
		t.Fatalf("refresh error observed %d times, want 1", got)
	}
}

func TestFileSourceInitialFailureIsStrict(t *testing.T) {
	_, err := New(Options{
		FilePath: filepath.Join(t.TempDir(), "missing.yaml"),
		Parse:    testParse,
	})
	if err == nil {
		t.Fatal("missing rules file must fail construction")
	}
}

func TestURLSourceInitialLoadAndSpec(t *testing.T) {
	tr := &fakeTransport{status: 200, body: rulesV1}
	obs := &fakeObserver{}
	p := newURLProvider(t, tr, obs, 30*time.Minute)
	if got := p.Decide("a.example.com"); got != core.RouteDirect {
		t.Fatalf("decide = %v, want direct", got)
	}
	want := Spec{Kind: SourceURL, Target: "http://rules.test/rules.yaml", Interval: 30 * time.Minute}
	if got := p.Spec(); got != want {
		t.Fatalf("spec = %+v, want %+v", got, want)
	}
	if got := obs.refreshCount(RefreshSuccess); got != 1 {
		t.Fatalf("refresh success observed %d times, want 1", got)
	}
	if got := obs.rulesOf(); got != 1 {
		t.Fatalf("observed rules = %d, want 1", got)
	}
}

func TestURLSourceInitialFailureWarnsAndRecovers(t *testing.T) {
	tr := &fakeTransport{status: 500, body: "boom"}
	obs := &fakeObserver{}
	p := newURLProvider(t, tr, obs, 10*time.Millisecond)

	// 启动拉取失败：不返回错误，空规则（默认动作）继续，状态记录失败。
	if got := p.Decide("a.example.com"); got != core.RouteProxy {
		t.Fatalf("decide = %v, want default proxy while unloaded", got)
	}
	snap := p.Snapshot()
	if snap.Loaded || snap.LastError == "" {
		t.Fatalf("unexpected snapshot after failed initial load: %+v", snap)
	}
	if got := obs.refreshCount(RefreshError); got != 1 {
		t.Fatalf("initial failure observed %d times, want 1", got)
	}

	// 源恢复后周期刷新自动加载成功。
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)
	defer p.Close()
	tr.set(200, rulesV1)
	waitFor(t, 3*time.Second, "rules become active after recovery", func() bool {
		return p.Decide("a.example.com") == core.RouteDirect
	})
	if snap := p.Snapshot(); !snap.Loaded || snap.LastError != "" || snap.Rules != 1 {
		t.Fatalf("unexpected snapshot after recovery: %+v", snap)
	}
}

func TestURLRefreshSwapsOnlyOnChange(t *testing.T) {
	tr := &fakeTransport{status: 200, body: rulesV1}
	obs := &fakeObserver{}
	p := newURLProvider(t, tr, obs, 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)
	defer p.Close()

	waitFor(t, 3*time.Second, "unchanged refresh counted", func() bool {
		return obs.refreshCount(RefreshUnchanged) >= 1
	})
	if got := p.Decide("a.example.com"); got != core.RouteDirect {
		t.Fatalf("rules changed without content change: decide = %v", got)
	}

	tr.set(200, rulesV2)
	waitFor(t, 3*time.Second, "changed content applied", func() bool {
		return p.Decide("a.example.net") == core.RouteDirect
	})
	if got := p.Decide("a.example.com"); got != core.RouteProxy {
		t.Fatalf("old rules leaked after refresh: decide = %v", got)
	}
}

func TestURLRefreshFailureKeepsRules(t *testing.T) {
	tr := &fakeTransport{status: 200, body: rulesV1}
	obs := &fakeObserver{}
	p := newURLProvider(t, tr, obs, 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)
	defer p.Close()

	// 刷新返回解码失败的内容：保持现有规则，记录错误。
	tr.set(200, "frobnicate example.com")
	waitFor(t, 3*time.Second, "error counted", func() bool {
		return obs.refreshCount(RefreshError) >= 1
	})
	if got := p.Decide("a.example.com"); got != core.RouteDirect {
		t.Fatalf("rules lost after bad refresh: decide = %v", got)
	}
	snap := p.Snapshot()
	if !snap.Loaded || snap.Rules != 1 || snap.LastError == "" {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}

	// 刷新返回 500：同样保持规则。
	tr.set(500, "boom")
	waitFor(t, 3*time.Second, "second error counted", func() bool {
		return obs.refreshCount(RefreshError) >= 2
	})
	if got := p.Decide("a.example.com"); got != core.RouteDirect {
		t.Fatalf("rules lost after http failure: decide = %v", got)
	}
}

func TestRecheckURLIsLenient(t *testing.T) {
	tr := &fakeTransport{status: 200, body: rulesV1}
	p := newURLProvider(t, tr, nil, 30*time.Minute)

	tr.set(500, "boom")
	if err := p.Recheck(context.Background()); err != nil {
		t.Fatalf("recheck with failing URL must be lenient, got %v", err)
	}
	if got := p.Decide("a.example.com"); got != core.RouteDirect {
		t.Fatalf("rules lost after failed recheck: decide = %v", got)
	}

	tr.set(200, rulesV2)
	if err := p.Recheck(context.Background()); err != nil {
		t.Fatalf("recheck: %v", err)
	}
	if got := p.Decide("a.example.net"); got != core.RouteDirect {
		t.Fatalf("recheck did not apply new content: decide = %v", got)
	}
}

func TestUpdateOptionsRecompilesWithoutFetch(t *testing.T) {
	tr := &fakeTransport{status: 200, body: rulesV1}
	p := newURLProvider(t, tr, nil, 30*time.Minute)
	before := tr.requests()

	p.UpdateOptions(core.RouteDirect, false)
	if got := p.Decide("unmatched.example"); got != core.RouteDirect {
		t.Fatalf("decide = %v, want direct after options update", got)
	}
	if got := p.Decide("a.example.com"); got != core.RouteDirect {
		t.Fatalf("rules lost after options update: decide = %v", got)
	}
	if got := tr.requests(); got != before {
		t.Fatalf("options update triggered a fetch: %d -> %d", before, got)
	}
}

func TestOnChangeFiresOnEngineSwap(t *testing.T) {
	tr := &fakeTransport{status: 200, body: rulesV1}
	var changes atomic.Int64
	p, err := New(Options{
		URL:             "http://rules.test/rules.yaml",
		RefreshInterval: 10 * time.Millisecond,
		Parse:           testParse,
		Default:         core.RouteProxy,
		Logger:          discardLogger(),
		OnChange:        func() { changes.Add(1) },
		fetchClient:     &http.Client{Transport: tr},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := changes.Load(); got != 1 {
		t.Fatalf("changes after initial load = %d, want 1", got)
	}

	// 未变化的周期刷新不触发回调。
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)
	defer p.Close()
	waitFor(t, 3*time.Second, "unchanged refresh ran", func() bool { return tr.requests() >= 2 })
	if got := changes.Load(); got != 1 {
		t.Fatalf("changes after unchanged refresh = %d, want 1", got)
	}

	// 内容变化触发一次。
	tr.set(200, rulesV2)
	waitFor(t, 3*time.Second, "changed content applied", func() bool {
		return p.Decide("a.example.net") == core.RouteDirect && changes.Load() == 2
	})
	if got := changes.Load(); got != 2 {
		t.Fatalf("changes after content change = %d, want 2", got)
	}

	// 引擎参数变化触发一次。
	p.UpdateOptions(core.RouteDirect, true)
	if got := changes.Load(); got != 3 {
		t.Fatalf("changes after options update = %d, want 3", got)
	}
}

func TestFetchRulesConstraints(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wantSub string
	}{
		{"unsupported scheme", "ftp://rules.test/r.yaml", "scheme"},
		{"missing host", "http:///r.yaml", "missing host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := fetchConfig{client: &http.Client{Transport: &fakeTransport{status: 200}}, maxBytes: 1024}.fetchRules(context.Background(), tc.url)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantSub)
			}
		})
	}

	t.Run("non-2xx status", func(t *testing.T) {
		_, err := fetchConfig{client: &http.Client{Transport: &fakeTransport{status: 404, body: "nope"}}, maxBytes: 1024}.fetchRules(context.Background(), "http://rules.test/r.yaml")
		if err == nil || !strings.Contains(err.Error(), "unexpected status") {
			t.Fatalf("err = %v, want status error", err)
		}
	})

	t.Run("body too large", func(t *testing.T) {
		_, err := fetchConfig{client: &http.Client{Transport: &fakeTransport{status: 200, body: "123456789"}}, maxBytes: 8}.fetchRules(context.Background(), "http://rules.test/r.yaml")
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("err = %v, want size error", err)
		}
	})

	t.Run("body at limit", func(t *testing.T) {
		data, err := fetchConfig{client: &http.Client{Transport: &fakeTransport{status: 200, body: "12345678"}}, maxBytes: 8}.fetchRules(context.Background(), "http://rules.test/r.yaml")
		if err != nil || string(data) != "12345678" {
			t.Fatalf("data=%q err=%v", data, err)
		}
	})
}

func TestSpecOf(t *testing.T) {
	cases := []struct {
		file, url string
		interval  time.Duration
		want      Spec
	}{
		{"", "", 0, Spec{}},
		{"/tmp/rules.yaml", "", 0, Spec{Kind: SourceFile, Target: "/tmp/rules.yaml"}},
		{"", "https://r.test/r.yaml", time.Minute, Spec{Kind: SourceURL, Target: "https://r.test/r.yaml", Interval: time.Minute}},
	}
	for _, tc := range cases {
		if got := SpecOf(tc.file, tc.url, tc.interval); got != tc.want {
			t.Fatalf("SpecOf(%q, %q, %v) = %+v, want %+v", tc.file, tc.url, tc.interval, got, tc.want)
		}
	}
}

func TestStartAndCloseIdempotent(t *testing.T) {
	tr := &fakeTransport{status: 200, body: rulesV1}
	p := newURLProvider(t, tr, nil, 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)
	p.Start(ctx) // 幂等
	p.Close()
	p.Close() // 幂等

	// 未配置来源的 Provider：Start/Close 均为空操作。
	empty, err := New(Options{Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	empty.Start(ctx)
	empty.Close()

	// 刷新周期为 0（仅启动拉取一次）：不启动循环，Close 正常返回。
	once := newURLProvider(t, &fakeTransport{status: 200, body: rulesV1}, nil, 0)
	once.Start(ctx)
	once.Close()
}

// TestRefreshLoopSurvivesGenerationCancel 钉住 B-1 契约：URL 刷新循环绑定
// 首次 Start 传入的应用级 ctx，寿命由 Close 终结——代际 ctx（其子 ctx）取消
// 后 fetch 计数继续增长（热加载复用实例的刷新循环不随 gen.cancel() 停摆）；
// 重复 Start（restore 浅拷贝路径）不重建循环（首次调用生效）；Close 后计数
// 冻结。
func TestRefreshLoopSurvivesGenerationCancel(t *testing.T) {
	tr := &fakeTransport{status: 200, body: rulesV1}
	p := newURLProvider(t, tr, nil, 10*time.Millisecond)
	parent := context.Background()              // 应用级 ctx（startResources 绑定它）
	gctx, gcancel := context.WithCancel(parent) // 代际 ctx

	p.Start(parent)
	waitFor(t, 3*time.Second, "refresh loop started fetching", func() bool { return tr.requests() >= 2 })

	// 代际结束：复用实例的刷新循环仍继续 fetch。
	gcancel()
	baseline := tr.requests()
	waitFor(t, 3*time.Second, "fetch continues after generation cancel", func() bool { return tr.requests() > baseline })

	// 重复 Start（restore 浅拷贝路径）：首次调用生效，不重建第二个循环——
	// 用 done 通道同一性机械固化「不重建」，用计数继续增长固化「原循环仍活」，
	// 两者合起来即 fetch 计数不会翻倍增长。
	doneBefore := p.done
	p.Start(gctx) // 传入已取消的代际 ctx 也必须被忽略
	if p.done != doneBefore {
		t.Fatal("重复 Start 重建了刷新循环（应首次调用生效）")
	}
	more := tr.requests()
	waitFor(t, 3*time.Second, "fetch continues after redundant start", func() bool { return tr.requests() > more })

	// Close 后计数冻结。
	p.Close()
	frozen := tr.requests()
	time.Sleep(60 * time.Millisecond)
	if got := tr.requests(); got != frozen {
		t.Fatalf("fetches after Close = %d, want frozen at %d", got, frozen)
	}
}
