// Package ruleset 管理分流规则的来源（本地文件 / 远程 URL）与定时刷新（路线图 3.4）。
//
// 语义：
//   - 构建时同步加载一次：本地文件读取 / 解析失败返回错误（严格）；
//     远程 URL 拉取失败只告警，以空规则继续（后续刷新自动重试）；
//   - URL 源按周期重新拉取：内容有变化才重新编译并原子切换（生效边界=新连接），
//     内容未变只刷新“最近成功”状态；任何失败都保留当前规则继续服务；
//   - Recheck 供配置热加载（SIGHUP）调用：文件源严格重读（失败应拒绝重载），
//     URL 源容错重拉（失败只告警，保持现有规则）。
package ruleset

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OopsOo0ps/proxy/internal/metrics"
	"github.com/OopsOo0ps/proxy/internal/routing"
)

// SourceKind 标识规则来源类型。
type SourceKind uint8

const (
	// SourceNone 表示未配置规则源：仅内置行为（私网直连）与配置的默认动作。
	SourceNone SourceKind = iota
	// SourceFile 表示本地规则文件。
	SourceFile
	// SourceURL 表示远程规则 URL。
	SourceURL
)

// String 返回来源类型的字符串表示（日志与 /stats 使用）。
func (k SourceKind) String() string {
	switch k {
	case SourceFile:
		return "file"
	case SourceURL:
		return "url"
	default:
		return "none"
	}
}

// 缺省约束。
const (
	// DefaultFetchTimeout 是单次 HTTP 拉取的超时。
	DefaultFetchTimeout = 15 * time.Second
	// DefaultMaxFetchBytes 是单次拉取的响应体上限。
	DefaultMaxFetchBytes = 8 << 20 // 8 MiB
)

// Spec 描述规则源的关键配置，用于配置热加载时判断能否复用现有 Provider。
type Spec struct {
	Kind     SourceKind
	Target   string // 文件路径或 URL
	Interval time.Duration
}

// SpecOf 依据配置字段构造 Spec（至多一个来源非空）。
// interval 是已被调用方解释过的生效刷新周期（0 = 仅启动拉取一次）。
func SpecOf(filePath, rawURL string, interval time.Duration) Spec {
	switch {
	case rawURL != "":
		return Spec{Kind: SourceURL, Target: rawURL, Interval: interval}
	case filePath != "":
		return Spec{Kind: SourceFile, Target: filePath}
	default:
		return Spec{}
	}
}

// Options 是 New 的参数。
type Options struct {
	// FilePath 与 URL 至多设置一个（规则源互斥，构造时防御性校验）。
	FilePath string
	URL      string
	// RefreshInterval 是 URL 源的刷新周期，0 = 仅启动拉取一次；其余来源忽略。
	RefreshInterval time.Duration
	// FetchTimeout / MaxFetchBytes 为 0 时取包内缺省值（15s / 8 MiB）。
	FetchTimeout  time.Duration
	MaxFetchBytes int64
	// Default 是未命中规则时的默认动作；规则文件里的 default 优先。
	Default routing.Action
	// PrivateDirect 为 true 时环回 / 私网 / 特殊地址一律直连。
	PrivateDirect bool
	// Logger 记录加载与刷新结果；nil 时静默。
	Logger *slog.Logger
	// Metrics 指标；可为 nil。
	Metrics *metrics.Metrics
	// Now 注入时钟（测试用），默认 time.Now。
	Now func() time.Time
	// OnChange 在生效引擎发生切换后调用（规则内容变化或 UpdateOptions 变更参数，
	// 初始加载成功也会调用一次）：用于失效与路由相关的缓存（例如转发路径的
	// 空闲连接池）。回调在锁外执行，必须并发安全。
	OnChange func()

	// fetchClient 允许包内测试注入自定义 HTTP 客户端（nil = 内置客户端）。
	fetchClient *http.Client
}

// Snapshot 是规则源的运行时状态（供 /stats 与测试）。
type Snapshot struct {
	Source      SourceKind
	Target      string
	Interval    time.Duration
	Loaded      bool
	Rules       int
	LastSuccess time.Time // 零值 = 从未成功加载
	LastError   string    // 最近一次失败原因；成功后清空
}

// Provider 是并发安全的规则源：Decide 从原子指针读取当前生效的编译结果，
// 刷新成功时整体替换。零值不可用，请使用 New 构造。
type Provider struct {
	spec Spec

	mu          sync.Mutex
	opts        routing.Options // 当前引擎参数（UpdateOptions 可更新）
	rules       *routing.Rules  // 最近一次成功解析的规则；nil = 尚未成功加载
	hash        string          // 最近一次成功内容的 SHA-256（hex）
	loaded      bool
	lastSuccess time.Time
	lastErr     string

	engine atomic.Pointer[routing.Engine]

	// attemptMu 串行化读取 / 拉取尝试，避免周期刷新与 Recheck 并发重复拉取。
	attemptMu sync.Mutex

	fetch fetchConfig
	log   *slog.Logger
	m     *metrics.Metrics
	now   func() time.Time

	onChange func()

	loopMu  sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	started bool
	closed  bool
}

// New 构建规则源并同步完成首次加载。
//   - 未配置来源：返回仅含内置行为的空规则源；
//   - 本地文件：读取 / 解析失败返回错误（启动与重载都按严格语义处理）；
//   - 远程 URL：拉取失败不返回错误——记录失败状态、告警后以空规则继续，
//     后续周期刷新会自动重试。
func New(opts Options) (*Provider, error) {
	if opts.FilePath != "" && opts.URL != "" {
		return nil, errors.New("ruleset: at most one of file path and URL may be set")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	p := &Provider{
		spec:     SpecOf(opts.FilePath, opts.URL, opts.RefreshInterval),
		opts:     routing.Options{Default: opts.Default, PrivateDirect: opts.PrivateDirect},
		log:      logger,
		m:        opts.Metrics,
		now:      now,
		onChange: opts.OnChange,
		fetch:    resolveFetchConfig(opts),
	}

	empty, err := routing.NewEngine(nil, p.opts)
	if err != nil {
		return nil, fmt.Errorf("ruleset: build empty engine: %w", err)
	}
	p.engine.Store(empty)

	switch p.spec.Kind {
	case SourceFile:
		if err := p.attempt(context.Background()); err != nil {
			return nil, err
		}
	case SourceURL:
		if err := p.attempt(context.Background()); err != nil {
			p.log.Warn("ruleset: initial fetch failed; continuing with empty rule set",
				"url", p.spec.Target, "error", err)
		}
	}
	return p, nil
}

// Spec 返回规则源的关键配置（热加载复用判断）。
func (p *Provider) Spec() Spec { return p.spec }

// Decide 返回 host 的分流动作；任何时刻可用（尚未成功加载时按空规则处理）。
func (p *Provider) Decide(host string) routing.Action {
	if p == nil {
		return routing.Proxy
	}
	engine := p.engine.Load()
	if engine == nil {
		return routing.Proxy
	}
	return engine.Decide(host)
}

// UpdateOptions 更新引擎参数（默认动作 / 私网直连），基于最近一次成功解析的
// 规则重新编译并原子切换；不触发任何网络或文件访问，参数未变化时不动作。
func (p *Provider) UpdateOptions(def routing.Action, privateDirect bool) {
	p.mu.Lock()
	if p.opts.Default == def && p.opts.PrivateDirect == privateDirect {
		p.mu.Unlock()
		return
	}
	p.opts = routing.Options{Default: def, PrivateDirect: privateDirect}
	rules := p.rules
	opts := p.opts
	p.mu.Unlock()

	engine, err := routing.NewEngine(rules, opts)
	if err != nil {
		// 规则来自已通过解析的内容，理论上不会失败；防御性保留现有引擎。
		p.log.Warn("ruleset: recompile with new options failed; keeping current engine", "error", err)
		return
	}
	p.engine.Store(engine)
	p.notifyChange()
}

// Recheck 立即重新检查一次规则源，供配置热加载（SIGHUP）调用：
//   - 本地文件：重新读取并解析，失败返回错误（调用方应拒绝本次重载）；
//   - 远程 URL：重新拉取，失败只告警并保持现有规则（与周期刷新一致），返回 nil。
func (p *Provider) Recheck(ctx context.Context) error {
	if p.spec.Kind == SourceNone {
		return nil
	}
	err := p.attempt(ctx)
	if err == nil || p.spec.Kind == SourceFile {
		return err
	}
	p.log.Warn("ruleset: recheck fetch failed; keeping current rules",
		"url", p.spec.Target, "error", err)
	return nil
}

// Start 启动 URL 规则源的周期刷新；可重复调用（幂等）。
// 未配置 URL 来源、刷新周期为 0、已关闭或已启动时不做任何事。
func (p *Provider) Start(ctx context.Context) {
	if p == nil || p.spec.Kind != SourceURL || p.spec.Interval <= 0 {
		return
	}
	p.loopMu.Lock()
	if p.started || p.closed {
		p.loopMu.Unlock()
		return
	}
	p.started = true
	ctx, p.cancel = context.WithCancel(ctx)
	p.done = make(chan struct{})
	done := p.done
	p.loopMu.Unlock()
	go p.loop(ctx, done)
}

// Close 停止刷新循环并等待其退出；可重复调用，对 nil 接收者安全。
// 它不影响在途请求：被替换的规则源由上层丢弃引用，Decide 仍读最后生效的引擎。
func (p *Provider) Close() {
	if p == nil {
		return
	}
	p.loopMu.Lock()
	p.closed = true
	cancel, done := p.cancel, p.done
	p.loopMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

// Snapshot 返回当前规则源状态。
func (p *Provider) Snapshot() Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	rules := 0
	if p.rules != nil {
		rules = len(p.rules.Rules)
	}
	return Snapshot{
		Source:      p.spec.Kind,
		Target:      p.spec.Target,
		Interval:    p.spec.Interval,
		Loaded:      p.loaded,
		Rules:       rules,
		LastSuccess: p.lastSuccess,
		LastError:   p.lastErr,
	}
}

// loop 按周期刷新，直到 ctx 取消或 Close。
func (p *Provider) loop(ctx context.Context, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(p.spec.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := p.attempt(ctx); err != nil {
				p.log.Warn("ruleset: refresh failed; keeping current rules",
					"url", p.spec.Target, "error", err)
			}
		}
	}
}

// attempt 执行一次源读取 / 拉取并把成功结果应用到引擎：
// 内容有变化时重新编译并原子切换；内容未变只刷新成功状态与指标；
// 失败时记录错误与指标并返回错误，当前引擎保持不变。
func (p *Provider) attempt(ctx context.Context) error {
	p.attemptMu.Lock()
	defer p.attemptMu.Unlock()

	data, err := p.read(ctx)
	if err != nil {
		p.recordError(err)
		return err
	}
	rules, err := routing.ParseRules(data)
	if err != nil {
		p.recordError(err)
		return err
	}
	hash := hashOf(data)

	p.mu.Lock()
	if p.loaded && hash == p.hash {
		p.lastSuccess = p.now()
		p.lastErr = ""
		successAt := p.lastSuccess
		p.mu.Unlock()
		p.m.RulesetRefresh(metrics.RulesetUnchanged)
		p.m.SetRulesetLastSuccess(successAt)
		return nil
	}
	engine, err := routing.NewEngine(rules, p.opts)
	if err != nil {
		p.lastErr = err.Error()
		p.mu.Unlock()
		p.m.RulesetRefresh(metrics.RulesetError)
		return err
	}
	p.rules = rules
	p.hash = hash
	p.loaded = true
	p.lastSuccess = p.now()
	p.lastErr = ""
	successAt := p.lastSuccess
	count := len(rules.Rules)
	p.engine.Store(engine)
	p.mu.Unlock()
	// 先让调用方失效路由相关缓存（如转发路径空闲连接），再记录指标：
	// 外部观察到 success 计数时，缓存失效已完成。
	p.notifyChange()
	p.m.RulesetRefresh(metrics.RulesetSuccess)
	p.m.SetRulesetLastSuccess(successAt)
	p.m.SetRulesetRules(count)
	return nil
}

// notifyChange 调用变化回调（锁外执行，nil 时为空操作）。
func (p *Provider) notifyChange() {
	if p.onChange != nil {
		p.onChange()
	}
}

// recordError 记录一次失败的读取 / 拉取（状态 + 指标）。
func (p *Provider) recordError(err error) {
	p.mu.Lock()
	p.lastErr = err.Error()
	p.mu.Unlock()
	p.m.RulesetRefresh(metrics.RulesetError)
}

// read 读取规则源原始内容：本地文件直读，远程 URL 走 HTTP 拉取。
func (p *Provider) read(ctx context.Context) ([]byte, error) {
	switch p.spec.Kind {
	case SourceFile:
		data, err := os.ReadFile(p.spec.Target)
		if err != nil {
			return nil, fmt.Errorf("read rules file: %w", err)
		}
		return data, nil
	case SourceURL:
		return p.fetch.fetchRules(ctx, p.spec.Target)
	default:
		return nil, errors.New("ruleset: no rule source configured")
	}
}

// hashOf 返回内容摘要，用于刷新时判断规则是否变化。
func hashOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
