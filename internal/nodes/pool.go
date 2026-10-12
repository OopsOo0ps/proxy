// Package nodes 管理出口节点池：轮询选择、失败冷却、主动健康检查与自动切换。
//
// 选择策略为轮询 + 失败转移：每次拨号从游标位置开始依次尝试可用节点，
// 节点失败后累计失败次数并进入指数退避冷却（基数 10s，上限 5m），
// 冷却期内跳过该节点；全部节点都处于冷却时降级为全量尝试，
// 避免出现“有节点但永远不试”的黑洞。
//
// 整条故障转移链受一个总时间预算约束（Options.FailoverBudget，缺省 30s）：
// 预算耗尽即停止尝试，已消耗的等待不会随节点数量线性放大。
//
// 主动健康检查（路线图 3.3）：按周期对节点做轻量探测（TCP+TLS 握手后立即
// 关闭），连续失败达阈值后摘除该节点（硬摘除：不再参与任何尝试，真实流量
// 也不再经过它）；摘除后继续探测，连续成功达阈值自动加回并清空被动失败
// 计数与冷却。摘除状态只由探测更新，冷却状态只由真实拨号更新，二者独立
// 但共同决定节点是否可接流量。
package nodes

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OopsOo0ps/proxy/internal/core"
)

// 探测结果标签值：bool 结果的可读编码，供观测后端使用。
const (
	ProbeSuccess = "success"
	ProbeFailure = "failure"
)

// Observer 是节点池的遥测出口；*metrics.Metrics 适配实现（L4 单点）。
// 事件词汇（success/failure）随事件归属本包，Prometheus 编码归 metrics。
type Observer interface {
	// ProbeResult 记录一次主动健康探测结果。
	ProbeResult(addr string, ok bool)
	// HealthChanged 记录节点可接流量状态变化（healthy = false 表示已被摘除）。
	HealthChanged(addr string, healthy bool)
}

// NopObserver 是 Options 的缺省遥测出口：全部方法为空操作，
// 组件测试零构造、无需 registry。
var NopObserver Observer = nopObserver{}

type nopObserver struct{}

func (nopObserver) ProbeResult(string, bool)   {}
func (nopObserver) HealthChanged(string, bool) {}

// Node 描述一个出口节点（Trojan over TLS）。
// 运行时模型与配置模式解耦：由组装根从 config.Node 映射而来，
// 本包不反向依赖配置层。
type Node struct {
	Addr     string // host:port
	Password string // 隧道口令
	SNI      string // 可选：TLS SNI / 证书校验名
}

// DialFunc 通过指定节点建立到目标的隧道连接。
type DialFunc func(ctx context.Context, node Node, t core.Target) (net.Conn, error)

// ProbeFunc 对节点做一次轻量健康探测（如 TCP+TLS 握手），失败时返回错误。
type ProbeFunc func(ctx context.Context, node Node) error

// ErrNoHealthyNodes 表示所有出口节点都被主动健康检查摘除。
var ErrNoHealthyNodes = errors.New("nodes: all exit nodes removed by health check")

// DefaultFailoverBudget 是单次 Dial 在全部候选节点上的缺省总时间预算。
// 与 config.defaultFailoverBudget（配置层缺省 30s）保持一致。
const DefaultFailoverBudget = 30 * time.Second

// HealthOptions 是主动健康检查参数；Interval <= 0 时关闭主动探测。
type HealthOptions struct {
	// Interval 是探测周期；<= 0 关闭主动探测。
	Interval time.Duration
	// Timeout 是单次探测超时；<= 0 时取 3s。
	Timeout time.Duration
	// Failures 是连续失败多少次后摘除；<= 0 时取 3。
	Failures int
	// Successes 是摘除后连续成功多少次加回；<= 0 时取 2。
	Successes int
}

// Options 控制节点池行为。
type Options struct {
	// Cooldown 是失败冷却基数，默认 10s。
	Cooldown time.Duration
	// MaxCooldown 是冷却上限，默认 5m。
	MaxCooldown time.Duration
	// FailoverBudget 是单次 Dial 跨全部候选节点的总时间预算（含建连、握手与
	// 请求写出）；<= 0 时使用 DefaultFailoverBudget。调用方上下文更短时以更短者为准。
	FailoverBudget time.Duration
	// Now 可注入时钟（测试用），默认 time.Now。
	Now func() time.Time
	// Health 是主动健康检查参数；Interval <= 0 时关闭（仅保留被动冷却）。
	Health HealthOptions
	// Probe 是主动探测函数；开启健康检查（Health.Interval > 0）时必填。
	Probe ProbeFunc
	// OnRemove 在节点刚被主动摘除时回调（可选）。
	OnRemove func(addr string)
	// OnRejoin 在节点刚被主动加回时回调（可选）。
	OnRejoin func(addr string)
	// Logger 记录摘除/加回与探测失败；可为 nil。
	Logger *slog.Logger
	// Observer 是遥测出口；nil 时使用 NopObserver。
	Observer Observer
}

// Pool 是并发安全的出口节点池。
type Pool struct {
	mu     sync.Mutex
	nodes  []*state
	dial   DialFunc
	opts   Options
	cursor atomic.Uint64

	hcStarted bool
	hcClosed  bool
	hcCancel  context.CancelFunc
	hcDone    chan struct{}
}

type state struct {
	cfg            Node
	fails          int
	unhealthyUntil time.Time
	// removed 表示被主动健康检查摘除（硬摘除，不参与任何尝试）。
	removed bool
	// probeFails 是当前连续探测失败次数；probeSuccesses 是摘除后的连续成功次数。
	probeFails     int
	probeSuccesses int
}

// Status 是单个出口节点的状态快照。
type Status struct {
	Addr              string
	Healthy           bool          // 当前是否可接流量（未摘除且不在冷却中）
	Fails             int           // 连续真实拨号失败次数
	CooldownRemaining time.Duration // 冷却剩余时间；健康时为 0
	Removed           bool          // 是否被主动健康检查摘除
	ProbeFails        int           // 当前连续探测失败次数
}

// New 构建节点池；节点数量至少为 1。
func New(cfgs []Node, dial DialFunc, opts Options) (*Pool, error) {
	if len(cfgs) == 0 {
		return nil, errors.New("nodes: at least one exit node is required")
	}
	if dial == nil {
		return nil, errors.New("nodes: dial func is required")
	}
	if opts.Cooldown <= 0 {
		opts.Cooldown = 10 * time.Second
	}
	if opts.MaxCooldown <= 0 {
		opts.MaxCooldown = 5 * time.Minute
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.FailoverBudget <= 0 {
		opts.FailoverBudget = DefaultFailoverBudget
	}
	if opts.Observer == nil {
		opts.Observer = NopObserver
	}
	if opts.Health.Interval > 0 {
		if opts.Probe == nil {
			return nil, errors.New("nodes: probe func is required when health check is enabled")
		}
		if opts.Health.Timeout <= 0 {
			opts.Health.Timeout = 3 * time.Second
		}
		if opts.Health.Failures <= 0 {
			opts.Health.Failures = 3
		}
		if opts.Health.Successes <= 0 {
			opts.Health.Successes = 2
		}
	}
	p := &Pool{dial: dial, opts: opts}
	for i, cfg := range cfgs {
		if err := validateNode(cfg); err != nil {
			return nil, fmt.Errorf("nodes[%d]: %w", i, err)
		}
		p.nodes = append(p.nodes, &state{cfg: cfg})
	}
	return p, nil
}

// Len 返回节点数量。
func (p *Pool) Len() int { return len(p.nodes) }

// Snapshot 返回所有出口节点的状态快照（并发安全，只读）。
func (p *Pool) Snapshot() []Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.opts.Now()
	snap := make([]Status, 0, len(p.nodes))
	for _, st := range p.nodes {
		item := Status{Addr: st.cfg.Addr, Fails: st.fails, Removed: st.removed, ProbeFails: st.probeFails}
		item.Healthy = !st.removed
		if now.Before(st.unhealthyUntil) {
			item.Healthy = false
			item.CooldownRemaining = st.unhealthyUntil.Sub(now)
		}
		snap = append(snap, item)
	}
	return snap
}

// AnyHealthy 报告是否存在至少一个可接流量的节点（未被摘除且不在冷却中）。
func (p *Pool) AnyHealthy() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.opts.Now()
	for _, st := range p.nodes {
		if !st.removed && !now.Before(st.unhealthyUntil) {
			return true
		}
	}
	return false
}

// Dial 依次尝试可用节点建立连接；全部失败时返回聚合错误。
//
// 全部候选节点共享一个故障转移总预算（Options.FailoverBudget）：预算耗尽时
// 立即停止后续尝试，在途尝试随上下文取消，最坏等待从「节点数 × 单节点超时」
// 收敛为预算上限。因预算或调用方取消（而非节点自身错误）中断的尝试不计入
// 被动失败，避免把健康节点误送入冷却。
func (p *Pool) Dial(ctx context.Context, t core.Target) (net.Conn, Node, error) {
	candidates := p.candidates()
	if len(candidates) == 0 {
		return nil, Node{}, ErrNoHealthyNodes
	}
	// 子上下文与父上下文取更短的截止时间：调用方超时优先级更高。
	chainCtx, cancel := context.WithTimeout(ctx, p.opts.FailoverBudget)
	defer cancel()

	var errs []error
	tried := 0
	for _, st := range candidates {
		if err := chainCtx.Err(); err != nil {
			errs = append(errs, p.annotateChainAbort(ctx, err, tried))
			break
		}
		tried++
		conn, err := p.dial(chainCtx, st.cfg, t)
		if err == nil {
			p.markSuccess(st)
			return conn, st.cfg, nil
		}
		errs = append(errs, fmt.Errorf("node %s: %w", st.cfg.Addr, err))
		if chainCtx.Err() != nil {
			// 链被预算或调用方取消中断：不再尝试后续节点，也不记被动失败。
			errs = append(errs, p.annotateChainAbort(ctx, chainCtx.Err(), tried))
			break
		}
		p.markFailure(st)
	}
	return nil, Node{}, fmt.Errorf("all exit nodes failed: %w", errors.Join(errs...))
}

// annotateChainAbort 为「链被中断」标注原因：预算耗尽与调用方取消（父上下文
// 先到期或被取消）需要能区分，便于线上判断最坏等待是否已收敛到预算内。
func (p *Pool) annotateChainAbort(parent context.Context, err error, tried int) error {
	if parent.Err() == nil {
		return fmt.Errorf("failover budget %s exhausted after %d node attempt(s): %w",
			p.opts.FailoverBudget, tried, err)
	}
	return err
}

// candidates 返回本轮尝试顺序：先剔除被主动摘除的节点（硬摘除），
// 其余节点中优先健康者；全部处于冷却时退化为对未摘除节点的全量轮询。
// 全部节点被摘除时返回空切片，由 Dial 转为明确错误。
func (p *Pool) candidates() []*state {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 先取模再转 int，避免 32 位平台上高计数溢出为负数。
	start := int((p.cursor.Add(1) - 1) % uint64(len(p.nodes)))
	ordered := make([]*state, 0, len(p.nodes))
	for i := 0; i < len(p.nodes); i++ {
		ordered = append(ordered, p.nodes[(start+i)%len(p.nodes)])
	}

	now := p.opts.Now()
	available := make([]*state, 0, len(ordered))
	for _, st := range ordered {
		if !st.removed {
			available = append(available, st)
		}
	}
	if len(available) == 0 {
		return nil
	}
	healthy := make([]*state, 0, len(ordered))
	for _, st := range available {
		if !now.Before(st.unhealthyUntil) {
			healthy = append(healthy, st)
		}
	}
	if len(healthy) == 0 {
		return available
	}
	return healthy
}

func (p *Pool) markSuccess(st *state) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st.fails = 0
	st.unhealthyUntil = time.Time{}
}

func (p *Pool) markFailure(st *state) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st.fails++
	st.unhealthyUntil = p.opts.Now().Add(p.cooldownFor(st.fails))
}

// cooldownFor 返回第 fails 次连续失败后的冷却时长：base * 2^(fails-1)，封顶 MaxCooldown。
func (p *Pool) cooldownFor(fails int) time.Duration {
	cooldown := p.opts.Cooldown
	for i := 1; i < fails; i++ {
		cooldown *= 2
		if cooldown >= p.opts.MaxCooldown {
			return p.opts.MaxCooldown
		}
	}
	return cooldown
}

// StartHealthChecks 启动主动健康探测循环（Health.Interval > 0 时生效）：
// 启动后立即探测一轮，之后按周期探测；连续失败达阈值摘除节点，摘除后
// 连续成功达阈值自动加回。可重复调用（幂等）；Close 或父 ctx 取消后停止。
func (p *Pool) StartHealthChecks(ctx context.Context) {
	if p == nil || p.opts.Health.Interval <= 0 || p.opts.Probe == nil {
		return
	}
	p.mu.Lock()
	if p.hcStarted || p.hcClosed {
		p.mu.Unlock()
		return
	}
	p.hcStarted = true
	ctx, cancel := context.WithCancel(ctx)
	p.hcCancel = cancel
	done := make(chan struct{})
	p.hcDone = done
	// 初始状态：全部节点视为可接流量（除非已因历史拨号处于冷却）。
	now := p.opts.Now()
	for _, st := range p.nodes {
		p.opts.Observer.HealthChanged(st.cfg.Addr, !st.removed && !now.Before(st.unhealthyUntil))
	}
	p.mu.Unlock()

	go p.healthLoop(ctx, done)
}

// Close 停止主动健康探测并等待探测循环退出；可重复调用，对 nil 接收者安全。
// 它不影响在途请求的拨号：被替换的池不再接新流量，由上层丢弃引用。
func (p *Pool) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.hcClosed = true
	cancel, done := p.hcCancel, p.hcDone
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

// healthLoop 周期执行探测，直到 ctx 取消。
func (p *Pool) healthLoop(ctx context.Context, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(p.opts.Health.Interval)
	defer ticker.Stop()
	for {
		p.probeAll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// probeAll 并发探测所有节点（单个节点超时不阻塞其他节点），等待本轮完成。
func (p *Pool) probeAll(ctx context.Context) {
	p.mu.Lock()
	states := append([]*state(nil), p.nodes...)
	p.mu.Unlock()

	var wg sync.WaitGroup
	for _, st := range states {
		wg.Add(1)
		go func(st *state) {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, p.opts.Health.Timeout)
			defer cancel()
			err := p.opts.Probe(pctx, st.cfg)
			if err != nil && ctx.Err() != nil {
				// 探测循环正在退出（关停/运行时替换）：取消不算节点故障。
				return
			}
			p.recordProbe(st, err)
		}(st)
	}
	wg.Wait()
}

// recordProbe 应用一次探测结果：
//   - 成功：清零连续失败计数；若节点已摘除，累计连续成功，达阈值后加回
//     并清空被动失败计数与冷却；
//   - 失败：清零连续成功计数；累计连续失败，达阈值后摘除节点。
func (p *Pool) recordProbe(st *state, err error) {
	ok := err == nil
	p.mu.Lock()
	var removedNow, rejoinedNow bool
	var probeFails int
	if ok {
		st.probeFails = 0
		if st.removed {
			st.probeSuccesses++
			if st.probeSuccesses >= p.opts.Health.Successes {
				st.removed = false
				st.probeSuccesses = 0
				st.fails = 0
				st.unhealthyUntil = time.Time{}
				rejoinedNow = true
			}
		}
	} else {
		st.probeSuccesses = 0
		st.probeFails++
		probeFails = st.probeFails
		if !st.removed && st.probeFails >= p.opts.Health.Failures {
			st.removed = true
			removedNow = true
		}
	}
	p.mu.Unlock()

	p.opts.Observer.ProbeResult(st.cfg.Addr, ok)
	switch {
	case removedNow:
		p.opts.Observer.HealthChanged(st.cfg.Addr, false)
		if l := p.opts.Logger; l != nil {
			l.Warn("exit node removed by active health check",
				"node", st.cfg.Addr, "consecutive_probe_failures", probeFails)
		}
		if p.opts.OnRemove != nil {
			p.opts.OnRemove(st.cfg.Addr)
		}
	case rejoinedNow:
		p.opts.Observer.HealthChanged(st.cfg.Addr, true)
		if l := p.opts.Logger; l != nil {
			l.Info("exit node rejoined after passing health checks", "node", st.cfg.Addr)
		}
		if p.opts.OnRejoin != nil {
			p.opts.OnRejoin(st.cfg.Addr)
		}
	default:
		if !ok {
			if l := p.opts.Logger; l != nil {
				l.Debug("health probe failed", "node", st.cfg.Addr, "consecutive_probe_failures", probeFails, "error", err)
			}
		}
	}
}

func validateNode(n Node) error {
	if _, _, err := net.SplitHostPort(n.Addr); err != nil {
		return fmt.Errorf("invalid node addr %q: %w", n.Addr, err)
	}
	if n.Password == "" {
		return errors.New("node password must not be empty")
	}
	if strings.ContainsAny(n.Password+n.SNI, "\r\n") {
		return errors.New("node password/sni must not contain CR or LF")
	}
	return nil
}
