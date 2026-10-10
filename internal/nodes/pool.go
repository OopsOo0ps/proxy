// Package nodes 管理出口节点池：轮询选择、失败冷却与自动切换。
//
// 选择策略为轮询 + 失败转移：每次拨号从游标位置开始依次尝试可用节点，
// 节点失败后累计失败次数并进入指数退避冷却（基数 10s，上限 5m），
// 冷却期内跳过该节点；全部节点都处于冷却时降级为全量尝试，
// 避免出现“有节点但永远不试”的黑洞。
package nodes

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OopsOo0ps/proxy/internal/config"
)

// DialFunc 通过指定节点建立到目标的隧道连接。
type DialFunc func(ctx context.Context, node config.Node, host string, port uint16) (net.Conn, error)

// Options 控制节点池行为。
type Options struct {
	// Cooldown 是失败冷却基数，默认 10s。
	Cooldown time.Duration
	// MaxCooldown 是冷却上限，默认 5m。
	MaxCooldown time.Duration
	// Now 可注入时钟（测试用），默认 time.Now。
	Now func() time.Time
}

// Pool 是并发安全的出口节点池。
type Pool struct {
	mu     sync.Mutex
	nodes  []*state
	dial   DialFunc
	opts   Options
	cursor atomic.Uint64
}

type state struct {
	cfg            config.Node
	fails          int
	unhealthyUntil time.Time
}

// Status 是单个出口节点的状态快照。
type Status struct {
	Addr              string
	Healthy           bool          // 当前是否不在冷却中
	Fails             int           // 连续失败次数
	CooldownRemaining time.Duration // 冷却剩余时间；健康时为 0
}

// New 构建节点池；节点数量至少为 1。
func New(cfgs []config.Node, dial DialFunc, opts Options) (*Pool, error) {
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
		item := Status{Addr: st.cfg.Addr, Healthy: true, Fails: st.fails}
		if now.Before(st.unhealthyUntil) {
			item.Healthy = false
			item.CooldownRemaining = st.unhealthyUntil.Sub(now)
		}
		snap = append(snap, item)
	}
	return snap
}

// AnyHealthy 报告是否存在至少一个不在冷却中的节点。
func (p *Pool) AnyHealthy() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.opts.Now()
	for _, st := range p.nodes {
		if !now.Before(st.unhealthyUntil) {
			return true
		}
	}
	return false
}

// Dial 依次尝试可用节点建立连接；全部失败时返回聚合错误。
func (p *Pool) Dial(ctx context.Context, host string, port uint16) (net.Conn, config.Node, error) {
	candidates := p.candidates()
	var errs []error
	for _, st := range candidates {
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
		conn, err := p.dial(ctx, st.cfg, host, port)
		if err == nil {
			p.markSuccess(st)
			return conn, st.cfg, nil
		}
		p.markFailure(st)
		errs = append(errs, fmt.Errorf("node %s: %w", st.cfg.Addr, err))
	}
	return nil, config.Node{}, fmt.Errorf("all exit nodes failed: %w", errors.Join(errs...))
}

// candidates 返回本轮尝试顺序：优先健康节点，全部冷却时退化为全量轮询。
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
	healthy := make([]*state, 0, len(ordered))
	for _, st := range ordered {
		if !now.Before(st.unhealthyUntil) {
			healthy = append(healthy, st)
		}
	}
	if len(healthy) == 0 {
		return ordered
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

func validateNode(n config.Node) error {
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
