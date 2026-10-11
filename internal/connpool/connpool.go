// Package connpool 维护“已握手、待领取”的上游隧道空闲连接池（预热池）。
//
// 为什么需要它：Trojan 协议一条隧道连接只服务一个目标，转发结束即关闭，
// 无法“用完再复用”；可复用的只有已完成 TCP+TLS 握手、尚未发送 Trojan 请求
// 的空闲连接。池在启动时为此类连接预热，请求到来时直接领取并补发请求，
// 省去一次到出口节点的完整握手往返。
//
// 设计要点：
//   - 领取时做非阻塞存活探测（即时检查 + 一个探测窗口复核，见 probeAlive）：
//     服务端已关闭、或已按握手超时回收并回放伪装响应的连接会被识别为失效并
//     丢弃，调用方回退新建，因此失效连接不会流入业务；探测不依赖读超时，
//     协程被调度延迟也不会漏检；
//   - 空闲连接受 IdleTTL 约束（默认 5s）。该值应明显小于服务端 handshake
//     超时（默认 10s），否则连接可能在池中就已经被服务端回收；
//   - 采用“按需补充”：启动预热到 MaxIdle，每次领取后异步补回 MaxIdle；
//     空闲期不做周期性握手，避免没有流量时的持续开销；
//   - 预热失败只计数（指标 + debug 日志）并等后续领取再试，不参与节点健康
//     判定，节点冷却与轮询逻辑保持不变。
package connpool

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/OopsOo0ps/proxy/internal/metrics"
)

// Node 描述一个可预热的上游节点。
type Node struct {
	// Addr 是节点地址（host:port），在池内唯一标识该节点。
	Addr string
	// Dial 建立到节点的 TCP+TLS 连接（握手完成，未发送 Trojan 请求）。
	Dial func(ctx context.Context) (net.Conn, error)
	// Start 在领取到的连接上向目标发起 Trojan 请求；ctx 是本次领取的上下文
	// （调用方可能带有故障转移总预算），实现应把请求写出的超时收敛到 ctx 截止时间内。
	Start func(ctx context.Context, conn net.Conn, host string, port uint16) error
}

// Options 控制池行为。
type Options struct {
	// MaxIdle 是每节点最大空闲连接数；<=0 时池关闭（Claim 恒失败）。
	MaxIdle int
	// IdleTTL 是空闲连接最长保留时间；<=0 时使用 5s。
	IdleTTL time.Duration
	// Now 注入时钟（测试用），默认 time.Now。
	Now func() time.Time
	// Logger 记录预热失败等调试信息；nil 时静默。
	Logger *slog.Logger
	// Metrics 指标；可为 nil。
	Metrics *metrics.Metrics
}

// Pool 是并发安全的预热连接池。
type Pool struct {
	opts Options

	mu      sync.Mutex
	nodes   map[string]*nodeState
	order   []*nodeState
	started bool
	closed  bool
	ctx     context.Context // 后台任务的父 ctx；Start 之后有效
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

type nodeState struct {
	spec Node
	idle []*idleConn // 栈：末尾最新，领取优先取最新（最旧的先过期淘汰）
	// dropped：节点被主动健康检查摘除期间置位，暂停后台补池并丢弃补池结果；
	// 节点重新收到真实领取（Claim）时解除。
	dropped bool
	warming int // 后台正在建立连接的数量
}

type idleConn struct {
	conn      net.Conn
	createdAt time.Time
}

// New 构建连接池；节点列表为空、地址重复或 Dial/Start 缺失时报错。
// MaxIdle <= 0 时返回的池处于关闭状态（Claim 恒返回 false），便于调用方统一持有。
func New(nodes []Node, opts Options) (*Pool, error) {
	if len(nodes) == 0 {
		return nil, errors.New("connpool: at least one node is required")
	}
	if opts.IdleTTL <= 0 {
		opts.IdleTTL = 5 * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	p := &Pool{opts: opts, nodes: make(map[string]*nodeState, len(nodes))}
	for i, n := range nodes {
		if n.Addr == "" {
			return nil, fmt.Errorf("connpool: nodes[%d]: addr must not be empty", i)
		}
		if n.Dial == nil || n.Start == nil {
			return nil, fmt.Errorf("connpool: nodes[%d] (%s): dial and start funcs are required", i, n.Addr)
		}
		if _, dup := p.nodes[n.Addr]; dup {
			return nil, fmt.Errorf("connpool: duplicate node addr %q", n.Addr)
		}
		st := &nodeState{spec: n}
		p.nodes[n.Addr] = st
		p.order = append(p.order, st)
	}
	// 为每个节点预创建空闲数指标序列，使 /metrics 在预热完成前也能看到它们。
	for _, st := range p.order {
		opts.Metrics.SetPoolIdle(st.spec.Addr, 0)
	}
	return p, nil
}

// Enabled 报告池是否生效（MaxIdle > 0）；对 nil 接收者安全。
func (p *Pool) Enabled() bool { return p != nil && p.opts.MaxIdle > 0 }

// Start 启动预热与过期清理；可重复调用（幂等）。ctx 取消或调用 Close 后停止。
func (p *Pool) Start(ctx context.Context) {
	if !p.Enabled() {
		return
	}
	p.mu.Lock()
	if p.started || p.closed {
		p.mu.Unlock()
		return
	}
	p.started = true
	p.ctx, p.cancel = context.WithCancel(ctx)
	interval := p.opts.IdleTTL / 2
	if interval < 250*time.Millisecond {
		interval = 250 * time.Millisecond
	}
	if interval > 5*time.Second {
		interval = 5 * time.Second
	}
	p.wg.Add(1)
	states := append([]*nodeState(nil), p.order...)
	p.mu.Unlock()

	go p.cleanLoop(interval)
	// 启动预热：每个节点补到 MaxIdle。失败只计数，后续领取时再补。
	for _, st := range states {
		p.refill(st)
	}
}

// Close 停止后台任务并关闭全部空闲连接；可重复调用。
func (p *Pool) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	if p.cancel != nil {
		p.cancel()
	}
	var conns []net.Conn
	for _, st := range p.order {
		for _, ic := range st.idle {
			conns = append(conns, ic.conn)
		}
		st.idle = nil
		p.opts.Metrics.SetPoolIdle(st.spec.Addr, 0)
	}
	p.mu.Unlock()

	for _, c := range conns {
		_ = c.Close()
	}
	p.wg.Wait()
}

// Claim 尝试为 (host, port) 从 addr 节点的池中领取一条空闲连接。
// 成功时连接已发送 Trojan 请求、可直接进入转发；失败返回 (nil, false)，
// 调用方应回退新建连接。内部会跳过过期或失效的空闲连接。
func (p *Pool) Claim(ctx context.Context, addr, host string, port uint16) (net.Conn, bool) {
	if !p.Enabled() || ctx.Err() != nil {
		return nil, false
	}
	p.mu.Lock()
	st := p.nodes[addr]
	if st != nil {
		// 真实请求进入说明节点已被重新投入服务：解除摘除期间的停补标记。
		st.dropped = false
	}
	p.mu.Unlock()
	if st == nil {
		return nil, false
	}

	for {
		ic := p.popNewest(st)
		if ic == nil {
			p.opts.Metrics.PoolClaim(metrics.PoolClaimMiss, addr)
			p.refill(st)
			return nil, false
		}
		if !p.fresh(ic) {
			// 超过 IdleTTL：直接淘汰，不再尝试复用。
			_ = ic.conn.Close()
			p.opts.Metrics.PoolClaim(metrics.PoolClaimStale, addr)
			continue
		}
		if err := probeAlive(ic.conn); err != nil {
			p.debug("idle connection failed liveness probe", addr, err)
			_ = ic.conn.Close()
			p.opts.Metrics.PoolClaim(metrics.PoolClaimStale, addr)
			continue
		}
		if err := st.spec.Start(ctx, ic.conn, host, port); err != nil {
			p.debug("failed to start trojan request on idle connection", addr, err)
			_ = ic.conn.Close()
			p.opts.Metrics.PoolClaim(metrics.PoolClaimStale, addr)
			continue
		}
		p.opts.Metrics.PoolClaim(metrics.PoolClaimHit, addr)
		p.refill(st)
		return ic.conn, true
	}
}

// IdleCounts 返回各节点当前空闲连接数快照（供 /stats 使用）；对 nil 接收者安全。
func (p *Pool) IdleCounts() map[string]int {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]int, len(p.order))
	for _, st := range p.order {
		out[st.spec.Addr] = len(st.idle)
	}
	return out
}

// DropNode 关闭并移除指定节点的全部空闲连接，同时暂停该节点的后台补池，
// 直到它再次收到真实领取（Claim）才恢复预热。用于节点被主动健康检查摘除时
// 清理积压的空闲隧道。对 nil 接收者、未启用与未知节点安全。
func (p *Pool) DropNode(addr string) {
	if !p.Enabled() {
		return
	}
	p.mu.Lock()
	st := p.nodes[addr]
	if st == nil {
		p.mu.Unlock()
		return
	}
	st.dropped = true
	conns := make([]net.Conn, 0, len(st.idle))
	for _, ic := range st.idle {
		conns = append(conns, ic.conn)
	}
	st.idle = nil
	p.mu.Unlock()

	p.opts.Metrics.SetPoolIdle(addr, 0)
	for _, c := range conns {
		_ = c.Close()
	}
}

// popNewest 弹出最新的空闲连接（空池返回 nil）。
func (p *Pool) popNewest(st *nodeState) *idleConn {
	p.mu.Lock()
	if len(st.idle) == 0 {
		p.mu.Unlock()
		return nil
	}
	last := len(st.idle) - 1
	ic := st.idle[last]
	st.idle[last] = nil // 避免持有已弹出连接的引用
	st.idle = st.idle[:last]
	idle := len(st.idle)
	p.mu.Unlock()
	p.opts.Metrics.SetPoolIdle(st.spec.Addr, idle)
	return ic
}

// fresh 报告空闲连接是否仍在 IdleTTL 内。
func (p *Pool) fresh(ic *idleConn) bool {
	return p.opts.Now().Sub(ic.createdAt) <= p.opts.IdleTTL
}

// refill 把节点的空闲连接后台补回 MaxIdle（受容量约束，不会超发）。
// 池未启动或已关闭时不做任何事；重复调用是安全的。
func (p *Pool) refill(st *nodeState) {
	p.mu.Lock()
	if !p.started || p.closed || st.dropped {
		p.mu.Unlock()
		return
	}
	n := p.opts.MaxIdle - len(st.idle) - st.warming
	if n <= 0 {
		p.mu.Unlock()
		return
	}
	st.warming += n
	ctx := p.ctx
	p.wg.Add(n)
	p.mu.Unlock()

	for i := 0; i < n; i++ {
		go func() {
			defer p.wg.Done()
			conn, err := st.spec.Dial(ctx)
			p.warmDone(st, conn, err)
		}()
	}
}

// warmDone 收尾一次后台预热：成功则入池，失败则计数。
func (p *Pool) warmDone(st *nodeState, conn net.Conn, err error) {
	p.mu.Lock()
	st.warming--
	closed := p.closed
	dropped := st.dropped
	var idle int
	if err == nil && !closed && !dropped {
		st.idle = append(st.idle, &idleConn{conn: conn, createdAt: p.opts.Now()})
		idle = len(st.idle)
	}
	p.mu.Unlock()

	if err == nil && (closed || dropped) {
		// 池已关闭或节点被摘除：不在池中保留连接。
		if conn != nil {
			_ = conn.Close()
		}
		return
	}
	if closed {
		return
	}
	if err != nil {
		p.opts.Metrics.PoolWarmFailed(st.spec.Addr)
		p.debug("warm dial failed", st.spec.Addr, err)
		return
	}
	p.opts.Metrics.SetPoolIdle(st.spec.Addr, idle)
}

// cleanLoop 周期清理超时空闲连接。
func (p *Pool) cleanLoop(interval time.Duration) {
	defer p.wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.prune()
		}
	}
}

// prune 关闭所有超过 IdleTTL 的空闲连接；关闭动作在锁外执行。
func (p *Pool) prune() {
	now := p.opts.Now()
	var expired []net.Conn
	p.mu.Lock()
	for _, st := range p.order {
		kept := st.idle[:0]
		for _, ic := range st.idle {
			if now.Sub(ic.createdAt) > p.opts.IdleTTL {
				expired = append(expired, ic.conn)
				continue
			}
			kept = append(kept, ic)
		}
		clear(st.idle[len(kept):])
		st.idle = kept
		p.opts.Metrics.SetPoolIdle(st.spec.Addr, len(kept))
	}
	p.mu.Unlock()

	for _, c := range expired {
		_ = c.Close()
	}
}

// probeWindow 是存活探测窗口：给在途的收尾字节（服务端回放的伪装响应、
// FIN/RST）留出到达时间；健康连接上什么都没有，等待即为探测成本。
const probeWindow = time.Millisecond

// probeAlive 判断空闲连接是否仍可复用。
//
// 对 TCP 连接（含 *tls.Conn 包装）使用非阻塞套接字探测（MSG_PEEK，见
// probeTCP）：不消费数据、不设置读期限，因此不受协程调度影响。
// 这一点是「预热池领取竞态」的修复关键：期限读在协程被延迟调度时会先
// 到期，Go 网络栈直接返回超时、忽略已排队的数据，把「服务端已按握手
// 超时回收并回放伪装响应」的连接误判为健康，伪装响应随后随隧道流入业务。
// 非 TCP 连接（如测试用 net.Pipe）退回期限读探测（probeAliveRead）。
func probeAlive(conn net.Conn) error {
	if tcp := tcpConnOf(conn); tcp != nil {
		if err, supported := probeTCP(tcp); supported {
			return err
		}
	}
	return probeAliveRead(conn)
}

// probeTCP 两阶段非阻塞探测：先即时检查一次（已排队的伪装响应、已收到的
// FIN/RST 立刻命中），无异常时等待一个探测窗口让在途数据到达，再复核一次。
// 两次检查都基于 MSG_PEEK，不受调度延迟影响；池中空闲连接在领取前没有
// 任何读取，服务端回放的伪装响应必然停留在内核缓冲，peek 可见。
func probeTCP(conn *net.TCPConn) (error, bool) {
	err, supported := probeTCPSyscall(conn)
	if !supported || err != nil {
		return err, supported
	}
	time.Sleep(probeWindow)
	return probeTCPSyscall(conn)
}

// tcpConnOf 取出连接背后的 *net.TCPConn：直接是 TCPConn，或经 NetConn()
// （*tls.Conn 等）包装的 TCPConn；无法还原时返回 nil。
func tcpConnOf(conn net.Conn) *net.TCPConn {
	for i := 0; i < 4 && conn != nil; i++ {
		if tcp, ok := conn.(*net.TCPConn); ok {
			return tcp
		}
		wrapped, ok := conn.(interface{ NetConn() net.Conn })
		if !ok {
			return nil
		}
		conn = wrapped.NetConn()
	}
	return nil
}

// probeAliveRead 是退回路径的存活探测：短暂等待后读一个字节。
// 预期结果是超时——服务端在收到 Trojan 请求前不会发送任何应用数据；
// 读到数据（服务端已按握手超时回收并回放伪装响应）或 EOF/错误都表示连接不可用。
// 探测通过后清除读期限，连接可正常使用。
//
// 注意：不能把读期限设为“立即到期”来“零等待”探测——Go 的网络栈在检测到
// 期限已过时会直接返回超时，不再检查已排队的 EOF/数据（也会跳过 TLS 内部的
// 握手后消息，如 NewSessionTicket），反而探测不出失效连接。
// 期限读依赖协程被及时调度，仅用于无法做非阻塞探测的连接。
func probeAliveRead(conn net.Conn) error {
	if err := conn.SetReadDeadline(time.Now().Add(probeWindow)); err != nil {
		return err
	}
	var one [1]byte
	_, err := conn.Read(one[:])
	var ne net.Error
	switch {
	case err == nil:
		return errors.New("connpool: unexpected data on idle connection")
	case errors.As(err, &ne) && ne.Timeout():
		return conn.SetReadDeadline(time.Time{})
	default:
		return err
	}
}

func (p *Pool) debug(msg, node string, err error) {
	if p.opts.Logger == nil {
		return
	}
	p.opts.Logger.Debug(msg, "node", node, "error", err)
}
