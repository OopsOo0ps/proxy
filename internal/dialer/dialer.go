// Package dialer 是路由感知的出站组合点（设计文档 §5.3 的组合树根）：
// 依据分流规则把目标分派给直连拨号或出口节点池。分派器透传被委派方的
// 权威 Route，入站不得自行推断上游（不变量 6）。
package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/defaults"
	"github.com/OopsOo0ps/proxy/internal/nodes"
)

// ErrNoNodes 表示决策为“走代理”但未配置任何出口节点。
var ErrNoNodes = errors.New("dialer: no exit nodes configured")

// 编译期断言：组合树的两个节点都满足 core 契约，接口漂移在构建期暴露。
var (
	_ core.TargetDialer = (*Dialer)(nil)
	_ core.TargetDialer = (*Direct)(nil)
)

// Router 是拨号前的分流决策器：*routing.Engine（静态规则）与
// *ruleset.Provider（含远程刷新的动态规则源）都满足该接口。
type Router interface {
	Decide(host string) core.RouteAction
}

// Direct 是直连拨号器（组合树的 direct 剪枝）：net.Dial + 权威路径
// Route{Direct}。client（路由分派的直连分支）与 server（服务端即出口）
// 两个组装根共用同一实现（§5.3 directDialer），可安全并发使用。
type Direct struct {
	d *net.Dialer
}

// NewDirect 构建直连拨号器；dialTimeout <= 0 时使用 defaults.DialTimeout。
func NewDirect(dialTimeout time.Duration) *Direct {
	if dialTimeout <= 0 {
		dialTimeout = defaults.DialTimeout
	}
	return &Direct{d: &net.Dialer{Timeout: dialTimeout}}
}

// DialTarget 直连建立到 t 的连接；返回的 Route 恒为 Route{Direct}（无出口标签）。
func (d *Direct) DialTarget(ctx context.Context, t core.Target) (net.Conn, core.Route, error) {
	addr := t.String()
	conn, err := d.d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, core.Route{Action: core.RouteDirect}, fmt.Errorf("direct dial %s: %w", addr, err)
	}
	return conn, core.Route{Action: core.RouteDirect}, nil
}

// Dialer 是路由感知的出站拨号器，实现 core.TargetDialer（入站组件只见
// core 契约，实现细节不出本包），可安全并发使用。
type Dialer struct {
	router Router
	pool   *nodes.Pool // 可为 nil（未配置节点，仅支持直连）
	direct *Direct
}

// Options 是 Dialer 构造参数。
type Options struct {
	// Router 分流引擎（必填）。
	Router Router
	// Pool 出口节点池；为空时仅能直连。
	Pool *nodes.Pool
	// DialTimeout 连接超时，默认 defaults.DialTimeout（10s）。
	DialTimeout time.Duration
}

// New 构建拨号器：路由分派器持有同一棵组合树的两个剪枝
// （Direct 直连 + Pool 出口节点池），分派只是透传。
func New(opts Options) *Dialer {
	return &Dialer{
		router: opts.Router,
		pool:   opts.Pool,
		direct: NewDirect(opts.DialTimeout),
	}
}

// DialTarget 建立到 t 的连接：按分流规则直连或经出口节点。
// 返回的 Route 是权威路径（直连 Route{Direct}；经池 Route{Proxy, 节点地址}），
// 路由判定为拒绝时返回 (nil, Route{Reject}, nil)，由入站按协议回拒绝响应。
func (d *Dialer) DialTarget(ctx context.Context, t core.Target) (net.Conn, core.Route, error) {
	switch d.router.Decide(t.Host) {
	case core.RouteDirect:
		return d.direct.DialTarget(ctx, t)
	case core.RouteReject:
		return nil, core.Route{Action: core.RouteReject}, nil
	default:
		if d.pool == nil {
			return nil, core.Route{Action: core.RouteProxy, Label: "pool"}, ErrNoNodes
		}
		return d.pool.DialTarget(ctx, t)
	}
}
