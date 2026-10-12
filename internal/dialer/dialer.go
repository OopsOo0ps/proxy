// Package dialer 依据分流规则建立到目标的连接：直连或经出口节点隧道。
package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/nodes"
	"github.com/OopsOo0ps/proxy/internal/routing"
)

// ErrNoNodes 表示决策为“走代理”但未配置任何出口节点。
var ErrNoNodes = errors.New("dialer: no exit nodes configured")

// 编译期断言：*Dialer 满足 core 契约，接口漂移在构建期暴露。
var (
	_ core.TargetDialer = (*Dialer)(nil)
	_ core.ProxyDialer  = (*Dialer)(nil)
)

// Router 是拨号前的分流决策器：*routing.Engine（静态规则）与
// *ruleset.Provider（含远程刷新的动态规则源）都满足该接口。
type Router interface {
	Decide(host string) routing.Action
}

// Dialer 是路由感知的出站拨号器，实现 core.TargetDialer 与 core.ProxyDialer
// （入站组件只见 core 契约，实现细节不出本包），可安全并发使用。
type Dialer struct {
	router Router
	pool   *nodes.Pool // 可为 nil（未配置节点，仅支持直连）
	direct *net.Dialer
}

// Options 是 Dialer 构造参数。
type Options struct {
	// Router 分流引擎（必填）。
	Router Router
	// Pool 出口节点池；为空时仅能直连。
	Pool *nodes.Pool
	// DialTimeout 连接超时，默认 10s。
	DialTimeout time.Duration
}

// New 构建拨号器。
func New(opts Options) *Dialer {
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 10 * time.Second
	}
	return &Dialer{
		router: opts.Router,
		pool:   opts.Pool,
		direct: &net.Dialer{Timeout: opts.DialTimeout},
	}
}

// RouteFor 返回 host 的路由决策（不含端口），用于指标与日志预判。
// 仅是预判：规则重载窗口内可能与实际不一致，权威路径以 DialTarget
// 返回的 core.Route 为准。
func (d *Dialer) RouteFor(host string) routing.Action {
	return d.router.Decide(host)
}

// DialTarget 建立到 t 的连接：按分流规则直连或经出口节点。
func (d *Dialer) DialTarget(ctx context.Context, t core.Target) (net.Conn, core.Route, error) {
	if d.router.Decide(t.Host) == routing.Direct {
		addr := t.String()
		conn, err := d.direct.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, core.Route{Action: routing.Direct}, fmt.Errorf("direct dial %s: %w", addr, err)
		}
		return conn, core.Route{Action: routing.Direct}, nil
	}
	return d.DialProxy(ctx, t)
}

// DialProxy 强制经出口节点建立到 t 的隧道连接（不做分流决策）。
// DNS 网关用它把解析请求固定送往出口（remote DNS）——出口是否可直连
// 公共 DNS 服务器不应受本地分流规则影响。
func (d *Dialer) DialProxy(ctx context.Context, t core.Target) (net.Conn, core.Route, error) {
	if d.pool == nil {
		return nil, core.Route{Action: routing.Proxy}, ErrNoNodes
	}
	conn, node, err := d.pool.Dial(ctx, t)
	if err != nil {
		return nil, core.Route{Action: routing.Proxy}, err
	}
	return conn, core.Route{Action: routing.Proxy, Upstream: node.Addr}, nil
}
