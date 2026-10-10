// Package dialer 依据分流规则建立到目标的连接：直连或经出口节点隧道。
package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/OopsOo0ps/proxy/internal/nodes"
	"github.com/OopsOo0ps/proxy/internal/routing"
)

// ErrNoNodes 表示决策为“走代理”但未配置任何出口节点。
var ErrNoNodes = errors.New("dialer: no exit nodes configured")

// Route 描述一次连接的路径，用于日志与指标。
type Route struct {
	// Action 是路由决策（Direct / Proxy）。
	Action routing.Action
	// Upstream 是命中的出口节点地址；直连时为空。
	Upstream string
}

// Label 返回日志中的 upstream 标签。
func (r Route) Label() string {
	if r.Upstream != "" {
		return r.Upstream
	}
	if r.Action == routing.Proxy {
		// 连接复用时可能无法得知具体节点。
		return "pool"
	}
	return "direct"
}

// Dialer 是路由感知的出站拨号器，可安全并发使用。
type Dialer struct {
	router *routing.Engine
	pool   *nodes.Pool // 可为 nil（未配置节点，仅支持直连）
	direct *net.Dialer
}

// Options 是 Dialer 构造参数。
type Options struct {
	// Router 分流引擎（必填）。
	Router *routing.Engine
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
func (d *Dialer) RouteFor(host string) routing.Action {
	return d.router.Decide(host)
}

// DialTarget 建立到 host:port 的连接：按分流规则直连或经出口节点。
func (d *Dialer) DialTarget(ctx context.Context, host string, port uint16) (net.Conn, Route, error) {
	if d.router.Decide(host) == routing.Direct {
		addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
		conn, err := d.direct.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, Route{Action: routing.Direct}, fmt.Errorf("direct dial %s: %w", addr, err)
		}
		return conn, Route{Action: routing.Direct}, nil
	}

	if d.pool == nil {
		return nil, Route{Action: routing.Proxy}, ErrNoNodes
	}
	conn, node, err := d.pool.Dial(ctx, host, port)
	if err != nil {
		return nil, Route{Action: routing.Proxy}, err
	}
	return conn, Route{Action: routing.Proxy, Upstream: node.Addr}, nil
}
