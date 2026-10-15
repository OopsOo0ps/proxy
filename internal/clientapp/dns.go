package clientapp

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/defaults"
	"github.com/OopsOo0ps/proxy/internal/dialer"
	"github.com/OopsOo0ps/proxy/internal/dnsgw"
)

// —— DNS 网关的动态参数与剪枝 ——

func dnsGatewayListen(cfg *config.Config) string {
	for i := range cfg.Inbounds {
		if cfg.Inbounds[i].Type == config.TypeDNS {
			return cfg.Inbounds[i].Listen
		}
	}
	return ""
}

func effectiveDNSRemote(r *config.Routing) string {
	if r == nil || r.DNS == nil {
		return defaults.DNSRemote
	}
	return r.DNS.EffectiveRemote()
}

func effectiveDNSTimeout(r *config.Routing) time.Duration {
	if r == nil || r.DNS == nil {
		return defaults.DNSTimeout
	}
	return r.DNS.EffectiveTimeout()
}

// resolveDNSLocal 返回生效的直连解析器列表；未显式配置时读取系统
// resolv.conf（读取失败或无可用条目时告警并保持为空，与既有启动行为一致）。
func (b *builder) resolveDNSLocal(r *config.Routing, dnsListen string) []string {
	if r != nil && r.DNS != nil && len(r.DNS.Local) > 0 {
		return append([]string(nil), r.DNS.Local...)
	}
	path := dnsgw.DefaultResolvConfPath
	resolved, err := dnsgw.LocalResolversFromResolvConf(path, dnsListen)
	switch {
	case err != nil:
		b.logger.Warn("dns gateway: cannot read system resolvers, direct-routed names will fail",
			"path", path, "error", err)
		return nil
	case len(resolved) == 0:
		b.logger.Warn("dns gateway: no usable system resolvers found, direct-routed names will fail",
			"path", path, "hint", "set routing.dns.local explicitly")
		return nil
	default:
		b.logger.Info("dns gateway: using system resolvers for direct-routed names",
			"path", path, "resolvers", resolved)
		return resolved
	}
}

// dnsRouter 把当前快照的分流表适配为 dnsgw 的查询判定（DNS 走哪条路 =
// 流量走哪条路）：core.Target 承载查询名（Port 无语义）。
type dnsRouter struct{ live *atomic.Pointer[Runtime] }

func (r dnsRouter) Decide(t core.Target) core.Route {
	rt := r.live.Load()
	if rt == nil || rt.table == nil {
		return core.Route{Action: core.RouteProxy}
	}
	return core.Route{Action: rt.table.Decide(t.Host)}
}

// dnsDirectDialer 是 DNS 网关的直连剪枝（本地解析路径）：对本地解析器的
// UDP 拨号，超时跟随当前快照。
type dnsDirectDialer struct{ live *atomic.Pointer[Runtime] }

func (d dnsDirectDialer) DialTarget(ctx context.Context, t core.Target) (net.Conn, core.Route, error) {
	timeout := defaults.DNSTimeout
	if rt := d.live.Load(); rt != nil && rt.dnsTimeout > 0 {
		timeout = rt.dnsTimeout
	}
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "udp", t.String())
	return conn, core.Route{Action: core.RouteDirect}, err
}

// dnsTunnelDialer 是 DNS 网关的代理剪枝（远端解析路径）：不经分流，一律经
// 当前快照的出口节点池（同一棵组合树的池子树，返回权威路径 Route{Proxy}）。
type dnsTunnelDialer struct{ live *atomic.Pointer[Runtime] }

func (d dnsTunnelDialer) DialTarget(ctx context.Context, t core.Target) (net.Conn, core.Route, error) {
	rt := d.live.Load()
	if rt == nil || rt.pool == nil {
		return nil, core.Route{Action: core.RouteProxy, Label: "pool"}, dialer.ErrNoNodes
	}
	return rt.pool.DialTarget(ctx, t)
}
