package clientapp

import (
	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/dialer"
	"github.com/OopsOo0ps/proxy/internal/status"
)

// —— 组装（除监听绑定外零副作用）——

// assemble 依据配置构建完整运行时（不绑定监听）；reuse 非 nil 时复用未变更
// 的上游栈（节点池与预热池，指纹判定）与规则源 Provider（Spec 判定，复用时
// 立即重检）。任何失败都不产生外部副作用：本运行时新建的资源全部关闭。
func (b *builder) assemble(cfg *config.Config, reuse *Runtime) (*Runtime, error) {
	rt := &Runtime{cfg: cfg, Telemetry: b.metrics}

	table, providers, err := b.buildRouting(cfg, reuse)
	if err != nil {
		rt.closeOwned(reuse)
		return nil, err
	}
	rt.table, rt.providers = table, providers

	if err := b.buildOutbound(cfg, reuse, rt); err != nil {
		rt.closeOwned(reuse)
		return nil, err
	}
	rt.Outbound = dialer.New(dialer.Options{
		Router:      table,
		Pool:        rt.pool,
		DialTimeout: cfg.Timeouts.EffectiveDial(),
	})

	if dnsListen := dnsGatewayListen(cfg); dnsListen != "" {
		rt.dnsRemote = effectiveDNSRemote(cfg.Routing)
		rt.dnsTimeout = effectiveDNSTimeout(cfg.Routing)
		rt.dnsLocal = b.resolveDNSLocal(cfg.Routing, dnsListen)
	}

	for i := range cfg.Inbounds {
		is, err := b.buildInbound(&cfg.Inbounds[i], rt)
		if err != nil {
			rt.closeOwned(reuse)
			return nil, err
		}
		rt.Inbounds = append(rt.Inbounds, is)
	}

	rt.Admin = status.NewServer(status.ServerOptions{
		Version:  b.version,
		Start:    b.start,
		Checks:   b.healthChecks(),
		Runtime:  b.runtimeStats,
		Metrics:  b.metrics.Handler(),
		LogLevel: b.logLevelHandler(),
	})
	return rt, nil
}

// bindRuntime 绑定运行时的全部监听（入站 + 运维端点）。previous 非 nil 时，
// 与旧入站同（type, listen）的端点沿用其已解析地址（端口 0 的配置在重载后
// 保持原端口）。任何失败关闭已绑定的一切并返回错误（不变量 3）。
func (b *builder) bindRuntime(rt *Runtime, previous *Runtime) error {
	for i := range rt.Inbounds {
		hint := ""
		if previous != nil {
			hint = previous.resolvedAddrOf(rt.Inbounds[i].Config)
		}
		bound, err := rt.Inbounds[i].bind(b.limiter, hint)
		if err != nil {
			rt.closeListeners()
			return err
		}
		rt.Inbounds[i].apply(bound)
	}
	if err := rt.Admin.Bind(rt.cfg.API.Listen); err != nil {
		rt.closeListeners()
		return err
	}
	if addr := rt.cfg.API.Listen; addr != "" && !config.IsLoopbackListen(addr) {
		b.logger.Warn("ops endpoints are bound to a non-loopback address; keep them behind a firewall and note PUT /log/level stays loopback-only", "listen", addr)
	}
	return nil
}
