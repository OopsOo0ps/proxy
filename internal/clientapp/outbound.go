package clientapp

import (
	"context"
	"fmt"
	"time"

	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/nodes"
	"github.com/OopsOo0ps/proxy/internal/outbound"
	"github.com/OopsOo0ps/proxy/internal/routing"
	"github.com/OopsOo0ps/proxy/internal/ruleset"
)

// —— 分流与出站 ——

// buildRouting 构建分流判定组合表：内联静态规则 + 规则源 Provider（至多
// 一个，schema 层已校验）按声明顺序匹配；私网直连是前置硬规则；缺省动作 =
// 规则源文档 default > 内联 default > proxy（与既有语义一致：规则文档的
// default 覆盖配置缺省）。reuse 非 nil 时按规则源 Spec 复用 Provider 并立即
// 重检（本地文件严格重读、远程 URL 容错重拉）。
func (b *builder) buildRouting(cfg *config.Config, reuse *Runtime) (*routeTable, []*ruleset.Provider, error) {
	privateDirect := cfg.Routing.EffectivePrivateDirect()

	var static *routing.Engine
	if cfg.Routing != nil && len(cfg.Routing.Rules) > 0 {
		engineRules := &routing.Rules{}
		for _, r := range cfg.Routing.Rules {
			if r.Default != nil {
				engineRules.Default = r.Default
				continue
			}
			rr, err := r.RoutingRule()
			if err != nil {
				return nil, nil, err
			}
			engineRules.Rules = append(engineRules.Rules, rr)
		}
		engine, err := routing.NewEngine(engineRules, routing.Options{PrivateDirect: false})
		if err != nil {
			return nil, nil, fmt.Errorf("routing.rules: %w", err)
		}
		static = engine
	}

	var providers []*ruleset.Provider
	if cfg.Routing != nil && len(cfg.Routing.Rulesets) == 1 {
		rs := cfg.Routing.Rulesets[0]
		spec := rulesetSpecOf(&rs)
		var (
			prov *ruleset.Provider
			err  error
		)
		if reuse != nil && len(reuse.providers) == 1 && reuse.providers[0].Spec() == spec {
			prov = reuse.providers[0]
			if err := prov.Recheck(context.Background()); err != nil {
				return nil, nil, err
			}
		} else {
			file, url, sha256, interval := rulesetSourceOf(&rs)
			prov, err = ruleset.New(ruleset.Options{
				FilePath:        file,
				URL:             url,
				ExpectedSHA256:  sha256,
				RefreshInterval: interval,
				Parse:           config.ParseRules,
				Default:         inlineDefault(cfg.Routing),
				PrivateDirect:   privateDirect,
				Logger:          b.logger,
				Observer:        b.metrics,
				OnChange:        b.onRulesChange,
			})
			if err != nil {
				return nil, nil, err
			}
		}
		providers = append(providers, prov)
	}

	// 缺省动作：规则源文档 default > 内联 default > proxy。
	def := inlineDefault(cfg.Routing)
	for _, p := range providers {
		if d, ok := p.DocDefault(); ok {
			def = d
			break
		}
	}
	return &routeTable{privateDirect: privateDirect, static: static, providers: providers, def: def}, providers, nil
}

// inlineDefault 返回内联规则指定的缺省动作；未指定时 proxy（缺省动作与
// 未配置 routing 段的运行语义同源）。
func inlineDefault(r *config.Routing) core.RouteAction {
	if r != nil {
		for i := range r.Rules {
			if d := r.Rules[i].Default; d != nil {
				return *d
			}
		}
	}
	return core.RouteProxy
}

// rulesetSpecOf 把规则源配置映射为 ruleset 的 Spec（复用判定依据）。
func rulesetSpecOf(rs *config.Ruleset) ruleset.Spec {
	file, url, sha256, interval := rulesetSourceOf(rs)
	return ruleset.SpecOf(file, url, sha256, interval)
}

// rulesetSourceOf 把规则源配置映射为 ruleset 的来源参数。
func rulesetSourceOf(rs *config.Ruleset) (file, url, sha256 string, interval time.Duration) {
	if rs.Type == "file" {
		return rs.Path, "", "", 0
	}
	return "", rs.URL, rs.SHA256, rs.EffectiveInterval()
}

// buildOutbound 构建出口链路（节点池 + 预热池）；未配置节点时保持 nil
// （仅直连）。reuse 非 nil 且上游栈指纹未变时复用现有实例（预热连接与
// 冷却 / 摘除状态保留）；指纹变化时重建（状态重置语义，§8.2 显式成文）。
func (b *builder) buildOutbound(cfg *config.Config, reuse *Runtime, rt *Runtime) error {
	if cfg.Outbound == nil || len(cfg.Outbound.Nodes) == 0 {
		return nil
	}
	if reuse != nil && reuse.pool != nil {
		changed, err := upstreamStackChanged(reuse.cfg, cfg)
		if err != nil {
			b.logger.Warn("upstream fingerprint failed; rebuilding pools", "error", err)
		} else if !changed {
			rt.pool = reuse.pool
			return nil
		}
	}

	// 配置模型 → 节点运行时模型（nodes 包不反向依赖 config）。
	// 每节点一个传输实例：协议参数（地址、口令、TLS/SNI、超时）经
	// buildTransport 在协议构造器封闭，SHA-224 口令派生等线格式细节不出
	// 协议包；节点池只携带地址、调度权重与传输能力（nodes 彻底协议无关）。
	nodeCfgs := make([]nodes.Node, 0, len(cfg.Outbound.Nodes))
	for i := range cfg.Outbound.Nodes {
		n := cfg.Outbound.Nodes[i]
		tr, addr, err := buildTransport(n, cfg.Timeouts.EffectiveDial(), cfg.Timeouts.EffectiveHandshake())
		if err != nil {
			return fmt.Errorf("outbound.nodes[%d]: %w", i, err)
		}
		nodeCfgs = append(nodeCfgs, nodes.Node{Addr: addr, Transport: tr, Weight: n.Weight})
	}

	// 节点池拨号回退路径：预热领取未命中时走节点自身传输（预热池由
	// nodes.Pool 自持，§5.3 组合树：NodePool → 每节点 PrewarmPool）。
	poolCfg := cfg.Outbound.Pool
	health := poolCfg.Health
	opts := nodes.Options{
		Logger:   b.logger,
		Observer: b.metrics,
		// 故障转移总预算：整条候选节点的等待上限（缺省 defaults.FailoverBudget）。
		FailoverBudget: poolCfg.EffectiveFailoverBudget(),
		// 预热池参数与观测出口：连接池实例由节点池按 Prewarmer 能力自建，
		// 组装根只注入配置（config 是预热参数的唯一入口）。
		Prewarm:         nodes.PrewarmOptions{Size: poolCfg.Prewarm.EffectiveSize(), TTL: poolCfg.Prewarm.EffectiveTTL()},
		PrewarmObserver: b.metrics,
		Health: nodes.HealthOptions{
			Interval:  health.EffectiveInterval(),
			Timeout:   health.EffectiveTimeout(),
			Failures:  health.EffectiveFailures(),
			Successes: health.EffectiveSuccesses(),
		},
	}
	if opts.Health.Interval > 0 {
		// 主动探测经 Prober 能力（传输构造时已含超时参数，期限由探测循环
		// 按 Health.Timeout 收敛）；未声明探测能力的传输不做主动探测判定
		//（恒成功），健康性交由被动冷却评估。
		opts.Probe = func(ctx context.Context, node nodes.Node) error {
			prober, ok := node.Transport.(outbound.Prober)
			if !ok {
				return nil
			}
			return prober.Probe(ctx)
		}
	}
	pool, err := nodes.New(nodeCfgs, nil, opts)
	if err != nil {
		return err
	}
	rt.pool = pool
	return nil
}

// upstreamStackChanged 判断两份配置的出口链路栈是否相同：相同 ⇒ 复用现有
// 节点池与预热池；不同 ⇒ 重建。比较依据是 config.UpstreamFingerprint
// （整份子结构的哈希），不做逐字段手工列举——新增上游相关字段时指纹自动变化。
func upstreamStackChanged(oldCfg, newCfg *config.Config) (bool, error) {
	oldFP, err := config.UpstreamFingerprint(oldCfg)
	if err != nil {
		return false, err
	}
	newFP, err := config.UpstreamFingerprint(newCfg)
	if err != nil {
		return false, err
	}
	return oldFP != newFP, nil
}
