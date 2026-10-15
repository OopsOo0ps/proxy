package clientapp

import (
	"errors"
	"net/http"
	"time"

	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/logging"
	"github.com/OopsOo0ps/proxy/internal/ruleset"
	"github.com/OopsOo0ps/proxy/internal/status"
)

// —— 可观测性接缝（/stats 与依赖健康）——

func (b *builder) logLevelHandler() http.Handler {
	if b.logCtrl == nil {
		return nil
	}
	return logging.LevelHandler(b.logger, b.logCtrl.LevelVar())
}

// healthChecks 返回依赖健康检查：配置了出口节点时，池中无健康节点视为
// 依赖不可用。
func (b *builder) healthChecks() []func() error {
	return []func() error{func() error {
		rt := b.live.Load()
		if rt == nil || rt.pool == nil {
			return nil
		}
		if rt.pool.AnyHealthy() {
			return nil
		}
		return errors.New("no healthy exit nodes available")
	}}
}

// runtimeStats 组装 /stats 快照：活跃连接数与出口节点状态。
func (b *builder) runtimeStats() status.Runtime {
	rt := b.live.Load()
	var out status.Runtime
	if rt == nil {
		return out
	}
	active := b.metrics.ActiveByProto()
	httpConns := active[core.ProtoHTTP]
	socksConns := active[core.ProtoSOCKS5]
	out = status.Runtime{
		Connections: status.Connections{
			HTTP:   httpConns,
			SOCKS5: socksConns,
			Total:  httpConns + socksConns,
		},
	}
	if rt.pool != nil {
		idle := rt.pool.IdleCounts()
		for _, n := range rt.pool.Snapshot() {
			out.Upstreams = append(out.Upstreams, status.Upstream{
				Addr:              n.Addr,
				Healthy:           n.Healthy,
				Fails:             n.Fails,
				CooldownRemaining: status.Seconds(n.CooldownRemaining),
				Removed:           n.Removed,
				ProbeFails:        n.ProbeFails,
				Idle:              idle[n.Addr],
			})
		}
	}
	if len(rt.providers) > 0 {
		if snap := rt.providers[0].Snapshot(); snap.Source != ruleset.SourceNone {
			out.Ruleset = &status.Ruleset{
				Source:    snap.Source.String(),
				Target:    snap.Target,
				Refresh:   status.Seconds(snap.Interval),
				Loaded:    snap.Loaded,
				Rules:     snap.Rules,
				LastError: snap.LastError,
			}
			if !snap.LastSuccess.IsZero() {
				out.Ruleset.LastSuccess = snap.LastSuccess.UTC().Format(time.RFC3339)
			}
		}
	}
	// 0 = 不限制时不输出 limit 字段（与 README 描述一致）。
	if b.limiter != nil && b.limiter.Max() > 0 {
		out.Limit = &status.Limit{
			MaxConnections: b.limiter.Max(),
			Current:        b.limiter.Active(),
			Rejected:       b.limiter.Rejected(),
		}
	}
	return out
}
