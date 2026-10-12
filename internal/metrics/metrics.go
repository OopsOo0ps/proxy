// Package metrics 是全部组件遥测的单点 Prometheus 适配层（L4）：
// 组件定义各自的 Observer 窄接口并发出领域事件（词汇常量随事件归属组件
// 与 core 契约），本包把它们编码为指标。
//
// 核心指标名与需求 1.7 / 2.3 一致：
//   - requests_total（counter，标签 proto/route/result）
//   - request_duration_seconds（histogram，标签 proto/route）
//   - active_connections（gauge，标签 proto）
//   - upstream_pool_claims_total（counter，标签 node/result）
//   - upstream_pool_idle_connections（gauge，标签 node）
//   - upstream_pool_warm_failures_total（counter，标签 node）
//   - upstream_health_probes_total（counter，标签 node/result）：主动健康探测（路线图 3.3）
//   - upstream_healthy（gauge，标签 node）：节点当前是否可接流量（0 = 已被摘除）
//   - connections_rejected_total（counter，标签 proto）：超过连接上限被拒绝的连接
//   - dns_queries_total（counter，标签 route/result）与 dns_query_duration_seconds
//     （histogram，标签 route）：DNS 网关查询（路线图 3.1）
//   - config_reloads_total（counter，标签 result）：配置热加载次数（路线图 3.2）
//   - ruleset_refreshes_total（counter，标签 result）：规则集加载 / 刷新次数（路线图 3.4）
//   - ruleset_last_success_timestamp_seconds（gauge）：最近一次成功加载规则的时间戳
//   - ruleset_rules（gauge）：当前生效的规则条数
package metrics

import (
	"net/http"
	"time"

	"github.com/OopsOo0ps/proxy/internal/connpool"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/dnsgw"
	"github.com/OopsOo0ps/proxy/internal/nodes"
	"github.com/OopsOo0ps/proxy/internal/ruleset"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// 配置热加载结果标签值（ConfigReload 事件归属组装根本包层级，词汇随事件
// 留在 metrics；其余事件词汇见各组件包与 core）。
const (
	ReloadSuccess = "success"
	ReloadError   = "error"
)

// 编译期断言：*Metrics 满足全部组件 Observer 契约（唯一 Prometheus 适配点）。
// 换观测后端 = 写一个新适配器，L0–L3 组件零改动。
var (
	_ core.Telemetry    = (*Metrics)(nil)
	_ dnsgw.DNSObserver = (*Metrics)(nil)
	_ nodes.Observer    = (*Metrics)(nil)
	_ connpool.Observer = (*Metrics)(nil)
	_ ruleset.Observer  = (*Metrics)(nil)
)

// Metrics 聚合全部指标。请使用 New 构造；方法对 nil 接收者安全（no-op），
// 便于在不需要指标的测试中省略构造。
type Metrics struct {
	registry      *prometheus.Registry
	requests      *prometheus.CounterVec
	duration      *prometheus.HistogramVec
	active        *prometheus.GaugeVec
	poolClaims    *prometheus.CounterVec
	poolIdle      *prometheus.GaugeVec
	poolWarmFails *prometheus.CounterVec
	healthProbes  *prometheus.CounterVec
	upstreamAlive *prometheus.GaugeVec
	rejected      *prometheus.CounterVec
	dnsQueries    *prometheus.CounterVec
	dnsDuration   *prometheus.HistogramVec
	configReloads *prometheus.CounterVec

	rulesetRefreshes   *prometheus.CounterVec
	rulesetLastSuccess prometheus.Gauge
	rulesetRules       prometheus.Gauge
}

// New 创建独立的指标集合（使用私有 registry，不污染全局默认值）。
func New() *Metrics {
	m := &Metrics{
		registry: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "requests_total",
			Help: "Total number of proxy requests handled.",
		}, []string{"proto", "route", "result"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "request_duration_seconds",
			Help:    "Proxy request duration in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"proto", "route"}),
		active: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "active_connections",
			Help: "Number of currently active connections.",
		}, []string{"proto"}),
		poolClaims: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "upstream_pool_claims_total",
			Help: "Total number of idle upstream connection claims by result (hit/miss/stale).",
		}, []string{"node", "result"}),
		poolIdle: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "upstream_pool_idle_connections",
			Help: "Number of idle pre-warmed upstream connections per node.",
		}, []string{"node"}),
		poolWarmFails: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "upstream_pool_warm_failures_total",
			Help: "Total number of background warm-up dial failures per node.",
		}, []string{"node"}),
		healthProbes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "upstream_health_probes_total",
			Help: "Total number of active health probes per node by result (success/failure).",
		}, []string{"node", "result"}),
		upstreamAlive: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "upstream_healthy",
			Help: "Whether an exit node currently accepts traffic (1 = healthy, 0 = removed by health check).",
		}, []string{"node"}),
		rejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "connections_rejected_total",
			Help: "Total number of connections rejected due to the configured connection limit.",
		}, []string{"proto"}),
		dnsQueries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dns_queries_total",
			Help: "Total number of DNS gateway queries by route and result.",
		}, []string{"route", "result"}),
		dnsDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "dns_query_duration_seconds",
			Help:    "DNS gateway query duration in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"route"}),
		configReloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "config_reloads_total",
			Help: "Total number of configuration reload attempts by result (success/error).",
		}, []string{"result"}),
		rulesetRefreshes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ruleset_refreshes_total",
			Help: "Total number of rule set load/refresh attempts by result (success/unchanged/error).",
		}, []string{"result"}),
		rulesetLastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ruleset_last_success_timestamp_seconds",
			Help: "Unix timestamp of the last successful rule set load.",
		}),
		rulesetRules: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ruleset_rules",
			Help: "Number of rules in the currently active rule set.",
		}),
	}
	m.registry.MustRegister(m.requests, m.duration, m.active, m.poolClaims, m.poolIdle, m.poolWarmFails, m.healthProbes, m.upstreamAlive, m.rejected, m.dnsQueries, m.dnsDuration, m.configReloads, m.rulesetRefreshes, m.rulesetLastSuccess, m.rulesetRules)
	m.preInitialize()
	return m
}

// preInitialize 预创建常用标签组合，保证 /metrics 在启动后（无流量时）
// 也能暴露 requests_total / request_duration_seconds / active_connections。
func (m *Metrics) preInitialize() {
	for _, proto := range []string{core.ProtoHTTP, core.ProtoSOCKS5, core.ProtoTunnel} {
		m.active.WithLabelValues(proto)
		m.rejected.WithLabelValues(proto)
		for _, route := range []string{core.RouteDirect, core.RouteProxy, core.RouteNone} {
			m.duration.WithLabelValues(proto, route)
			for _, result := range []string{core.ResultOK, core.ResultAuthFail, core.ResultDialFail, core.ResultError} {
				m.requests.WithLabelValues(proto, route, result)
			}
		}
	}
	for _, route := range []string{core.RouteDirect, core.RouteProxy, core.RouteNone} {
		for _, result := range []string{core.ResultOK, core.ResultError, dnsgw.ResultInvalid} {
			m.dnsQueries.WithLabelValues(route, result)
		}
	}
	for _, route := range []string{core.RouteDirect, core.RouteProxy} {
		m.dnsDuration.WithLabelValues(route)
	}
	for _, result := range []string{ReloadSuccess, ReloadError} {
		m.configReloads.WithLabelValues(result)
	}
	for _, result := range []string{ruleset.RefreshSuccess, ruleset.RefreshUnchanged, ruleset.RefreshError} {
		m.rulesetRefreshes.WithLabelValues(result)
	}
}

// Handler 返回 /metrics 端点；nil 接收者返回 404。
func (m *Metrics) Handler() http.Handler {
	if m == nil {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// ActiveByProto 返回按协议统计的活跃连接数快照；nil 接收者返回 nil。
// 数据直接取自注册表，保证与 /metrics 暴露的值一致。
func (m *Metrics) ActiveByProto() map[string]int64 {
	if m == nil {
		return nil
	}
	families, err := m.registry.Gather()
	if err != nil {
		return nil
	}
	out := make(map[string]int64)
	for _, family := range families {
		if family.GetName() != "active_connections" {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "proto" {
					out[label.GetValue()] = int64(metric.GetGauge().GetValue())
				}
			}
		}
	}
	return out
}

// —— core.Telemetry 适配（httpproxy / socks5 / trojan 服务端） ——

// RequestDone 记录一次完成的请求（含失败），并观察其耗时。
// proto/route/result 取 core 的遥测词汇常量。
func (m *Metrics) RequestDone(proto, route, result string, d time.Duration) {
	if m == nil {
		return
	}
	m.requests.WithLabelValues(proto, route, result).Inc()
	m.duration.WithLabelValues(proto, route).Observe(d.Seconds())
}

// ConnOpened 记录一个活跃连接开始。
func (m *Metrics) ConnOpened(proto string) {
	if m == nil {
		return
	}
	m.active.WithLabelValues(proto).Inc()
}

// ConnClosed 记录一个活跃连接结束。
func (m *Metrics) ConnClosed(proto string) {
	if m == nil {
		return
	}
	m.active.WithLabelValues(proto).Dec()
}

// ConnRejected 记录一次因超过连接上限被拒绝的连接。
func (m *Metrics) ConnRejected(proto string) {
	if m == nil {
		return
	}
	m.rejected.WithLabelValues(proto).Inc()
}

// —— dnsgw.DNSObserver 适配 ——

// QueryDone 记录一次 DNS 网关查询（含失败与被拒绝的非法查询）。
// route 取 core 的遥测词汇（direct / proxy / none）；耗时直方图只按
// 实际转发路径统计。
func (m *Metrics) QueryDone(route, result string, d time.Duration) {
	if m == nil {
		return
	}
	m.dnsQueries.WithLabelValues(route, result).Inc()
	if route == core.RouteDirect || route == core.RouteProxy {
		m.dnsDuration.WithLabelValues(route).Observe(d.Seconds())
	}
}

// —— nodes.Observer 适配 ——

// ProbeResult 记录一次主动健康探测结果（ok 为 true 表示成功）。
func (m *Metrics) ProbeResult(node string, ok bool) {
	if m == nil {
		return
	}
	result := nodes.ProbeFailure
	if ok {
		result = nodes.ProbeSuccess
	}
	m.healthProbes.WithLabelValues(node, result).Inc()
}

// HealthChanged 记录节点当前是否可接流量（1 = 可接，0 = 已被主动摘除）。
func (m *Metrics) HealthChanged(node string, healthy bool) {
	if m == nil {
		return
	}
	v := 0.0
	if healthy {
		v = 1
	}
	m.upstreamAlive.WithLabelValues(node).Set(v)
}

// —— connpool.Observer 适配 ——

// ClaimResult 记录一次空闲连接领取结果（result 取 connpool 的 Claim* 词汇）。
func (m *Metrics) ClaimResult(node, result string) {
	if m == nil {
		return
	}
	m.poolClaims.WithLabelValues(node, result).Inc()
}

// IdleSet 记录某出口节点当前的预热空闲连接数。
func (m *Metrics) IdleSet(node string, n int) {
	if m == nil {
		return
	}
	m.poolIdle.WithLabelValues(node).Set(float64(n))
}

// WarmFailed 记录一次后台预热拨号失败。
func (m *Metrics) WarmFailed(node string) {
	if m == nil {
		return
	}
	m.poolWarmFails.WithLabelValues(node).Inc()
}

// —— ruleset.Observer 适配 ——

// Refresh 记录一次规则集加载 / 刷新尝试（result 取 ruleset 的 Refresh* 词汇）。
func (m *Metrics) Refresh(result string) {
	if m == nil {
		return
	}
	m.rulesetRefreshes.WithLabelValues(result).Inc()
}

// SetLastSuccess 记录最近一次成功加载规则的时间戳（Unix 秒）；零值忽略。
func (m *Metrics) SetLastSuccess(t time.Time) {
	if m == nil || t.IsZero() {
		return
	}
	m.rulesetLastSuccess.Set(float64(t.Unix()))
}

// SetRules 记录当前生效的规则条数。
func (m *Metrics) SetRules(n int) {
	if m == nil {
		return
	}
	m.rulesetRules.Set(float64(n))
}

// —— 组装根直接使用（不经过 Observer 契约） ——

// ConfigReload 记录一次配置热加载尝试（result 取值 ReloadSuccess / ReloadError）。
func (m *Metrics) ConfigReload(result string) {
	if m == nil {
		return
	}
	m.configReloads.WithLabelValues(result).Inc()
}
