// Package metrics 提供 Prometheus 指标：请求计数、耗时、活跃连接与上游连接池。
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
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// 协议标签值。
const (
	ProtoHTTP   = "http"
	ProtoSOCKS5 = "socks5"
	ProtoTunnel = "tunnel"
)

// 路由标签值。
const (
	RouteDirect = "direct"
	RouteProxy  = "proxy"
	RouteNone   = "none"
)

// 结果标签值。
const (
	ResultOK       = "ok"
	ResultAuthFail = "auth_fail"
	ResultDialFail = "dial_fail"
	ResultError    = "error"
	// ResultInvalid：DNS 网关拒绝/丢弃的非法查询（未转发给任何上游）。
	ResultInvalid = "invalid"
)

// 连接池领取结果标签值：命中 / 池内无可用连接 / 池内连接已失效。
const (
	PoolClaimHit   = "hit"
	PoolClaimMiss  = "miss"
	PoolClaimStale = "stale"
)

// 主动健康探测结果标签值。
const (
	ProbeSuccess = "success"
	ProbeFailure = "failure"
)

// 配置热加载结果标签值。
const (
	ReloadSuccess = "success"
	ReloadError   = "error"
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
	}
	m.registry.MustRegister(m.requests, m.duration, m.active, m.poolClaims, m.poolIdle, m.poolWarmFails, m.healthProbes, m.upstreamAlive, m.rejected, m.dnsQueries, m.dnsDuration, m.configReloads)
	m.preInitialize()
	return m
}

// preInitialize 预创建常用标签组合，保证 /metrics 在启动后（无流量时）
// 也能暴露 requests_total / request_duration_seconds / active_connections。
func (m *Metrics) preInitialize() {
	for _, proto := range []string{ProtoHTTP, ProtoSOCKS5, ProtoTunnel} {
		m.active.WithLabelValues(proto)
		m.rejected.WithLabelValues(proto)
		for _, route := range []string{RouteDirect, RouteProxy, RouteNone} {
			m.duration.WithLabelValues(proto, route)
			for _, result := range []string{ResultOK, ResultAuthFail, ResultDialFail, ResultError} {
				m.requests.WithLabelValues(proto, route, result)
			}
		}
	}
	for _, route := range []string{RouteDirect, RouteProxy, RouteNone} {
		for _, result := range []string{ResultOK, ResultError, ResultInvalid} {
			m.dnsQueries.WithLabelValues(route, result)
		}
	}
	for _, route := range []string{RouteDirect, RouteProxy} {
		m.dnsDuration.WithLabelValues(route)
	}
	for _, result := range []string{ReloadSuccess, ReloadError} {
		m.configReloads.WithLabelValues(result)
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

// Observe 记录一次完成的请求（含失败），并观察其耗时。
func (m *Metrics) Observe(proto, route, result string, d time.Duration) {
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

// PoolClaim 记录一次空闲连接领取结果（hit / miss / stale）。
func (m *Metrics) PoolClaim(result, node string) {
	if m == nil {
		return
	}
	m.poolClaims.WithLabelValues(node, result).Inc()
}

// SetPoolIdle 记录某出口节点当前的预热空闲连接数。
func (m *Metrics) SetPoolIdle(node string, n int) {
	if m == nil {
		return
	}
	m.poolIdle.WithLabelValues(node).Set(float64(n))
}

// PoolWarmFailed 记录一次后台预热拨号失败。
func (m *Metrics) PoolWarmFailed(node string) {
	if m == nil {
		return
	}
	m.poolWarmFails.WithLabelValues(node).Inc()
}

// HealthProbe 记录一次主动健康探测结果（ok 为 true 表示成功）。
func (m *Metrics) HealthProbe(node string, ok bool) {
	if m == nil {
		return
	}
	result := ProbeFailure
	if ok {
		result = ProbeSuccess
	}
	m.healthProbes.WithLabelValues(node, result).Inc()
}

// SetUpstreamHealthy 记录节点当前是否可接流量（1 = 可接，0 = 已被主动摘除）。
func (m *Metrics) SetUpstreamHealthy(node string, healthy bool) {
	if m == nil {
		return
	}
	v := 0.0
	if healthy {
		v = 1
	}
	m.upstreamAlive.WithLabelValues(node).Set(v)
}

// ConnRejected 记录一次因超过连接上限被拒绝的连接。
func (m *Metrics) ConnRejected(proto string) {
	if m == nil {
		return
	}
	m.rejected.WithLabelValues(proto).Inc()
}

// ObserveDNS 记录一次 DNS 网关查询（含失败与被拒绝的非法查询）。
// route 取值 direct / proxy / none；耗时直方图只按实际转发路径统计。
func (m *Metrics) ObserveDNS(route, result string, d time.Duration) {
	if m == nil {
		return
	}
	m.dnsQueries.WithLabelValues(route, result).Inc()
	if route == RouteDirect || route == RouteProxy {
		m.dnsDuration.WithLabelValues(route).Observe(d.Seconds())
	}
}

// ConfigReload 记录一次配置热加载尝试（result 取值 success / error）。
func (m *Metrics) ConfigReload(result string) {
	if m == nil {
		return
	}
	m.configReloads.WithLabelValues(result).Inc()
}
