// Package metrics 是全部组件遥测的单点 Prometheus 适配层（L4）：
// 组件定义各自的 Observer 窄接口并发出领域事件（词汇常量随事件归属组件
// 与 core 契约），本包把它们编码为指标。
//
// 核心指标名与需求 1.7 / 2.3 一致：
//   - requests_total（counter，标签 proto/route/result）
//   - request_duration_seconds（histogram，标签 proto/route）
//   - active_connections（gauge，标签 proto）：active = ConnOpened − (ConnDone+ConnRejected)
//   - upstream_pool_claims_total（counter，标签 node/result）
//   - upstream_pool_idle_connections（gauge，标签 node）
//   - upstream_pool_warm_failures_total（counter，标签 node）
//   - upstream_health_probes_total（counter，标签 node/result）：主动健康探测（路线图 3.3）
//   - upstream_healthy（gauge，标签 node）：节点当前是否可接流量（0 = 已被摘除）
//   - connections_rejected_total（counter，标签 proto）：未进入服务即被拒的连接
//     （过载闸 / 认证失败等；拒绝原因不作为指标维度）
//   - entitlement_decisions_total（counter，标签 decision/reason）：订阅门禁判定
//     （设计书 §3.1/§6.2；decision ∈ {allow, deny}，reason 为存储期拒绝原因
//     有限枚举，allow 恒记 none；按用户粒度的标签明确不做）
//   - dns_queries_total（counter，标签 route/result）与 dns_query_duration_seconds
//     （histogram，标签 route）：DNS 网关查询（路线图 3.1）
//   - config_reloads_total（counter，标签 result）：配置热加载次数（路线图 3.2）
//   - ruleset_refreshes_total（counter，标签 result）：规则集加载 / 刷新次数（路线图 3.4）
//   - ruleset_last_success_timestamp_seconds（gauge）：最近一次成功加载规则的时间戳
//   - ruleset_rules（gauge）：当前生效的规则条数
package metrics

import (
	"net/http"
	"slices"
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

// 订阅门禁决策词汇（设计书 §3.1/§6.2，EntitlementDecision 事件归属组装根的
// 门禁接线点）。decision ∈ {allow, deny}；reason 为存储期拒绝原因有限枚举，
// 词汇属主是 internal/accounts 的 RejectReason——metrics 触达不了 accounts
// （ProtocolPkgs 领域词汇 allowlist），枚举值在此按值复写，一致性由 serverapp
// 的计数装饰器测试（全原因逐路径驱动）钉住。allow 恒记 reason=none。
const (
	EntitlementDecisionAllow = "allow"
	EntitlementDecisionDeny  = "deny"
)

// 门禁拒绝原因标签值（与 accounts.RejectReason 逐字对应）。
const (
	EntitlementReasonNone           = "none"
	EntitlementReasonUnknownUser    = "unknown_user"
	EntitlementReasonBadCredentials = "bad_credentials"
	EntitlementReasonDisabled       = "disabled"
	EntitlementReasonNoSubscription = "no_subscription"
	EntitlementReasonExpired        = "expired"
	EntitlementReasonClockRollback  = "clock_rollback"
)

// entitlementDenyReasons 是 deny 决策的 reason 有限枚举（preInitialize 用：
// 启动后 /metrics 即有全枚举序列，无序列空洞）。
var entitlementDenyReasons = []string{
	EntitlementReasonUnknownUser,
	EntitlementReasonBadCredentials,
	EntitlementReasonDisabled,
	EntitlementReasonNoSubscription,
	EntitlementReasonExpired,
	EntitlementReasonClockRollback,
}

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
	entitlements  *prometheus.CounterVec
	dnsQueries    *prometheus.CounterVec
	dnsDuration   *prometheus.HistogramVec
	configReloads *prometheus.CounterVec

	rulesetRefreshes   *prometheus.CounterVec
	rulesetLastSuccess prometheus.Gauge
	rulesetRules       prometheus.Gauge
}

// New 创建独立的指标集合（使用私有 registry，不污染全局默认值）。
// enabledProtos 是组装根传入的已启用入站协议集合（core.Proto* 常量）：
// 常用标签组合按集合预初始化，零流量时 /metrics 也有时间序列
// （client 传实际启用的入站，server 传 {core.ProtoTunnel}）。
func New(enabledProtos []string) *Metrics {
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
		entitlements: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "entitlement_decisions_total",
			Help: "Total number of subscription gate decisions by decision (allow/deny) and storage-period reject reason (allow is always reason=none).",
		}, []string{"decision", "reason"}),
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
	m.registry.MustRegister(m.requests, m.duration, m.active, m.poolClaims, m.poolIdle, m.poolWarmFails, m.healthProbes, m.upstreamAlive, m.rejected, m.entitlements, m.dnsQueries, m.dnsDuration, m.configReloads, m.rulesetRefreshes, m.rulesetLastSuccess, m.rulesetRules)
	m.preInitialize(enabledProtos)
	return m
}

// preInitialize 预创建常用标签组合，保证 /metrics 在启动后（无流量时）
// 也能暴露 requests_total / request_duration_seconds / active_connections。
// proto 集合来自组装根（按配置的入站集合）；DNS 网关序列仅在启用 dns 入站时
// 预初始化；重载与规则源序列与协议无关，恒初始化。
func (m *Metrics) preInitialize(enabledProtos []string) {
	for _, proto := range enabledProtos {
		m.active.WithLabelValues(proto)
		m.rejected.WithLabelValues(proto)
		for _, route := range []string{
			core.RouteDirect.String(), core.RouteProxy.String(), core.RouteReject.String(),
		} {
			m.duration.WithLabelValues(proto, route)
			for _, result := range []string{core.ResultOK, core.ResultDenied, core.ResultDialFail, core.ResultError} {
				m.requests.WithLabelValues(proto, route, result)
			}
		}
	}
	if slices.Contains(enabledProtos, core.ProtoDNS) {
		for _, route := range []string{core.RouteDirect.String(), core.RouteProxy.String(), ""} {
			// overloaded：UDP 查询闸超限丢弃（route 维度留空）。
			for _, result := range []string{core.ResultOK, core.ResultError, dnsgw.ResultInvalid, core.ResultOverload} {
				m.dnsQueries.WithLabelValues(route, result)
			}
		}
		// reject/denied：路由拒绝（REFUSED，不发给上游）恒成对出现，单列精确序列，
		// 避免全叉积造出 reject×ok 等永不出现的空序列。
		m.dnsQueries.WithLabelValues(core.RouteReject.String(), core.ResultDenied)
		for _, route := range []string{core.RouteDirect.String(), core.RouteProxy.String()} {
			m.dnsDuration.WithLabelValues(route)
		}
	}
	for _, result := range []string{ReloadSuccess, ReloadError} {
		m.configReloads.WithLabelValues(result)
	}
	// 订阅门禁决策序列（有限枚举，协议无关恒初始化）：allow 恒记 none，
	// deny 按存储期拒绝原因逐枚举预建。
	m.entitlements.WithLabelValues(EntitlementDecisionAllow, EntitlementReasonNone)
	for _, reason := range entitlementDenyReasons {
		m.entitlements.WithLabelValues(EntitlementDecisionDeny, reason)
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

// ConnOpened 记录一个活跃连接开始（active +1）。
func (m *Metrics) ConnOpened(proto string) {
	if m == nil {
		return
	}
	m.active.WithLabelValues(proto).Inc()
}

// ConnRejected 记录一次未进入服务即被拒的连接：active -1、rejected +1。
// reason 取事件拒绝原因词汇（core.ResultOverload / core.ResultDenied 等），
// 计数维度只有 proto（拒绝原因用于日志与排查，指标不为其扩维）。
func (m *Metrics) ConnRejected(proto, reason string) {
	if m == nil {
		return
	}
	m.active.WithLabelValues(proto).Dec()
	m.rejected.WithLabelValues(proto).Inc()
}

// ConnDone 记录一次服务终态：active -1、requests/duration +1。
// route 标签从 ConnAttrs 的权威 Route 字段派生（不变量 6）：Label 为
// "pool"（池选择未定，如上游连接复用）时记 "pool"，其余取动作的观测写法
// （direct / proxy / reject）。入站保证 ConnDone 只携带拨号产物、明确的路由
// 判定或未定标记；未进入服务的终态（认证失败、过载等）走 ConnRejected，
// 不经本方法，因此不会把零值 Route 伪造成真实直连路径。
func (m *Metrics) ConnDone(a core.ConnAttrs) {
	if m == nil {
		return
	}
	route := RouteLabel(a.Route)
	m.requests.WithLabelValues(a.Proto, route, a.Result).Inc()
	m.duration.WithLabelValues(a.Proto, route).Observe(a.Duration.Seconds())
	m.active.WithLabelValues(a.Proto).Dec()
}

// RouteLabel 从权威 Route 派生 route 观测标签（requests_total /
// request_duration_seconds / dns 口径共用）。Label 为 "pool"（池选择未定）
// 时原样使用，其余取动作的观测写法。
func RouteLabel(r core.Route) string {
	if r.Label == "pool" {
		return "pool"
	}
	return r.Action.String()
}

// —— dnsgw.DNSObserver 适配 ——

// QueryDone 记录一次 DNS 网关查询（含失败与被拒绝的非法查询）。
// route 取 core.RouteAction 的观测写法（direct / proxy）；非法查询（未转发
// 给任何上游）路由维度留空，耗时直方图只按实际转发路径统计。
func (m *Metrics) QueryDone(route, result string, d time.Duration) {
	if m == nil {
		return
	}
	m.dnsQueries.WithLabelValues(route, result).Inc()
	if route == core.RouteDirect.String() || route == core.RouteProxy.String() {
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

// EntitlementDecision 记录一次订阅门禁判定（设计书 §3.1 可观测性）：由组装根
// 的门禁计数装饰器在决策点上报（trojan.Verifier 契约只暴露 (user, ok)，原因
// 细分经判定明细 API 取回——accounts 不 import metrics）。decision 取值
// EntitlementDecisionAllow / EntitlementDecisionDeny；reason 为有限枚举
// （deny 记存储期拒绝原因，allow 恒记 EntitlementReasonNone）。
func (m *Metrics) EntitlementDecision(decision, reason string) {
	if m == nil {
		return
	}
	m.entitlements.WithLabelValues(decision, reason).Inc()
}
