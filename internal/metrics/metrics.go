// Package metrics 提供 Prometheus 指标：请求计数、耗时、活跃连接与节点拨号。
//
// 核心指标名与需求 1.7 一致：
//   - requests_total（counter，标签 proto/route/result）
//   - request_duration_seconds（histogram，标签 proto/route）
//   - active_connections（gauge，标签 proto）
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
)

// Metrics 聚合全部指标。请使用 New 构造；方法对 nil 接收者安全（no-op），
// 便于在不需要指标的测试中省略构造。
type Metrics struct {
	registry *prometheus.Registry
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	active   *prometheus.GaugeVec
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
	}
	m.registry.MustRegister(m.requests, m.duration, m.active)
	m.preInitialize()
	return m
}

// preInitialize 预创建常用标签组合，保证 /metrics 在启动后（无流量时）
// 也能暴露 requests_total / request_duration_seconds / active_connections。
func (m *Metrics) preInitialize() {
	for _, proto := range []string{ProtoHTTP, ProtoSOCKS5, ProtoTunnel} {
		m.active.WithLabelValues(proto)
		for _, route := range []string{RouteDirect, RouteProxy, RouteNone} {
			m.duration.WithLabelValues(proto, route)
			for _, result := range []string{ResultOK, ResultAuthFail, ResultDialFail, ResultError} {
				m.requests.WithLabelValues(proto, route, result)
			}
		}
	}
}

// Handler 返回 /metrics 端点；nil 接收者返回 404。
func (m *Metrics) Handler() http.Handler {
	if m == nil {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
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
