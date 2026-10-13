// Package defaults 是全部文档化数值缺省的唯一来源（L0 纯常量，零依赖，
// 设计文档 §5.1）。
//
// 收录规则（防它变成垃圾抽屉）：只有 **config 文档化** 或 **跨层共享** 的数值
// 进本包（超时、健康阈值、池上限与 TTL、排空期限、故障转移预算、并发上限、
// 规则源刷新周期、日志与 DNS 缺省）；包内机械细节（如 relay 的有界排空窗口、
// ruleset 的抓取超时与响应体上限）留在各自包内。
//
// config 的文档化缺省与领域包（nodes / shutdown / dnsgw / connpool 等）的
// 实现缺省引用同一常量：同一语义在任何入口（配置解析 / 直接使用库）下取值
// 相同，"两份默认值 + 一条防漂移测试" 的变通不再需要。
package defaults

import "time"

// 超时（config timeouts 段文档化；服务端握手/空闲与客户端拨号同源）。
const (
	// DialTimeout 是建立目标 / 节点连接的缺省超时。
	DialTimeout = 10 * time.Second
	// HandshakeTimeout 是握手阶段（TLS + 协议协商）的缺省超时。
	HandshakeTimeout = 10 * time.Second
	// IdleTimeout 是连接空闲回收的缺省期限。
	IdleTimeout = 90 * time.Second
	// DrainTimeout 是优雅关停排空的缺省期限。
	DrainTimeout = 15 * time.Second
)

// 出口节点池与预热池（config outbound.pool 段文档化）。
const (
	// FailoverBudget 是出口节点故障转移链的缺省总时间预算。
	FailoverBudget = 30 * time.Second
	// HealthInterval 是主动健康探测的缺省周期；0 值语义由调用方定义（关闭）。
	HealthInterval = 10 * time.Second
	// HealthTimeout 是单次健康探测的缺省超时。
	HealthTimeout = 3 * time.Second
	// HealthFailures 是节点连续探测失败多少次后被摘除的缺省阈值。
	HealthFailures = 3
	// HealthSuccesses 是摘除后连续探测成功多少次加回的缺省阈值。
	HealthSuccesses = 2
	// PrewarmSize 是每个出口节点保留的缺省预热空闲连接数；0 = 关闭。
	PrewarmSize = 2
	// PrewarmTTL 是预热空闲连接的缺省保留时长。
	PrewarmTTL = 5 * time.Second
)

// 并发背压（config limits 段文档化）。
const (
	// MaxConnections 是进程级并发连接上限的缺省值；0 = 不限制。
	MaxConnections = 1024
)

// 规则源（config routing.rulesets 段文档化）。
const (
	// RulesetRefreshInterval 是远程规则源的缺省刷新周期；0 = 仅启动拉取一次。
	RulesetRefreshInterval = 30 * time.Minute
)

// 日志（config log 段文档化）。
const (
	// LogLevel 是缺省日志级别（debug | info | warn | error）。
	LogLevel = "info"
	// LogFormat 是缺省日志格式（json | text）。
	LogFormat = "json"
)

// DNS 网关（config routing.dns 段文档化）。
const (
	// DNSRemote 是经出口节点访问的缺省远程解析服务器。
	DNSRemote = "1.1.1.1:53"
	// DNSTimeout 是单次 DNS 查询的缺省超时。
	DNSTimeout = 5 * time.Second
)
