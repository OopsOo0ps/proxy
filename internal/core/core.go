// Package core 定义入站与出站之间的核心契约（L1 层，设计文档 §4.1）。
//
// 契约锚在消费方：入站组件（httpproxy / socks5 / dnsgw）只依赖本包的接口面，
// 出站实现（*dialer.Dialer / *nodes.Pool）与凭据实现（*auth.Store）凭 Go 结构化
// 类型直接满足，无需适配。依赖规则由 internal/arch 的守护测试强制：
//
//   - core 只依赖标准库，不得依赖任何其它 internal 包；
//   - 入站包禁止 import dialer / nodes / connpool / trojan / outbound，
//     出站能力一律经本包契约触达。
//
// Target 是本包的共享词汇之一：全仓「到哪连」的统一形状，替换
// (host, port) 双参签名（参数转置在编译期即不可能）。
package core

import (
	"context"
	"net"
	"strconv"
	"time"
)

// Target 是一次代理请求的终点（全仓唯一的目的地词汇）。
//
// Host 保存客户端原始请求的域名或 IP 字面量（IPv6 不带方括号）——解析是
// 路由/出口的事，这里不做。Port 为 0 值没有缺省语义，由调用方显式填入。
// 不做继承式扩展（不加 Network/UDP 占位字段），UDP 会话模型等真实需求
// 进来再议。
type Target struct {
	// Host 是目标域名或 IP 字面量，不含端口。
	Host string
	// Port 是目标端口。
	Port uint16
}

// String 以 host:port 形式返回目标；IPv6 字面量自动加方括号
// （net.JoinHostPort 语义）。
func (t Target) String() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(int(t.Port)))
}

// RouteAction 是路由判定结果。
type RouteAction uint8

const (
	// RouteDirect 表示目标本机直连。
	RouteDirect RouteAction = iota
	// RouteProxy 表示目标经由出口节点转发。
	RouteProxy
	// RouteReject 表示路由判定为拒绝：入站按协议回拒绝响应。
	RouteReject
)

// String 返回动作的观测写法（metrics 标签与日志的 route 字段由此派生）。
func (a RouteAction) String() string {
	switch a {
	case RouteDirect:
		return "direct"
	case RouteProxy:
		return "proxy"
	case RouteReject:
		return "reject"
	default:
		return "unknown"
	}
}

// Route 是一次连接实际走过的路径（权威值，不变量 6）。
// Label 词汇：Direct 时空串；Proxy 时为出口标签（节点名，池选择未定时
// 为 "pool"，回退由生产方在构造时填入）。
type Route struct {
	// Action 是路由判定结果。
	Action RouteAction
	// Label 是出口标签；Direct 时空串。
	Label string
}

// TargetDialer 把一条双向字节流接到 Target：入站消费出站的唯一接口，
// 且天然可组合——路由分派器、直连拨号器、节点池都是 TargetDialer
// （组合树见设计文档 §5.3）。
//
// 返回的 Route 是权威路径：入站拿它填日志与遥测，不得自行推断上游。
type TargetDialer interface {
	// DialTarget 建立到 t 的连接；判定为拒绝时返回 Action 为 RouteReject
	// 的 Route（调用方按协议回拒绝响应）。
	DialTarget(ctx context.Context, t Target) (net.Conn, Route, error)
}

// Authenticator 是入站认证的消费方锚点接口。
// 实现方（auth 包）以结构化类型满足它，无需 import core。
type Authenticator interface {
	Authenticate(username, password string) bool
}

// —— 事件词汇常量（唯一来源）。新增入站协议 = 加一个 Proto 常量，
// metrics 预初始化、入站套件断言、日志口径读同一常量，不会漏。

const (
	// ProtoHTTP 是 HTTP 代理入站。
	ProtoHTTP = "http"
	// ProtoSOCKS5 是 SOCKS5 入站。
	ProtoSOCKS5 = "socks5"
	// ProtoDNS 是 DNS 网关入站。
	ProtoDNS = "dns"
	// ProtoTunnel 是 Trojan 隧道（服务端）。
	ProtoTunnel = "tunnel"
)

// result 标签值：一条被服务连接的终态结果。
const (
	// ResultOK 表示请求成功完成。
	ResultOK = "ok"
	// ResultDenied 表示被拒绝：认证失败与路由拒绝共用。
	ResultDenied = "denied"
	// ResultDialFail 表示出站建立失败。
	ResultDialFail = "dial_fail"
	// ResultError 表示其余失败。
	ResultError = "error"
	// ResultOverload 表示过载拒绝（并发上限）。
	ResultOverload = "overloaded"
)

// ConnAttrs 是一条被服务的连接的终态观测属性。
type ConnAttrs struct {
	// RequestID 是本次连接的日志关联 ID。
	RequestID string
	// ClientIP 是对端地址（不含端口）。
	ClientIP string
	// Proto 是入站协议（core.Proto*）。
	Proto string
	// Target 是请求目标。
	Target Target
	// Route 是权威路径（来自 DialTarget 返回值）。
	Route Route
	// Result 是终态结果（core.Result*）。
	Result string
	// Duration 是从接受连接到终态的耗时。
	Duration time.Duration
	// BytesUp 是客户端到目标方向的字节数。
	BytesUp int64
	// BytesDown 是目标到客户端方向的字节数。
	BytesDown int64
}

// Telemetry 是入站侧遥测锚点。三个事件恰好覆盖三类基础指标：
//   - requests_total / request_duration_seconds ← ConnDone
//   - active_connections                        ← ConnOpened 与 (ConnDone|ConnRejected) 之差
//   - connections_rejected_total                ← ConnRejected
//
// 缺省 NopTelemetry，组件测试零构造。事件发射时机全部由入站协议代码负责：
// accept 后 ConnOpened；未进入服务即被拒（过载闸/认证失败等）ConnRejected；
// 服务终态（含强制断开后的收尾）ConnDone。
type Telemetry interface {
	// ConnOpened 在 accept 成功后计（active +1）。
	ConnOpened(proto string)
	// ConnRejected 记录一次未进入服务即被拒的连接：active -1、rejected +1；
	// reason 取事件拒绝原因词汇（如 core.ResultOverload / core.ResultDenied）。
	ConnRejected(proto, reason string)
	// ConnDone 记录一次服务终态：active -1、requests/duration/result +1。
	ConnDone(a ConnAttrs)
}

// NopTelemetry 是组件 Options 的缺省遥测出口：全部方法为空操作，
// 组件测试零构造、无需 registry，nil 接口判断不再需要。
var NopTelemetry Telemetry = nopTelemetry{}

type nopTelemetry struct{}

func (nopTelemetry) ConnOpened(string)           {}
func (nopTelemetry) ConnRejected(string, string) {}
func (nopTelemetry) ConnDone(ConnAttrs)          {}
