// Package core 定义入站与出站之间的核心契约（L1 层，设计文档 2.1/3）。
//
// 契约锚在消费方：入站组件（httpproxy / socks5 / dnsgw）只依赖本包的接口面，
// 出站实现（*dialer.Dialer）与凭据实现（*auth.Store）凭 Go 结构化类型直接满足，
// 无需适配。依赖规则由 internal/arch 的守护测试强制：
//
//   - core 只依赖 routing（共享词汇）+ stdlib，不得依赖任何其它 internal 包；
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

	"github.com/OopsOo0ps/proxy/internal/routing"
)

// Target 是一次代理会话的目标地址。
//
// 只承载「要连哪里」：Host 是域名或 IP 字面量（IPv6 不带方括号），
// Port 为 0 值没有缺省语义，由调用方显式填入。不做继承式扩展
// （不加 Network/UDP 占位字段），UDP 会话模型等真实需求进来再议。
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

// Route 描述一次连接实际走过的路径（日志与指标词汇）。
type Route struct {
	// Action 是路由决策（Direct / Proxy）。
	Action routing.Action
	// Upstream 是命中的出口节点地址；直连时为空。
	Upstream string
}

// Label 返回日志中的 upstream 标签：节点地址 / "pool"（连接复用时无法
// 得知具体节点）/ "direct"。
func (r Route) Label() string {
	if r.Upstream != "" {
		return r.Upstream
	}
	if r.Action == routing.Proxy {
		// 连接复用时可能无法得知具体节点。
		return "pool"
	}
	return "direct"
}

// TargetDialer 是入站侧消费的出站拨号能力；*dialer.Dialer 实现。
// httpproxy 与 socks5 以它作为可注入的拨号类型——组装根的单个运行期
// 适配器用一个 Dialer() 方法同时满足两边的策略接口（见 internal/clientapp
// 的 clientLive）。
type TargetDialer interface {
	// DialTarget 建立到 t 的连接：按分流规则直连或经出口节点。
	// 返回的 Route 是本次连接的实际路径（权威值）。
	DialTarget(ctx context.Context, t Target) (net.Conn, Route, error)
	// RouteFor 返回 host 的预判路由（不含端口），仅用于日志与指标预判；
	// 规则重载窗口内可能与实际不一致，实际以 DialTarget 返回值为准。
	RouteFor(host string) routing.Action
}

// ProxyDialer 是「强制走出口」的拨号能力（DNS 网关远程解析用），
// 不做分流决策——出口是否可直连公共 DNS 服务器不应受本地分流规则影响。
type ProxyDialer interface {
	// DialProxy 强制经出口节点建立到 t 的隧道连接。
	DialProxy(ctx context.Context, t Target) (net.Conn, Route, error)
}

// Authenticator 是入站凭据校验能力；*auth.Store 实现。
// 实现必须对任意输入安全可调用；「是否启用认证」由调用方在取策略时
// 以明确的 nil 判定表达（见各入站 LivePolicy 的 Auth 方法约定）。
type Authenticator interface {
	Verify(username, password string) bool
}

// —— 会话遥测词汇 ——

// proto 标签值：RequestDone / Conn* 事件来自哪个会话服务组件。
const (
	// ProtoHTTP 是 HTTP 代理入站。
	ProtoHTTP = "http"
	// ProtoSOCKS5 是 SOCKS5 入站。
	ProtoSOCKS5 = "socks5"
	// ProtoTunnel 是 Trojan 隧道（服务端）。
	ProtoTunnel = "tunnel"
)

// route 标签值：请求实际走过的路径（与 routing.Action 的字符串写法一致；
// RouteNone 表示尚未形成路由决策即终止——认证失败、目标解析失败等）。
const (
	RouteDirect = "direct"
	RouteProxy  = "proxy"
	RouteNone   = "none"
)

// result 标签值：请求结果。
const (
	ResultOK       = "ok"
	ResultAuthFail = "auth_fail"
	ResultDialFail = "dial_fail"
	ResultError    = "error"
)

// Telemetry 是会话服务组件（httpproxy / socks5 / trojan 服务端）的遥测出口；
// *metrics.Metrics 适配实现（L4 单点）。标签词汇见上方 Proto* / Route* /
// Result* 常量——事件词汇随契约归 core，Prometheus 编码归 metrics。
type Telemetry interface {
	// RequestDone 记录一次完成的请求（含失败），并观察其耗时。
	RequestDone(proto, route, result string, d time.Duration)
	// ConnOpened / ConnClosed 记录一个活跃连接的开始与结束。
	ConnOpened(proto string)
	ConnClosed(proto string)
	// ConnRejected 记录一次因超过连接上限被拒绝的连接。
	ConnRejected(proto string)
}

// NopTelemetry 是组件 Options 的缺省遥测出口：全部方法为空操作，
// 组件测试零构造、无需 registry，nil 接口判断不再需要。
var NopTelemetry Telemetry = nopTelemetry{}

type nopTelemetry struct{}

func (nopTelemetry) RequestDone(string, string, string, time.Duration) {}
func (nopTelemetry) ConnOpened(string)                                 {}
func (nopTelemetry) ConnClosed(string)                                 {}
func (nopTelemetry) ConnRejected(string)                               {}
