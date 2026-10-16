// 运行时快照与生命周期（设计文档 §8.2：不可变快照）。
//
// Runtime 是一次配置构建的全部产物，构造后不可变；监听绑定属于构建步骤
// （不变量 3：绑定失败关闭已打开的一切并返回错误，旧运行时零影响）。
// 重载以"完整构建新快照 → 原子切换 → 旧快照排空"流水线整体生效。
package clientapp

import (
	"context"
	"net"
	"time"

	"github.com/OopsOo0ps/proxy/internal/accounts"
	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/connlimit"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/nodes"
	"github.com/OopsOo0ps/proxy/internal/ruleset"
	"github.com/OopsOo0ps/proxy/internal/status"
)

// Runtime 是一次构建的全部产物（组装根的运行时快照）。导出字段为文档
// §8.2 的快照形状；未导出字段是快照携带的组装产物，供生命周期与 /stats
// 消费。构造后不可变：热加载产出全新快照，原子替换。
type Runtime struct {
	// Inbounds 是全部入站端点（监听已绑定，服务函数就绪）。
	Inbounds []InboundServer
	// Outbound 是出站组合树根（路由分派器，§5.3）。
	Outbound core.TargetDialer
	// Telemetry 是遥测出口（L4 metrics 适配）。
	Telemetry core.Telemetry
	// Admin 是运维端点（/metrics /health /stats /log/level）。
	Admin *status.Server

	cfg        *config.Config
	table      *routeTable
	providers  []*ruleset.Provider
	pool       *nodes.Pool // 持有预热池（§5.3：NodePool → 每节点 PrewarmPool）
	dnsRemote  string
	dnsLocal   []string
	dnsTimeout time.Duration
	// entitlement 是客户端 entitlement 门禁视图（nil = 门禁不活跃）：本次
	// 组装从管理员分发的 entitlement 文件只读加载，注入各 http/socks5 入站
	// 的 liveView 与静态凭据复合（设计书 §3.1 客户端行；重载时整份重建）。
	entitlement *accounts.GateView
}

// InboundServer 是构建完成的一个入站端点：协议端点就绪，监听由绑定步骤
// 接入。Serve / Close / Addr 在绑定前为空操作，绑定后即可用。
type InboundServer struct {
	// Proto 是观测口径（core.Proto*）。
	Proto string
	// Config 是入站配置快照：同端口重绑与失败恢复按它重建监听。
	Config config.Inbound
	// Listener 是已绑定的监听（含并发闸包装；dns 网关为 TCP 侧）。
	Listener net.Listener
	// Serve 阻塞服务直到 ctx 取消：停止接受新连接，存量连接按排空语义收尾。
	Serve func(ctx context.Context) error
	// Close 关闭监听（停止接受新连接）；幂等，不影响存量连接。
	Close func()
	// Addr 返回绑定后的实际监听地址；未绑定时为空串。
	Addr func() string

	// closeIdle 在分流规则变化后丢弃转发路径空闲连接（http 专用）。
	closeIdle func()
	// bind 绑定监听（含并发闸包装与过载拒绝响应）；previous 是同
	//（type, listen）旧入站的已解析地址（端口 0 的配置重载后保持原端口）。
	// 绑定产物由调用方经 apply 回填（避免闭包持有构造期局部副本）。
	bind func(limiter *connlimit.Limiter, previous string) (inboundBound, error)

	// auth 是该入站的共性凭据存储（nil = 不校验；测试断言用）。
	auth *auth.Store
}

// inboundBound 是一次成功绑定产生的运行期产物。
type inboundBound struct {
	listener net.Listener
	serve    func(ctx context.Context) error
	close    func()
	addr     func() string
}

// apply 把绑定产物回填到端点（绑定后 Serve / Close / Addr 即可用）。
func (is *InboundServer) apply(b inboundBound) {
	is.Listener = b.listener
	is.Serve = b.serve
	is.Close = b.close
	is.Addr = b.addr
}

// newInboundServer 构造未绑定的入站端点（Serve / Close / Addr 为空操作，
// 由 bind 步骤填充）。
func newInboundServer(proto string, ic config.Inbound) InboundServer {
	is := InboundServer{Proto: proto, Config: ic}
	is.Serve = func(context.Context) error { return nil }
	is.Close = func() {}
	is.Addr = func() string { return "" }
	return is
}

// startResources 启动快照的后台资源（预热池、健康探测、规则源刷新）。
//
// 成文契约：后台资源绑定应用级 ctx（startGeneration 传入 parent），生命周期
// 由 Close（closeResources）终结，不随代际结束而停止。各组件 Start 幂等
// （首次调用生效，重复 Start 的 ctx 参数被忽略），因此 restore 回滚路径的
// 浅拷贝共享同一 pool / provider 实例是安全的——重复 Start 不会重建循环。
// 被替换实例由 releaseReplaced 显式 Close，新实例由 switchTo 以应用级 ctx
// 启动。
func (r *Runtime) startResources(ctx context.Context) {
	r.pool.Start(ctx)
	for _, p := range r.providers {
		p.Start(ctx)
	}
}

// closeResources 关闭快照的后台资源（幂等）：释放空闲预热连接并停止
// 探测 / 刷新循环。在途连接不受影响（它们持有已领取的连接）。
func (r *Runtime) closeResources() {
	r.pool.Close()
	for _, p := range r.providers {
		p.Close()
	}
}

// Close 关闭监听与后台资源（幂等）：G4 守护测试与构建失败清理路径使用。
func (r *Runtime) Close() {
	r.closeListeners()
	r.closeResources()
}

// closeListeners 关闭全部监听（入站 + 运维端点；幂等）。
func (r *Runtime) closeListeners() {
	for i := range r.Inbounds {
		r.Inbounds[i].Close()
	}
	_ = r.Admin.Close()
}

// closeOwned 关闭监听与「本运行时新建（非复用）」的后台资源；
// 用于构建 / 绑定失败的清理路径（不变量 3：失败路径关闭已打开的一切）。
func (r *Runtime) closeOwned(reuse *Runtime) {
	r.closeListeners()
	if r.pool != nil && (reuse == nil || r.pool != reuse.pool) {
		r.pool.Close()
	}
	for _, p := range r.providers {
		if reuse == nil || !containsProvider(reuse.providers, p) {
			p.Close()
		}
	}
}

// releaseReplaced 关闭被 next 替换的后台资源（新运行时复用的除外）。
// 提交路径使用：切换后立即释放被替换的池与规则源，在途连接不受影响。
func (r *Runtime) releaseReplaced(next *Runtime) {
	if r.pool != nil && r.pool != next.pool {
		r.pool.Close()
	}
	for _, p := range r.providers {
		if !containsProvider(next.providers, p) {
			p.Close()
		}
	}
}

func containsProvider(providers []*ruleset.Provider, p *ruleset.Provider) bool {
	for _, q := range providers {
		if q == p {
			return true
		}
	}
	return false
}

// dropForwardIdleConns 在分流规则变化后丢弃转发路径（绝对地址请求）的空闲
// 上游连接，避免后续请求复用到旧路由建立的连接；在途请求不受影响，
// 新请求按新规则重新建连。
func (r *Runtime) dropForwardIdleConns() {
	for i := range r.Inbounds {
		if r.Inbounds[i].closeIdle != nil {
			r.Inbounds[i].closeIdle()
		}
	}
}

// resolvedAddrOf 返回与 ic 同（type, listen）的旧入站已解析地址：
// 重载绑定时的端口稳定提示（端口 0 的配置在重载后保持原端口）。
func (r *Runtime) resolvedAddrOf(ic config.Inbound) string {
	for i := range r.Inbounds {
		old := &r.Inbounds[i]
		if old.Config.Type == ic.Type && old.Config.Listen == ic.Listen {
			return old.Addr()
		}
	}
	return ""
}
