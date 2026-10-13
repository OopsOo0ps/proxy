// Package outbound 定义出口端点的传输契约（L1 层，设计文档 §4.2）。
//
// 契约按能力拆分，不假设所有出口协议同形：
//
//   - Transport 是必备能力：建立绑定到目标的就绪隧道；
//   - Prepared 是两阶段预热的中间句柄（协议包自定义的值，对池不透明）；
//   - Prewarmer 是可选能力：「协议握手」与「绑定目标」两阶段分离的传输
//     （如 Trojan）才支持先握手入池、领取时补发绑定的预热模型；
//     多路复用协议不属于此类，将来以自己的方式接入，不走此接口；
//   - Prober 是可选能力：可对传输做主动健康探测。
//
// 每个出口节点携带一个 Transport 实例，协议参数（地址、口令、TLS 等）在
// 协议实现的构造器内封闭——节点池与组装根只见能力面，线格式细节不出协议包；
// 混合协议节点天然可用（每节点各自的 Transport），无需第二个协议出现才动模型。
//
// 依赖规则由 internal/arch 守护测试强制：本包只依赖 core + stdlib。
package outbound

import (
	"context"
	"net"

	"github.com/OopsOo0ps/proxy/internal/core"
)

// Transport 是一个出口端点的隧道能力（每节点一个实例，封闭协议参数）。
type Transport interface {
	// DialTunnel 建立绑定到 target 的就绪隧道，可直接转发原始字节。
	// 语义约定：读写即目标侧字节流，半关闭传递对端 EOF；
	// 失败时必须返回非 nil error（不允许 (nil, nil) 假成功）。
	DialTunnel(ctx context.Context, target core.Target) (net.Conn, error)
}

// Prepared 是两阶段预热的中间句柄（协议包自定义的值，对池不透明）。
type Prepared interface {
	// Discard 释放底层资源：池在 TTL 淘汰、节点摘除或关停时调用。
	// 实现必须可安全重复调用。
	Discard()
}

// Prewarmer 是「握手与绑定两阶段分离」传输的可选能力。
// Trojan 属于此类；多路复用协议不是——它们将来以自己的方式接入，不走此接口。
// 只有实现该能力的传输才参与预热池，其余节点每次直接 DialTunnel。
type Prewarmer interface {
	// ConnectIdle 建立已完成协议握手、尚未绑定目标的空闲隧道（入池形态）。
	ConnectIdle(ctx context.Context) (Prepared, error)
	// Bind 在空闲句柄上向 target 补发绑定请求，返回可转发的连接。
	// 失败（含句柄已被 Discard）时必须返回错误，调用方回退新建；
	// 返回的连接由调用方负责关闭。
	Bind(ctx context.Context, p Prepared, target core.Target) (net.Conn, error)
}

// Prober 是可主动探测传输的可选能力（主动健康检查用）。
// 不实现则该节点只做被动健康判定。
type Prober interface {
	// Probe 做一次轻量探测（如完成握手后立即关闭）；失败时返回错误。
	Probe(ctx context.Context) error
}
