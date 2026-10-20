package trojan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/outbound"
)

// 编译期断言：Trojan 传输同时满足出口传输契约的全部三项能力。
var (
	_ outbound.Transport = (*Transport)(nil)
	_ outbound.Prewarmer = (*Transport)(nil)
	_ outbound.Prober    = (*Transport)(nil)
)

// Transport 是单个出口节点的 Trojan over TLS 传输（outbound 三能力全实现）。
// 每节点一个实例：协议参数（地址、口令、TLS、超时）在构造时封闭，
// 线格式的 SHA-224 口令派生属协议细节，收敛在本包内部——组装根只见
// 隧道能力面，不触碰口令摘要。可安全并发使用。
type Transport struct {
	cfg          ClientConfig
	passwordHash string // hex(SHA224(password))，构造时派生一次
}

// NewTransport 构建节点传输并封闭全部协议参数。协议语义校验在这里
// （设计文档 §7.3，config 不认识协议字段语义）：地址必须为 host:port、
// 口令非空且不含 CR/LF。config.Params 只是参数形状，此处兜底非配置路径
// 的直接构造。
func NewTransport(cfg ClientConfig) (*Transport, error) {
	if _, _, err := net.SplitHostPort(cfg.ServerAddr); err != nil {
		return nil, fmt.Errorf("trojan: server addr %q: %w", cfg.ServerAddr, err)
	}
	if cfg.Password == "" {
		return nil, errors.New("trojan: password must not be empty")
	}
	if strings.ContainsAny(cfg.Password, "\r\n") {
		return nil, errors.New("trojan: password must not contain CR or LF")
	}
	return &Transport{cfg: cfg, passwordHash: auth.SHA224Hex(cfg.Password)}, nil
}

// idleConn 是包内自定义的两阶段预热句柄（outbound.Prepared）：
// 包住已完成 TLS 握手、尚未绑定目标的空闲连接，对预热池不透明。
type idleConn struct{ net.Conn }

// closeWriter / closeReader 是支持半关闭的连接（*net.TCPConn、*tls.Conn 均实现）。
type (
	closeWriter interface{ CloseWrite() error }
	closeReader interface{ CloseRead() error }
)

// CloseWrite 透传底层半关闭写方向的能力：预热领取的连接（动态类型
// idleConn）与 DialTunnel 新建的 *tls.Conn 必须语义等价，否则 relay 的
// 半关闭会静默失效（relay.halfClose 只对实现 closeWriter 的连接生效），
// 客户端 FIN 传不到节点，转发要等 timeouts.idle 超时才结束，预热名额
// 也被整段占住。底层不支持半关闭时返回 nil（与 relay.halfClose 的容忍
// 语义一致，连接最终会被整体关闭）。
func (c idleConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

// CloseRead 透传底层半关闭读方向的能力，语义与 CloseWrite 对称。
func (c idleConn) CloseRead() error {
	if cr, ok := c.Conn.(closeReader); ok {
		return cr.CloseRead()
	}
	return nil
}

// Discard 释放底层连接。当前实现与 Close 等价：预热池在 TTL 淘汰、节点
// 摘除或关停时直接 Close 底层连接，不经过 Discard；全仓唯一的 Discard
// 调用点是 nodes.prewarmNode 的句柄类型断言失败分支。保留为未来非 Close
// 等价释放的扩展点。
func (c idleConn) Discard() { _ = c.Close() }

// DialTunnel 实现 outbound.Transport：建立绑定到 target 的就绪隧道，
// 可直接转发原始字节。
func (t *Transport) DialTunnel(ctx context.Context, target core.Target) (net.Conn, error) {
	return Dial(ctx, t.cfg, target)
}

// ConnectIdle 实现 outbound.Prewarmer 的 connect 阶段：建立已完成 TLS 握手、
// 尚未发送 Trojan 请求的空闲隧道句柄（预热池的入池形态）。
func (t *Transport) ConnectIdle(ctx context.Context) (outbound.Prepared, error) {
	conn, err := Connect(ctx, t.cfg)
	if err != nil {
		return nil, err
	}
	return idleConn{conn}, nil
}

// Bind 实现 outbound.Prewarmer 的 bind 阶段：在空闲句柄上向 target 补发
// Trojan 请求并返回可转发的连接。SHA-224 口令派生在本方法内部完成，
// 不再由组装根喂入摘要；timeout 取构造时的握手超时，并收敛到 ctx 截止
// 时间内（故障转移总预算覆盖）。句柄对池不透明，但必须承载底层连接
// （预热池的存活探测与领取后补发绑定都经它，映射在组装根完成）；句柄已被
// Discard 时连接已关闭，StartRequest 必然失败（调用方回退新建）。
func (t *Transport) Bind(ctx context.Context, p outbound.Prepared, target core.Target) (net.Conn, error) {
	conn, ok := p.(net.Conn)
	if !ok {
		return nil, errors.New("trojan: bind: prepared handle does not carry a connection")
	}
	if err := StartRequest(ctx, conn, t.passwordHash, target, t.cfg.HandshakeTimeout); err != nil {
		return nil, err
	}
	return conn, nil
}

// Probe 实现 outbound.Prober：完成一次 TLS 握手后立即关闭（不发 Trojan 请求、
// 不占预热池）。ctx 携带探测期限（主动健康检查按 Health.Timeout 收敛）。
func (t *Transport) Probe(ctx context.Context) error {
	conn, err := Connect(ctx, t.cfg)
	if err != nil {
		return err
	}
	return conn.Close()
}
