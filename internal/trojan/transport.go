package trojan

import (
	"context"
	"errors"
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

// NewTransport 构建节点传输并封闭全部协议参数。口令校验归协议构造器：
// 非空且不含 CR/LF（config 层已有同规则校验，此处兜底非配置路径的直接构造）。
func NewTransport(cfg ClientConfig) (*Transport, error) {
	if cfg.Password == "" {
		return nil, errors.New("trojan: password must not be empty")
	}
	if strings.ContainsAny(cfg.Password, "\r\n") {
		return nil, errors.New("trojan: password must not contain CR or LF")
	}
	return &Transport{cfg: cfg, passwordHash: auth.SHA224Hex(cfg.Password)}, nil
}

// DialTunnel 实现 outbound.Transport：建立绑定到 target 的就绪隧道，可直接转发原始字节。
func (t *Transport) DialTunnel(ctx context.Context, target core.Target) (net.Conn, error) {
	return Dial(ctx, t.cfg, target)
}

// ConnectIdle 实现 outbound.Prewarmer 的 connect 阶段：建立已完成 TLS 握手、
// 尚未发送 Trojan 请求的空闲隧道（预热池的入池形态）。
func (t *Transport) ConnectIdle(ctx context.Context) (net.Conn, error) {
	return Connect(ctx, t.cfg)
}

// Bind 实现 outbound.Prewarmer 的 bind 阶段：在空闲隧道上补发 Trojan 请求。
// SHA-224 口令派生在本方法内部完成，不再由组装根喂入摘要。
// timeout 取构造时的握手超时，并收敛到 ctx 截止时间内（故障转移总预算覆盖）。
func (t *Transport) Bind(ctx context.Context, conn net.Conn, target core.Target) error {
	return StartRequest(ctx, conn, t.passwordHash, target, t.cfg.HandshakeTimeout)
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
