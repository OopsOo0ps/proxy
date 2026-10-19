package clientapp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/outbound"
	"github.com/OopsOo0ps/proxy/internal/trojan"
)

// —— 两个分派点（全仓唯一，设计文档 §7.4）——

// buildTransport 是出口协议分派点：switch n.Protocol → DecodeParams →
// 协议构造器（协议语义校验在这里，不在 config）。返回节点传输与其地址
// （nodes.Node 的标识，来自协议参数）。
func buildTransport(n config.Node, dialTimeout, handshakeTimeout time.Duration) (outbound.Transport, string, error) {
	switch n.Protocol {
	case config.ProtocolTrojan:
		var p trojan.Params
		if err := config.DecodeParams(n.Params, &p); err != nil {
			return nil, "", fmt.Errorf("node %q: decode trojan params: %w", n.Name, err)
		}
		tlsCfg, err := clientTLSConfig(p)
		if err != nil {
			return nil, "", fmt.Errorf("node %q: %w", n.Name, err)
		}
		tr, err := trojan.NewTransport(trojan.ClientConfig{
			ServerAddr:       p.Addr,
			Password:         p.Password,
			TLSConfig:        tlsCfg,
			DialTimeout:      dialTimeout,
			HandshakeTimeout: handshakeTimeout,
		})
		if err != nil {
			return nil, "", err
		}
		return tr, p.Addr, nil
	default:
		return nil, "", fmt.Errorf("unknown outbound protocol %q", n.Protocol)
	}
}

// clientTLSConfig 从协议参数组装 TLS 客户端配置（CA 信任与 SNI 是 trojan
// 传输的协议素材；SNI 为空时由 crypto/tls 取拨号地址主机名）。
func clientTLSConfig(p trojan.Params) (*tls.Config, error) {
	// 护栏：insecure-skip-verify 仅允许环回地址（本地自签演示场景）；远程
	// 节点 fail-closed——必须改用 ca-file 做证书校验。复用 config 的
	// IsLoopbackListen 从严语义：主机名（localhost 除外）一律按非环回处理。
	if p.InsecureSkipVerify && !config.IsLoopbackListen(p.Addr) {
		return nil, fmt.Errorf("insecure-skip-verify is only allowed for loopback addresses (got %q); configure ca-file instead", p.Addr)
	}
	// ClientSessionCache 启用 TLS 会话恢复（session resumption）：不缓存时每条
	// 新隧道都要与出口节点做完整 TLS 握手，是冷路径（每请求新建隧道）吞吐的
	// 实测瓶颈。容量 1024 是每节点 LRU 会话条目数，足以覆盖 8192 并发上限下的
	// 在用节点会话。该 *tls.Config 每节点一份、由该节点所有连接共享；当 SNI
	// 为空时 trojan 侧会对它做浅拷贝（Clone）补 ServerName，cache 指针仍被
	// 复制共享，恢复照常生效。
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: p.InsecureSkipVerify, // 仅环回自签调试
		ClientSessionCache: tls.NewLRUClientSessionCache(1024),
	}
	if p.SNI != "" {
		tlsCfg.ServerName = p.SNI
	}
	if p.CAFile != "" {
		pemData, err := os.ReadFile(p.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ca-file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("ca-file: no certificates found in %s", p.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, nil
}
