package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// upstreamStack 是「出口链路栈」的配置子集：它决定节点池、预热连接池与
// TLS 客户端能否在热加载中复用（见 clientapp.buildRuntime）。
//
// 指纹覆盖整份结构：任何字段变化都会改变指纹，不存在「新增字段忘了加进
// 比较列表、重载静默沿用旧池」的空间。config.Client 新增顶层字段时，
// TestUpstreamFingerprintFieldClassification 会强制给它归类（上游相关 →
// 加入本结构；无关 → 加入测试里的非上游清单）。
type upstreamStack struct {
	Nodes       []Node      `json:"nodes"`
	Pool        Pool        `json:"pool"`
	HealthCheck HealthCheck `json:"health_check"`
	TLS         ClientTLS   `json:"tls"`
	Timeouts    Timeouts    `json:"timeouts"`
}

// UpstreamFingerprint 返回出口链路栈配置的稳定指纹（SHA-256 十六进制）。
// 指纹相同 ⇒ 上游栈未变，运行时可以复用现有节点池与预热池；
// 不同 ⇒ 必须重建。计算失败时调用方应按「已变更」处理（保守重建）。
func UpstreamFingerprint(c *Client) (string, error) {
	raw, err := json.Marshal(upstreamStack{
		Nodes:       c.Nodes,
		Pool:        c.Pool,
		HealthCheck: c.HealthCheck,
		TLS:         c.TLS,
		Timeouts:    c.Timeouts,
	})
	if err != nil {
		return "", fmt.Errorf("config: marshal upstream stack: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
