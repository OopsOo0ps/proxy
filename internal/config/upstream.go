package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

// 上游链路栈指纹（热加载复用判断，见 clientapp 组装根）：决定节点池与
// 预热池能否复用的配置子集。协议参数（地址、口令、SNI、CA）都在节点的
// params 块内，随节点一起参与指纹——新增协议参数自动参与比较。
type upstreamNode struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Weight   int    `json:"weight"`
	Params   any    `json:"params"`
}

// UpstreamFingerprint 返回出口链路栈配置的稳定指纹（SHA-256 十六进制）。
// 指纹相同 ⇒ 上游栈未变，运行时可以复用现有节点池与预热池；
// 不同 ⇒ 必须重建。计算失败时调用方应按「已变更」处理（保守重建）。
//
// params 节点先规范化为通用映射（去注释与行号信息）：等价的参数块
// （跨格式 / 注释差异）产出相同指纹，避免无关编辑触发池重建。
func UpstreamFingerprint(c *Config) (string, error) {
	nodes := make([]upstreamNode, 0, c.nodeCount())
	if c.Outbound != nil {
		for _, n := range c.Outbound.Nodes {
			v, err := paramsValue(n.Params)
			if err != nil {
				return "", err
			}
			nodes = append(nodes, upstreamNode{Name: n.Name, Protocol: n.Protocol, Weight: n.Weight, Params: v})
		}
	}
	raw, err := json.Marshal(struct {
		Nodes    []upstreamNode `json:"nodes"`
		Pool     PoolConfig     `json:"pool"`
		Timeouts Timeouts       `json:"timeouts"`
	}{
		Nodes:    nodes,
		Pool:     c.poolConfig(),
		Timeouts: c.Timeouts,
	})
	if err != nil {
		return "", fmt.Errorf("config: marshal upstream stack: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func (c *Config) poolConfig() PoolConfig {
	if c.Outbound == nil {
		return PoolConfig{}
	}
	return c.Outbound.Pool
}

// paramsValue 把 params 节点规范化为通用值（map/slice/scalar）：注释与
// 位置信息被丢弃，键以字符串形式保留；未提供 params 时返回 nil。
func paramsValue(n yaml.Node) (any, error) {
	if n.Kind == 0 {
		return nil, nil
	}
	var v any
	if err := n.Decode(&v); err != nil {
		return nil, fmt.Errorf("config: canonicalize node params: %w", err)
	}
	return v, nil
}
