package config_test

import (
	"testing"

	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/nodes"
	"github.com/OopsOo0ps/proxy/internal/shutdown"
)

// TestFailoverBudgetDefaultMatchesNodes 防漂移：配置层缺省（config 包内常量）
// 与节点池库缺省（nodes.DefaultFailoverBudget）必须一致，否则同一链路在
// 不同入口（配置解析 / 直接使用库）下会得到不同的最坏等待上限。
func TestFailoverBudgetDefaultMatchesNodes(t *testing.T) {
	cfg, err := config.ParseClient([]byte(`
inbound:
  http: "127.0.0.1:8080"
nodes:
  - addr: "node1.example.com:443"
    password: token
`))
	if err != nil {
		t.Fatalf("ParseClient: %v", err)
	}
	if got := cfg.Timeouts.Failover.Std(); got != nodes.DefaultFailoverBudget {
		t.Fatalf("config default failover = %v, nodes default = %v", got, nodes.DefaultFailoverBudget)
	}
}

// TestShutdownTimeoutDefaultMatchesShutdown 防漂移：配置层的关停缺省
// （config 包内常量）与 shutdown.DefaultTimeout 必须一致，否则同一语义在
// 配置解析与运行时兜底两条路径下取值不同。
func TestShutdownTimeoutDefaultMatchesShutdown(t *testing.T) {
	cfg, err := config.ParseClient([]byte(`
inbound:
  http: "127.0.0.1:8080"
nodes:
  - addr: "node1.example.com:443"
    password: token
`))
	if err != nil {
		t.Fatalf("ParseClient: %v", err)
	}
	if got := cfg.Timeouts.Shutdown.Std(); got != shutdown.DefaultTimeout {
		t.Fatalf("config default shutdown = %v, shutdown.DefaultTimeout = %v", got, shutdown.DefaultTimeout)
	}
}
