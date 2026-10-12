// 出站传输一致性验收助手（设计文档 7 / 阶段 4）。
//
// 仅供测试使用：各出口协议在自己的 _test.go 中以回环服务端为夹具调用
// RunConformance，未来协议接入即跑同一套验收，无需逐条重写断言。

package outbound

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/OopsOo0ps/proxy/internal/core"
)

const (
	// conformanceTimeout 是验收中每个网络操作的期限。
	conformanceTimeout = 5 * time.Second
	// poolDwell 模拟连接在预热池中的停留（需小于服务端握手超时）。
	poolDwell = 50 * time.Millisecond
)

// ConformanceSpec 描述一次传输一致性验收的被测对象。
type ConformanceSpec struct {
	// Transport 指向健康回环服务端的被测传输（必填）。
	Transport Transport
	// Target 是服务端侧可达的目标。
	Target core.Target
	// RoundTrip 在就绪隧道上做一次原始字节往返断言（如回显）。
	RoundTrip func(t *testing.T, conn net.Conn)

	// Prewarmer 参与两阶段（connect/bind）验收；nil 跳过。
	Prewarmer Prewarmer
	// Prober 参与探测验收（对健康端点必须成功）；nil 跳过。
	Prober Prober
	// DeadProber 指向不可达端点的探测实例（Probe 必须失败）；nil 跳过。
	DeadProber Prober
}

// RunConformance 对被测传输跑一致性验收：
//   - dial：DialTunnel 一次调用建立绑定到 Target 的就绪隧道，可直接转发
//     原始字节；
//   - prewarm（实现 Prewarmer 时）：ConnectIdle 建立空闲隧道，在池中停留
//     后 Bind 补发绑定仍可转发；Bind 失败（连接已作废）必须报错，且调用方
//     回退新建的隧道仍然可用；
//   - probe（实现 Prober 时）：健康端点探测成功；不可达端点探测失败。
func RunConformance(t *testing.T, spec ConformanceSpec) {
	t.Helper()

	t.Run("dial", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), conformanceTimeout)
		defer cancel()
		conn, err := spec.Transport.DialTunnel(ctx, spec.Target)
		if err != nil {
			t.Fatalf("DialTunnel: %v", err)
		}
		defer func() { _ = conn.Close() }()
		spec.RoundTrip(t, conn)
	})

	if spec.Prewarmer != nil {
		t.Run("prewarm-bind", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), conformanceTimeout)
			defer cancel()

			// connect → 池中停留 → bind → 可转发。
			idle, err := spec.Prewarmer.ConnectIdle(ctx)
			if err != nil {
				t.Fatalf("ConnectIdle: %v", err)
			}
			defer func() { _ = idle.Close() }()
			time.Sleep(poolDwell)
			if err := spec.Prewarmer.Bind(ctx, idle, spec.Target); err != nil {
				t.Fatalf("Bind after dwell: %v", err)
			}
			spec.RoundTrip(t, idle)

			// Bind 失败路径：连接作废后 Bind 必须报错，
			// 且随后的回退新建（调用方 fallback）仍然可用。
			stale, err := spec.Prewarmer.ConnectIdle(ctx)
			if err != nil {
				t.Fatalf("ConnectIdle (stale case): %v", err)
			}
			_ = stale.Close() // 作废：模拟池中连接失效
			if err := spec.Prewarmer.Bind(ctx, stale, spec.Target); err == nil {
				t.Fatal("Bind on discarded connection: expected error")
			}
			fresh, err := spec.Transport.DialTunnel(ctx, spec.Target)
			if err != nil {
				t.Fatalf("fallback DialTunnel after Bind failure: %v", err)
			}
			defer func() { _ = fresh.Close() }()
			spec.RoundTrip(t, fresh)
		})
	}

	if spec.Prober != nil {
		t.Run("probe", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), conformanceTimeout)
			defer cancel()
			if err := spec.Prober.Probe(ctx); err != nil {
				t.Fatalf("Probe against healthy endpoint: %v", err)
			}
			if spec.DeadProber == nil {
				return
			}
			if err := spec.DeadProber.Probe(ctx); err == nil {
				t.Fatal("expected probe error against unreachable endpoint")
			}
		})
	}
}
