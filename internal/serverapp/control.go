// accounts / control 接线（设计书 §2.1 / §3.1，迭代①）：accounts 模式下
// 构建进程级账户存储（builder 持有，跨代际复用——metrics/limiter/logCtrl 的
// 进程级组件先例）、门禁读视图（隧道凭据校验器）与控制面端点。
//
// cfg.Accounts 为 nil（缺省）= 全部不构建：rt.Control 与 rt.gate 保持 nil，
// 入站沿用静态凭据（auth.NewStore），行为与现状逐字一致。accounts 模式与
// 静态凭据互斥由 config 校验层强制（身份命名空间唯一），因此 accounts 模式
// 下入站不再调用 auth.NewStore（空 users 列表会构造失败，见 buildInbound）。
package serverapp

import (
	"fmt"

	"github.com/OopsOo0ps/proxy/internal/accounts"
	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/control"
	"github.com/OopsOo0ps/proxy/internal/trojan"
)

// 编译期断言：门禁视图结构化满足数据面契约（trojan.Verifier），accounts 包
// 不感知消费方（设计书 §3.1；先例：app.go 的 var _ trojan.LivePolicy）。
var _ trojan.Verifier = (*accounts.GateView)(nil)

// buildAccountsControl 构建 accounts 模式的进程级组件与控制面端点（cfg.Accounts
// 为 nil 时零构建）。产物挂到 rt：
//   - rt.gate：隧道凭据校验器视图（buildInbound 消费；动态存储，账户变更对
//     下一次判定立即可见）；
//   - rt.Control：控制面服务（runtimeServices 暴露给生命周期核心、bindRuntime
//     绑定监听）。
//
// 必须在入站构建之前调用：入站的隧道校验器在 accounts 模式下取门禁视图。
func (b *builder) buildAccountsControl(cfg *config.Config, rt *Runtime) error {
	if cfg.Accounts == nil {
		return nil
	}
	store, err := b.accountsStore(cfg.Accounts.File)
	if err != nil {
		return err
	}
	rt.gate = accounts.NewGateView(store)
	rt.Control, err = control.New(control.Deps{Store: store, Logger: b.logger})
	if err != nil {
		return fmt.Errorf("control endpoint: %w", err)
	}
	return nil
}

// accountsStore 返回进程级账户存储：builder 持有、跨代际复用（同一路径的
// 热加载不重读文件——控制面的动态变更以文件为权威状态，代际切换后新 Store
// 会重读到全部变更，进程级单例则避免新旧代际两个 Store 实例并发写同一文件）。
// 首次构建或路径变更时严格加载：文件缺失/损坏 = 构建失败（启动期 fail-closed，
// 设计书 §3.3）；空账户列表合法（空库语义）。
func (b *builder) accountsStore(path string) (*accounts.Store, error) {
	if b.accounts != nil && b.accountsPath == path {
		return b.accounts, nil
	}
	store, err := accounts.Open(path)
	if err != nil {
		return nil, fmt.Errorf("accounts %s: %w", path, err)
	}
	b.accounts, b.accountsPath = store, path
	return store, nil
}
