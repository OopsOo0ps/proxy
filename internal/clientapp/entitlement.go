// 客户端 entitlement 门禁（设计书 §3.1 客户端行 / §2.2 clientapp ──► accounts，
// 迭代④）：管理员分发的 entitlement 文件（cfg.Accounts.File，与账户库同一
// 文件格式 = 文件分发零转换）经 accounts.LoadReadOnly 只读加载，Store.Gate
// 构建门禁读视图，与入站静态凭据复合成同一形状的 core.Authenticator，经
// liveView.Auth() 注入 http / socks5 入站。
//
// 客户端真相源 = entitlement 文件；客户端门禁的价值是本地快速失败与省隧道
// 往返——客户端二进制在用户手里，**服务端才是防篡改的墙**（设计书 §3.1，
// 威胁模型如实声明）。
//
// fail-closed 链（设计书 §3.3 运行期行）：每次 assemble 重新加载文件（重载
// 必须重建 entitlement 视图）；文件缺失/损坏 = 组装失败——启动期从未成功
// 加载 ⇒ 拒绝启动；运行期重载失败 ⇒ 旧快照原子保留、继续服务（不可变快照 +
// 原子切换语义天然覆盖，见 app.go）。门禁不活跃（gate 段缺省/关闭；config
// 校验层已禁止客户端上孤立的 accounts 段）= 返回 nil，行为与现状逐字一致。
package clientapp

import (
	"errors"
	"fmt"

	"github.com/OopsOo0ps/proxy/internal/accounts"
	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/core"
)

// 编译期断言：门禁视图与复合认证器都结构化满足数据面契约（core.Authenticator），
// accounts 包不感知消费方（设计书 §3.1；先例：serverapp/control.go 对
// trojan.Verifier 的断言、liveview.go 对三份 LivePolicy 的断言）。
var (
	_ core.Authenticator = (*accounts.GateView)(nil)
	_ core.Authenticator = gatedAuth{}
)

// buildEntitlement 构建本次组装的客户端 entitlement 门禁视图（cfg.Gate 缺省
// 或关闭 = 返回 nil，门禁不活跃，行为与现状逐字一致）。
//
// 文件按 assemble 每次重读：重载必须重建 entitlement 视图（管理员重发文件
// 后 SIGHUP 即生效）；读取或解析失败返回错误——启动期 = 拒绝启动，运行期 =
// 重载失败、旧配置继续服务（设计书 §3.3 运行期行）。
func (b *builder) buildEntitlement(cfg *config.Config) (*accounts.GateView, error) {
	if cfg.Gate == nil || !cfg.Gate.Enabled {
		return nil, nil
	}
	if cfg.Accounts == nil {
		// config 校验层保证 gate.enabled ⇒ accounts（validateGate fail-closed）；
		// 组装根防御式再拦一道：门禁失去判定依据即组装失败，不静默降级。
		return nil, errors.New("clientapp: gate.enabled requires the accounts section (the entitlement file is the client's subscription source)")
	}
	store, err := accounts.LoadReadOnly(cfg.Accounts.File)
	if err != nil {
		return nil, fmt.Errorf("clientapp: entitlement file: %w", err)
	}
	b.logger.Info("entitlement file loaded", "path", cfg.Accounts.File, "users", store.Len())
	return store.Gate(true), nil
}

// gatedAuth 是复合认证器（设计书 §3.1 客户端行）：入站静态凭据 ∧ entitlement
// 订阅有效，两者都必须通过。拒绝走既有认证拒绝通道（HTTP 407 / SOCKS5 失败
// 码，I2）——协议层按认证失败响应，判定发生在握手期，不发生任何拨号。
//
// static 用具体类型 *auth.Store 而非接口：避免把 nil *auth.Store 装进接口后
// 被误判为「有静态维度」（liveview.go 的 nil 纪律）；nil = 无静态维度。
type gatedAuth struct {
	static *auth.Store        // 入站静态凭据（nil = 无静态维度）
	gate   *accounts.GateView // entitlement 门禁视图（非 nil）
}

// Authenticate 实现 core.Authenticator：静态维度先判（常量时间比对），订阅
// 维度后判；任一不过即拒绝（短路，无副作用、无拨号）。
func (g gatedAuth) Authenticate(username, password string) bool {
	if g.static != nil && !g.static.Authenticate(username, password) {
		return false
	}
	return g.gate.Authenticate(username, password)
}
