// accounts / control / payment 接线（设计书 §2.1 / §3.1，迭代①③）：accounts
// 模式下构建进程级账户存储（builder 持有，跨代际复用——metrics/limiter/logCtrl
// 的进程级组件先例）、门禁读视图（隧道凭据校验器，on = cfg.Gate.Enabled）与
// 控制面端点；payment 模式（cfg.Payment 在场）再构建进程级网关客户端与订单
// 服务注入控制面。
//
// cfg.Accounts 为 nil（缺省）= 全部不构建：rt.Control 与 rt.gate 保持 nil，
// 入站沿用静态凭据（auth.NewStore），行为与现状逐字一致。accounts 模式与
// 静态凭据互斥由 config 校验层强制（身份命名空间唯一），因此 accounts 模式
// 下入站不再调用 auth.NewStore（空 users 列表会构造失败，见 buildInbound）。
package serverapp

import (
	"errors"
	"fmt"
	"os"

	"github.com/OopsOo0ps/proxy/internal/accounts"
	"github.com/OopsOo0ps/proxy/internal/alipay"
	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/control"
	"github.com/OopsOo0ps/proxy/internal/metrics"
	"github.com/OopsOo0ps/proxy/internal/payment"
	"github.com/OopsOo0ps/proxy/internal/trojan"
)

// 编译期断言：门禁视图与其计数装饰器都结构化满足数据面契约（trojan.Verifier），
// accounts 包不感知消费方（设计书 §3.1；先例：app.go 的 var _ trojan.LivePolicy）。
var (
	_ trojan.Verifier = (*accounts.GateView)(nil)
	_ trojan.Verifier = countingGate{}
)

// buildAccountsControl 构建 accounts 模式的进程级组件与控制面端点（cfg.Accounts
// 为 nil 时零构建）。产物挂到 rt：
//   - rt.gate：隧道凭据校验器视图（buildInbound 消费；动态存储，账户变更对
//     下一次判定立即可见）；
//   - rt.Control：控制面服务（runtimeServices 暴露给生命周期核心、bindRuntime
//     绑定监听）；cfg.Payment 在场时额外注入支付领域服务与网关客户端。
//
// 必须在入站构建之前调用：入站的隧道校验器在 accounts 模式下取门禁视图。
func (b *builder) buildAccountsControl(cfg *config.Config, rt *Runtime) error {
	if cfg.Accounts == nil {
		// config 校验层保证 payment ⇒ accounts（validatePayment fail-closed）；
		// 这里再防御式拦一道：支付配置失去账户库即组装失败（订阅延长无处落地）。
		if cfg.Payment != nil {
			return errors.New("serverapp: payment requires the accounts section")
		}
		return nil
	}
	store, err := b.accountsStore(cfg.Accounts.File)
	if err != nil {
		return err
	}
	// 门禁视图（设计书 §3.1）：on = cfg.Gate.Enabled（段缺省 = 关闭，行为与
	// 现状逐字一致；开启 = 无有效订阅即拒绝，deny-by-default）。经计数装饰器
	// 包装后作为隧道凭据校验器——决策计数发生在组装根（L4），accounts（L2）
	// 不 import metrics（L4 以下禁止，arch 守护强制）。
	rt.gate = countingGate{
		gate: store.Gate(cfg.Gate != nil && cfg.Gate.Enabled),
		m:    b.metrics,
	}
	deps := control.Deps{Store: store, Logger: b.logger}
	if cfg.Payment != nil {
		pay, err := b.paymentService(cfg, store)
		if err != nil {
			return err
		}
		client, err := b.alipayClient(cfg.Payment)
		if err != nil {
			return err
		}
		deps.Pay = pay
		deps.Alipay = client
		deps.NotifyURL = cfg.Payment.NotifyURL
	}
	rt.Control, err = control.New(deps)
	if err != nil {
		return fmt.Errorf("control endpoint: %w", err)
	}
	return nil
}

// countingGate 是账户门禁视图的计数装饰器（L4 组装根持有，设计书 §3.1
// 可观测性）：trojan.Verifier 契约只暴露 (user, ok)，存储期拒绝原因经视图的
// 判定明细 API（DecideTunnel）取回，计入 entitlement_decisions_total{decision,
// reason}（有限枚举；allow 记 reason=none）。计数点 = 门禁决策点：一次隧道
// 握手恰好一次判定 ⇒ 恰好一次计数。计数发生在组装根，accounts（L2）不
// import metrics（L4 以下禁止，arch 守护强制）。
type countingGate struct {
	gate *accounts.GateView
	m    *metrics.Metrics
}

// VerifyTunnel 实现 trojan.Verifier：判定经门禁视图的明细 API，随后按决策
// 计数；返回值与视图逐字一致（拒绝时仍返回匹配名，供日志定位）。
func (g countingGate) VerifyTunnel(hashHex string) (string, bool) {
	name, d := g.gate.DecideTunnel(hashHex)
	if d.Allow {
		g.m.EntitlementDecision(metrics.EntitlementDecisionAllow, metrics.EntitlementReasonNone)
		return name, true
	}
	g.m.EntitlementDecision(metrics.EntitlementDecisionDeny, string(d.Reason))
	return name, false
}

// paymentCacheKey 是进程级订单服务的构建键：热加载后键与既有实例一致则复用
// （跨代际单写者），任一字段（账户库路径 / 订单文件路径 / 档位）变化则重建。
// 账户库路径参与键：订单落地绑定具体 Store 实例，账户库换路径重建 Store 时
// 缓存的 Service 必须随之重建（否则延长落在旧库上）。
type paymentCacheKey struct {
	accountsPath string
	path         string
	periodDays   int
	priceCents   int64
}

// alipayCacheKey 是进程级网关客户端的构建键：网关地址 / 应用 ID / 密钥文件
// 任一变更即重建（Client 构造后只读，重建即重新读取密钥文件）。
type alipayCacheKey struct {
	gateway     string
	appID       string
	merchantKey string
	alipayPub   string
}

// paymentService 返回进程级订单服务：builder 持有、跨代际复用（accountsStore
// 同款纪律——orders.json 的单写者由进程级单例保证，代际切换不会留下两个
// Service 并发写同一文件）。构建即校验：档位非正 / orders 文件损坏 = 构建
// 失败（启动与热加载都拒绝，fail-closed）。
func (b *builder) paymentService(cfg *config.Config, store *accounts.Store) (*payment.Service, error) {
	p := cfg.Payment
	key := paymentCacheKey{
		accountsPath: cfg.Accounts.File,
		path:         p.OrdersFile,
		periodDays:   p.PeriodDays,
		priceCents:   p.PriceCents,
	}
	if b.payment != nil && b.paymentKey == key {
		return b.payment, nil
	}
	svc, err := payment.Open(p.OrdersFile, store, p.PeriodDays, p.PriceCents)
	if err != nil {
		return nil, fmt.Errorf("payment %s: %w", p.OrdersFile, err)
	}
	b.payment, b.paymentKey = svc, key
	return svc, nil
}

// alipayClient 返回进程级网关客户端：builder 持有、跨代际复用（密钥文件 /
// 网关地址 / 应用 ID 任一变更即重建）。密钥文件的读取与 PEM 解析在此收口
// （alipay 以 PEM 字节注入、保持文件系统无关）：文件缺失 / 非法 = 构建失败
// （fail-closed，设计书 §5）。
func (b *builder) alipayClient(cfg *config.Payment) (*alipay.Client, error) {
	key := alipayCacheKey{
		gateway:     cfg.GatewayURL,
		appID:       cfg.AppID,
		merchantKey: cfg.MerchantKeyFile,
		alipayPub:   cfg.AlipayPublicKeyFile,
	}
	if b.alipay != nil && b.alipayKey == key {
		return b.alipay, nil
	}
	merchantPEM, err := os.ReadFile(cfg.MerchantKeyFile)
	if err != nil {
		return nil, fmt.Errorf("alipay merchant key %s: %w", cfg.MerchantKeyFile, err)
	}
	peerPEM, err := os.ReadFile(cfg.AlipayPublicKeyFile)
	if err != nil {
		return nil, fmt.Errorf("alipay public key %s: %w", cfg.AlipayPublicKeyFile, err)
	}
	client, err := alipay.New(alipay.ClientConfig{
		Gateway:        cfg.GatewayURL,
		AppID:          cfg.AppID,
		MerchantKeyPEM: merchantPEM,
		AlipayKeyPEM:   peerPEM,
	})
	if err != nil {
		return nil, fmt.Errorf("alipay client: %w", err)
	}
	b.alipay, b.alipayKey = client, key
	return client, nil
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
