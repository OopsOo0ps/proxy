// Package payment 是订单聚合的 L2 领域包：订单状态机、trade_no 幂等落地、
// 版本化 JSON 文件持久化（orders.json，独立于 accounts.json），以及订阅单调
// 延长的触发方（设计书 §1.1 / §2.1，迭代③）。
//
// 职责边界：
//   - HTTP-free / gin-free / alipay-free：线格式方言与网关验签归 internal/alipay
//     与控制面（调用方把验签后的支付事实整理为 Trade 传入），本包只核对账务
//     语义（订单归属、金额、trade_no 幂等），对网关方言零编译期感知（§2.2）；
//   - 与 accounts 的唯一聚合间边：applied 幂等落地 → accounts 订阅单调延长
//     （ExtendSubscriptionExpiresAt；同层边由 internal/arch 显式登记）；
//   - 固定单一档位：period_days + price_cents（无多档计划/优惠券/退款流，
//     §6 不过度设计）；订单超时惰性判定（无后台清扫线程）。
//
// 授予语义（§1.2 Grant 支付路径）：paid_until = max(now, current_expiry) +
// period_days，经 accounts 单调延长（max 在聚合边界再守一道，永不回退）；
// 管理员纠错通道是 accounts.SetSubscriptionExpiresAt（可任意设置），不归本包。
//
// 通知幂等（§1.1 I4）：同一 trade_no 重复 notify 只落地一次——applied 订单对
// 同号通知直接 ACK（无账务变更）；金额不符拒落地；closed/超时订单 ACK 但不动账。
//
// 已知取舍（单主机文件持久化的固有窗口，无账务日志不做精确一次）：落地按
// 「paid 检查点 → accounts 延长 → applied 终态」三步落盘推进；进程在「延长
// 已生效、applied 未落盘」窗口崩溃后，网关重试会自 paid 状态重新续落地，
// 极端情况下多延长一个周期（偏差方向用户受益，管理员纠错通道可回收）。
//
// 单写者前提：持久化不做跨进程文件锁，同一 orders.json 只允许一个进程写
// （部署保证，镜像 accounts 的纪律）。
package payment

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/OopsOo0ps/proxy/internal/accounts"
)

// OrderStatus 是订单状态（设计书 §1.2 状态机）：
//
//	pending → paid → applied（applied 幂等：同 trade_no 重复通知直接 ACK）
//	pending → closed（超时未付，惰性判定；closed 终态）
type OrderStatus string

const (
	// OrderPending 已创建待支付。
	OrderPending OrderStatus = "pending"
	// OrderPaid 网关已确认支付（落地检查点：trade_no 已固定，等待订阅延长
	// 与终态落盘；中断后同号通知自此处续落地）。
	OrderPaid OrderStatus = "paid"
	// OrderApplied 已落地（订阅已延长；终态，同 trade_no 重复通知直接 ACK）。
	OrderApplied OrderStatus = "applied"
	// OrderClosed 超时未付关闭（终态；再收到通知 ACK 但不动账）。
	OrderClosed OrderStatus = "closed"
)

// orderTTL 是订单支付时限（固定值：无配置段、无多档；超时未付的 pending
// 订单在下一次通知触碰时惰性关闭）。
const orderTTL = 2 * time.Hour

// 错误集（调用方以 errors.Is 区分；文件与持久化错误以包装错误返回）。
var (
	// ErrInvalidTrade 通知事实形状非法（缺 trade_no / 金额非正）。
	ErrInvalidTrade = errors.New("payment: invalid trade")
	// ErrUnknownOrder 通知的商户订单号不存在（非本商户订单，fail-closed 拒绝）。
	ErrUnknownOrder = errors.New("payment: unknown order")
	// ErrAmountMismatch 通知金额与订单金额不符（拒落地，不动账）。
	ErrAmountMismatch = errors.New("payment: amount mismatch")
	// ErrTradeConflict 同一订单收到不同 trade_no（幂等键冲突，拒落地）。
	ErrTradeConflict = errors.New("payment: trade_no conflict")
	// ErrInvalidOrder 订单形状非法（下单参数 / 文件行形状）。
	ErrInvalidOrder = errors.New("payment: invalid order")
)

// Order 是一笔订阅购买订单的导出形态（聚合根快照）。order_id 即网关口径的
// out_trade_no（幂等创建键）；username 是弱引用（字符串，不校验账户存在性
// ——账户只停用不删除，订单以用户名引用，设计书 §1.1）。
type Order struct {
	// OrderID 是订单号（= out_trade_no，全库唯一）。
	OrderID string
	// Username 是购买账户（弱引用字符串）。
	Username string
	// AmountCents 是订单金额（分，整数；固定单一档位 = price_cents）。
	AmountCents int64
	// Status 是订单状态（pending | paid | applied | closed）。
	Status OrderStatus
	// TradeNo 是网关交易号（trade_no；落地幂等键，paid/applied 后固定）。
	TradeNo string
	// GmtPayment 是网关原文付款时刻（gmt_payment 原样留存，仅审计；本包不解析）。
	GmtPayment string
	// CreatedAt 是下单时刻。
	CreatedAt time.Time
	// ExpiresAt 是订单超时时刻（不含）：pending 且 now ≥ ExpiresAt 视为超时，
	// 下一次通知触碰时惰性置为 closed。
	ExpiresAt time.Time
	// AppliedAt 是落地时刻（零值 = 未落地）。
	AppliedAt time.Time
}

// Trade 是一笔已通过验签的支付通知事实（值对象）：调用方（控制面）负责网关
// 验签与 trade_status 过滤（只有已支付通知进入落地，其余状态不上账），本包
// 核对账务语义——订单归属、金额、trade_no 幂等（§1.1 I4）。字段是网关原文
// 的最小落地子集，不含任何线格式方言。
type Trade struct {
	// OutTradeNo 是商户订单号（= Order.OrderID，订单寻址键）。
	OutTradeNo string
	// TradeNo 是网关交易号（trade_no；幂等落地键，非空）。
	TradeNo string
	// AmountCents 是通知口径的订单金额（分，整数；与订单金额逐字核对）。
	AmountCents int64
	// GmtPayment 是网关原文付款时刻（原样入账留存，仅审计）。
	GmtPayment string
}

// Service 是订单聚合的领域服务：订单状态机 + 独立文件持久化 + 支付通知的
// 幂等落地。构造后可安全并发使用（全部公开方法互斥；落地对 accounts 的调用
// 在服务锁内串行——单写者前提下落地天然串行，两把锁无嵌套回环）。
type Service struct {
	// Now 是时钟注入点：下单时刻、超时判定与 paid_until 计算都取自此（缺省
	// time.Now，测试注入假时钟——镜像 accounts.Store.Now 的手法）。
	Now func() time.Time

	accounts   *accounts.Store // 唯一聚合间边：applied 落地 → 订阅单调延长
	periodDays int
	priceCents int64

	mu     sync.Mutex
	orders map[string]Order // order_id → 订单行
	ids    []string         // 订单号插入序（文件与 List 输出稳定）
	path   string           // orders.json 路径
}

// Create 为 username 下单（固定单一档位）：金额 = price_cents，创建与超时
// 时刻取注入时钟。username 只做形状校验（弱引用，不查账户库，§1.1）；返回
// 的 Order 携带全局唯一的 order_id（即 out_trade_no，网关下单直接使用）。
func (s *Service) Create(username string) (Order, error) {
	if strings.TrimSpace(username) == "" || strings.ContainsAny(username, "\r\n") {
		return Order{}, fmt.Errorf("%w: username %q", ErrInvalidOrder, username)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	id, err := s.newOrderID(now)
	if err != nil {
		return Order{}, err
	}
	o := Order{
		OrderID:     id,
		Username:    username,
		AmountCents: s.priceCents,
		Status:      OrderPending,
		CreatedAt:   now,
		ExpiresAt:   now.Add(orderTTL),
	}
	next := append(s.snapshotLocked(), o)
	if err := s.saveLocked(next); err != nil {
		return Order{}, err
	}
	s.orders[id] = o
	s.ids = append(s.ids, id)
	return o, nil
}

// ApplyNotify 把一笔已验签的支付通知落地为账务动作（幂等，§1.1 I4）。
//
// 返回 ack 表示对网关的应答建议（true = success，false = fail）；err 非 nil
// 时 ack 恒为 false。判定序（先决条件优先，任何路径不产生部分账务）：
//
//   - 通知形状非法（缺 trade_no / 金额非正）⇒ 拒绝；
//   - 订单不存在 ⇒ 拒绝（非本商户订单，fail-closed）；
//   - 订单已 applied：同 trade_no ⇒ ACK（幂等重放，不再延长）；不同 ⇒ 拒绝；
//   - 通知金额与订单不符 ⇒ 拒绝（不动账）；
//   - 订单 closed ⇒ ACK（不动账，网关重试到此为止）；
//   - 订单 paid（落地中断的检查点）：同 trade_no ⇒ 续落地；不同 ⇒ 拒绝；
//   - 订单 pending 且已超时 ⇒ 惰性置 closed 并落盘，ACK（不动账）；
//   - 其余（pending 未超时 / paid 续落地）⇒ paid 检查点 → 订阅单调延长
//     （paid_until = max(now, current) + period_days）→ applied 终态。
func (s *Service) ApplyNotify(trade Trade) (bool, error) {
	if trade.TradeNo == "" || trade.AmountCents <= 0 {
		return false, fmt.Errorf("%w: trade_no %q amount_cents %d", ErrInvalidTrade, trade.TradeNo, trade.AmountCents)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.orders[trade.OutTradeNo]
	if !ok {
		return false, fmt.Errorf("%w: %q", ErrUnknownOrder, trade.OutTradeNo)
	}
	switch {
	case o.Status == OrderApplied:
		if o.TradeNo != trade.TradeNo {
			return false, fmt.Errorf("%w: order %s already applied by trade %s", ErrTradeConflict, o.OrderID, o.TradeNo)
		}
		return true, nil // 幂等重放：不再延长（I4）
	case o.Status == OrderClosed:
		return true, nil // 终态订单：ACK 但不动账
	case o.AmountCents != trade.AmountCents:
		return false, fmt.Errorf("%w: order %s wants %d, notify says %d", ErrAmountMismatch, o.OrderID, o.AmountCents, trade.AmountCents)
	case o.Status == OrderPaid && o.TradeNo != trade.TradeNo:
		return false, fmt.Errorf("%w: order %s checkpointed by trade %s", ErrTradeConflict, o.OrderID, o.TradeNo)
	}
	now := s.now()
	if o.Status == OrderPending && !now.Before(o.ExpiresAt) {
		// 惰性超时关闭：下一次触碰时置终态并落盘；通知 ACK 但不动账
		//（无后台清扫线程，设计书 §1.2）。
		o.Status = OrderClosed
		if err := s.persistOrder(o); err != nil {
			return false, err
		}
		return true, nil
	}
	return s.land(o, trade, now)
}

// List 返回全部订单快照（插入序）。
func (s *Service) List() []Order {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Order, 0, len(s.ids))
	for _, id := range s.ids {
		out = append(out, s.orders[id])
	}
	return out
}

// land 完成一次落地（调用方持锁、订单已通过全部前置核对）：paid 检查点落盘
// → accounts 订阅单调延长 → applied 终态落盘。延长失败时订单停在 paid
// （网关重试自该检查点续落地；崩溃窗口说明见包注释）。
func (s *Service) land(o Order, trade Trade, now time.Time) (bool, error) {
	// paid 检查点：受理支付事实（trade_no / gmt_payment 固定，幂等键就位）。
	o.Status = OrderPaid
	o.TradeNo = trade.TradeNo
	o.GmtPayment = trade.GmtPayment
	if err := s.persistOrder(o); err != nil {
		return false, err
	}

	// 订阅单调延长（唯一聚合间边）：paid_until = max(now, current) + period。
	current, err := s.currentExpiry(o.Username)
	if err != nil {
		return false, fmt.Errorf("payment: order %s: %w", o.OrderID, err)
	}
	paidUntil := current
	if now.After(paidUntil) {
		paidUntil = now
	}
	paidUntil = paidUntil.Add(time.Duration(s.periodDays) * 24 * time.Hour)
	if err := s.accounts.ExtendSubscriptionExpiresAt(o.Username, paidUntil); err != nil {
		return false, fmt.Errorf("payment: order %s: extend subscription for %q: %w", o.OrderID, o.Username, err)
	}

	// applied 终态。
	o.Status = OrderApplied
	o.AppliedAt = now
	if err := s.persistOrder(o); err != nil {
		return false, err
	}
	return true, nil
}

// persistOrder 把订单变更先落盘、成功后应用内存（文件是权威状态，镜像
// accounts 的变更纪律：进程崩溃不会留下内存与文件不一致的中间态）。
func (s *Service) persistOrder(o Order) error {
	next := s.snapshotLocked()
	for i := range next {
		if next[i].OrderID == o.OrderID {
			next[i] = o
		}
	}
	if err := s.saveLocked(next); err != nil {
		return err
	}
	s.orders[o.OrderID] = o
	return nil
}

// currentExpiry 读取账户当前订阅到期时刻（零值 = 无订阅）。
func (s *Service) currentExpiry(username string) (time.Time, error) {
	u, err := s.accounts.Get(username)
	if err != nil {
		return time.Time{}, err
	}
	return u.Subscription.ExpiresAt, nil
}

// newOrderID 生成全局唯一的订单号（= out_trade_no）：UTC 墙钟前缀 + 随机
// 后缀（可读且防碰撞），与既有订单冲突时重试（调用方持锁）。
func (s *Service) newOrderID(now time.Time) (string, error) {
	for range 5 {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", fmt.Errorf("payment: generate order id: %w", err)
		}
		id := "O" + now.UTC().Format("20060102150405") + hex.EncodeToString(b[:])
		if _, taken := s.orders[id]; !taken {
			return id, nil
		}
	}
	return "", errors.New("payment: order id collision (retry exhausted)")
}

// now 返回当前时刻（Now 注入点；nil 回退 time.Now）。
func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// snapshotLocked 返回当前订单行列表（插入序；调用方持锁）。
func (s *Service) snapshotLocked() []Order {
	out := make([]Order, 0, len(s.ids))
	for _, id := range s.ids {
		out = append(out, s.orders[id])
	}
	return out
}

// saveLocked 把变更后的完整订单列表原子落盘（调用方持锁）。
func (s *Service) saveLocked(next []Order) error {
	if err := saveFile(s.path, next); err != nil {
		return fmt.Errorf("payment: persist %s: %w", s.path, err)
	}
	return nil
}
