package accounts

import (
	"crypto/sha256"
	"crypto/subtle"
	"time"
)

// GateView 是账户库之上的门禁读视图：方法形状与数据面既有契约逐字一致——
//
//	Authenticate(username, password string) bool  ⇔ core.Authenticator
//	VerifyTunnel(hashHex string) (string, bool)   ⇔ trojan.Verifier
//
// 结构化满足、不 import core / trojan（实现不感知消费方；auth.Store 的既有
// 手法）。编译期断言在组装根接线处补齐，本包保持 core-free / trojan-free。
//
// 判定式（设计书 §3.1）：允许 = 口令匹配 ∧ 状态启用 ∧ (¬on ∨ 订阅有效)；
// 订阅有效 = now ≥ granted_at ∧ now < expires_at（时钟回拨即拒绝，fail-closed）。
//
// on 是门禁开关（Store.Gate(enabled) 注入，来源 cfg.Gate.Enabled）：关闭时
// 行为与现状等价（口令正确 ∧ 状态启用即放行，订阅维度不参与判定）；开启时
// deny-by-default——无有效订阅即拒绝。订阅维度的存储期拒绝原因即便在门禁
// 关闭时也按同一枚举给出，供调用方记日志/计数。
//
// 拒绝原因只进日志与计数器，绝不写入协议响应——拒绝在线上与认证失败同形
// （HTTP 407 / SOCKS5 失败码 / trojan 伪装页，设计书 §1.1 I2）。
type GateView struct {
	store *Store
	on    bool // cfg.Gate.Enabled；关闭 = 与现状等价，开启 = 无订阅即拒绝
}

// Gate 构建账户库的门禁读视图（设计书 §3.1：服务端以 store.Gate(cfg.Gate.Enabled)
// 构造）。on = 门禁开关；视图读经 Store 的动态内存态，账户变更对后续判定
// 立即可见——生效边界为下一次判定，与既有凭据语义一致。
func (s *Store) Gate(on bool) *GateView {
	return &GateView{store: s, on: on}
}

// Decision 是一次门禁判定：允许与否 + 存储期拒绝原因（仅日志/计数用途）。
type Decision struct {
	// Allow 是否允许（放行出站）。
	Allow bool
	// Reason 是拒绝原因；Allow 为 true 时为 ReasonNone。
	Reason RejectReason
}

// RejectReason 是存储期拒绝原因（设计书 §3.3）。只进日志/计数，不上协议线。
type RejectReason string

const (
	// ReasonNone 表示允许（无拒绝原因）。
	ReasonNone RejectReason = ""
	// ReasonUnknownUser 用户名不存在（隧道路径 = 摘要反查未命中）。
	ReasonUnknownUser RejectReason = "unknown_user"
	// ReasonBadCredentials 口令不匹配（入站路径）。
	ReasonBadCredentials RejectReason = "bad_credentials"
	// ReasonDisabled 账户已停用。
	ReasonDisabled RejectReason = "disabled"
	// ReasonNoSubscription 无订阅（expires_at 缺省）。
	ReasonNoSubscription RejectReason = "no_subscription"
	// ReasonExpired 订阅已到期（now ≥ expires_at）。
	ReasonExpired RejectReason = "expired"
	// ReasonClockRollback 系统时刻早于订阅授予时刻（时钟回拨，fail-closed）。
	ReasonClockRollback RejectReason = "clock_rollback"
)

// Authenticate 校验入站用户名/口令（形状与 core.Authenticator 契约一致）。
func (g *GateView) Authenticate(username, password string) bool {
	return g.Decide(username, password).Allow
}

// Decide 是 Authenticate 的判定明细：拒绝原因供调用方记日志（不上协议线）。
func (g *GateView) Decide(username, password string) Decision {
	rec, found := g.store.lookup(username)
	got := sha256.Sum256([]byte(password))
	// 未知名时 want 为零值摘要：比较依然执行但不可能相等（时序纪律，镜像 auth.Store）。
	if subtle.ConstantTimeCompare(got[:], rec.sha256Sum[:]) != 1 {
		if !found {
			return Decision{Reason: ReasonUnknownUser}
		}
		return Decision{Reason: ReasonBadCredentials}
	}
	return gateDecision(rec, g.on, g.store.now())
}

// VerifyTunnel 校验隧道口令摘要（形状与 trojan.Verifier 契约一致），返回匹配
// 的用户名。拒绝时同样返回匹配名（ok=false），供调用方日志定位。
func (g *GateView) VerifyTunnel(hashHex string) (string, bool) {
	name, d := g.DecideTunnel(hashHex)
	return name, d.Allow
}

// DecideTunnel 是 VerifyTunnel 的判定明细。
func (g *GateView) DecideTunnel(hashHex string) (string, Decision) {
	rec, found := g.store.lookupTunnel(hashHex)
	if !found {
		return "", Decision{Reason: ReasonUnknownUser}
	}
	return rec.username, gateDecision(rec, g.on, g.store.now())
}

// gateDecision 是门禁判定式（口令匹配由调用方按各自路径先行完成）。
func gateDecision(rec userRecord, on bool, now time.Time) Decision {
	if rec.status != StatusActive {
		return Decision{Reason: ReasonDisabled}
	}
	if !on {
		return Decision{Allow: true} // 门禁关闭：订阅维度不参与判定（与现状等价）
	}
	if rec.sub.ExpiresAt.IsZero() {
		return Decision{Reason: ReasonNoSubscription}
	}
	if now.Before(rec.sub.GrantedAt) {
		return Decision{Reason: ReasonClockRollback} // 系统时刻早于授予时刻：时钟回拨
	}
	if !now.Before(rec.sub.ExpiresAt) {
		return Decision{Reason: ReasonExpired}
	}
	return Decision{Allow: true}
}
