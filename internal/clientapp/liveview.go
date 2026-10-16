package clientapp

import (
	"sync/atomic"
	"time"

	"github.com/OopsOo0ps/proxy/internal/accounts"
	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/defaults"
	"github.com/OopsOo0ps/proxy/internal/dnsgw"
	"github.com/OopsOo0ps/proxy/internal/httpproxy"
	"github.com/OopsOo0ps/proxy/internal/socks5"
)

// —— 热加载视图（运行期热更路径，§8.2）——

// liveView 是入站的热加载视图：dialer、超时与 DNS 参数读当前快照；auth 与
// gate 锚定构建该入站时的凭据（生效边界 = 新连接）：auth 是入站静态凭据，
// gate 是本次组装从 entitlement 文件加载的门禁视图（见 entitlement.go），
// 两者在 Auth() 复合成同一形状的认证器。单个适配器同时满足 httpproxy /
// socks5 / dnsgw 三份消费方接口（方法集是三者的并集；返回类型锚定 core 契
// 约），新增热加载项只需维护这一处；任意消费方接口增删方法都会让文件底部
// 编译期断言失败，不会静默失配。
type liveView struct {
	live *atomic.Pointer[Runtime]
	auth *auth.Store        // nil = 不校验（现状）
	gate *accounts.GateView // nil = 无 entitlement 门禁（现状）
}

func (l liveView) current() *Runtime { return l.live.Load() }

// Auth 返回当前认证能力：入站静态凭据与 entitlement 门禁的复合体（设计书
// §3.1 客户端行：静态凭据 ∧ 订阅有效，两者都必须通过；见 gatedAuth）。
// nil 纪律不变：两者皆缺省时必须返回真正的 nil 接口——消费方以接口 == nil
// 判定「不校验」，nil 指针装进接口会被误判为启用。
func (l liveView) Auth() core.Authenticator {
	switch {
	case l.gate == nil && l.auth == nil:
		return nil
	case l.gate == nil:
		return l.auth
	case l.auth == nil:
		// 防御路径：config 校验层要求门禁开启时 http/socks5 入站必须配 auth
		//（requiredAuth），正常组装不会走到这里；退化为 entitlement 单独
		// 判定（订阅视图自带凭据比对），不静默放行。
		return l.gate
	default:
		return gatedAuth{static: l.auth, gate: l.gate}
	}
}

func (l liveView) Dialer() core.TargetDialer {
	if rt := l.current(); rt != nil {
		return rt.Outbound
	}
	return nil
}

func (l liveView) IdleTimeout() time.Duration {
	if rt := l.current(); rt != nil {
		return rt.cfg.Timeouts.EffectiveIdle()
	}
	return defaults.IdleTimeout
}

func (l liveView) ReadHeaderTimeout() time.Duration {
	if rt := l.current(); rt != nil {
		return rt.cfg.Timeouts.EffectiveHandshake()
	}
	return defaults.HandshakeTimeout
}

func (l liveView) HandshakeTimeout() time.Duration {
	if rt := l.current(); rt != nil {
		return rt.cfg.Timeouts.EffectiveHandshake()
	}
	return defaults.HandshakeTimeout
}

func (l liveView) ShutdownTimeout() time.Duration {
	if rt := l.current(); rt != nil {
		return rt.cfg.Timeouts.EffectiveShutdown()
	}
	return defaults.DrainTimeout
}

// Router 把当前快照的分流表适配为 dnsgw 的查询判定。
func (l liveView) Router() dnsgw.RouteDecider { return dnsRouter{live: l.live} }

func (l liveView) Remote() string {
	if rt := l.current(); rt != nil {
		return rt.dnsRemote
	}
	return defaults.DNSRemote
}

func (l liveView) Local() []string {
	if rt := l.current(); rt != nil {
		return rt.dnsLocal
	}
	return nil
}

func (l liveView) Timeout() time.Duration {
	if rt := l.current(); rt != nil {
		return rt.dnsTimeout
	}
	return defaults.DNSTimeout
}

// 编译期断言：消费方接口与适配器失配（增删方法）会直接编译失败。
var (
	_ httpproxy.LivePolicy = liveView{}
	_ socks5.LivePolicy    = liveView{}
	_ dnsgw.LivePolicy     = liveView{}
)
