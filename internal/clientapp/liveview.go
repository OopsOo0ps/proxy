package clientapp

import (
	"sync/atomic"
	"time"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/defaults"
	"github.com/OopsOo0ps/proxy/internal/dnsgw"
	"github.com/OopsOo0ps/proxy/internal/httpproxy"
	"github.com/OopsOo0ps/proxy/internal/socks5"
)

// —— 热加载视图（运行期热更路径，§8.2）——

// liveView 是入站的热加载视图：dialer、超时与 DNS 参数读当前快照；
// auth 锚定构建该入站时的凭据（生效边界 = 新连接）。单个适配器同时满足
// httpproxy / socks5 / dnsgw 三份消费方接口（方法集是三者的并集；返回类型
// 锚定 core 契约），新增热加载项只需维护这一处；任意消费方接口增删方法
// 都会让文件底部编译期断言失败，不会静默失配。
type liveView struct {
	live *atomic.Pointer[Runtime]
	auth *auth.Store // nil = 不校验
}

func (l liveView) current() *Runtime { return l.live.Load() }

// Auth 返回当前凭据校验能力；未配置认证时必须返回真正的 nil 接口——
// 消费方以接口 == nil 判定“不校验”，nil *Store 装进接口会被误判为启用。
func (l liveView) Auth() core.Authenticator {
	if l.auth == nil {
		return nil
	}
	return l.auth
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
