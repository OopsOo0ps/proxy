package clientapp

import (
	"context"
	"fmt"
	"net"

	"github.com/OopsOo0ps/proxy/internal/auth"
	"github.com/OopsOo0ps/proxy/internal/config"
	"github.com/OopsOo0ps/proxy/internal/connlimit"
	"github.com/OopsOo0ps/proxy/internal/core"
	"github.com/OopsOo0ps/proxy/internal/dnsgw"
	"github.com/OopsOo0ps/proxy/internal/httpproxy"
	"github.com/OopsOo0ps/proxy/internal/socks5"
)

// buildInbound 是入站协议分派点：switch ic.Type → 构造对应协议端点；
// 共性认证（auth）在组装根构建，协议语义校验在协议构造器。返回的端点
// 尚未绑定监听（绑定属构建步骤，不变量 3）；bind 返回绑定产物，
// 由绑定步骤回填（避免闭包持有构造期局部副本）。
func (b *builder) buildInbound(ic *config.Inbound, rt *Runtime) (InboundServer, error) {
	switch ic.Type {
	case config.TypeHTTP:
		live, err := b.liveView(ic)
		if err != nil {
			return InboundServer{}, err
		}
		srv := &httpproxy.Server{Live: live, Logger: b.logger, Telemetry: b.metrics}
		is := newInboundServer(core.ProtoHTTP, *ic)
		is.auth = live.auth
		is.closeIdle = srv.CloseIdleConnections
		is.bind = func(limiter *connlimit.Limiter, previous string) (inboundBound, error) {
			ln, err := net.Listen("tcp", bindAddr(ic.Listen, previous))
			if err != nil {
				return inboundBound{}, fmt.Errorf("clientapp: listen http %s: %w", ic.Listen, err)
			}
			wrapped := connlimit.WrapListener(ln, limiter, func(conn net.Conn) {
				// 过载拒绝也是一次 accept 后的终态：先开后拒，保持 active 口径
				// 平衡（active = ConnOpened − (ConnDone+ConnRejected)）。
				b.metrics.ConnOpened(core.ProtoHTTP)
				b.metrics.ConnRejected(core.ProtoHTTP, core.ResultOverload)
				httpproxy.WriteOverloaded(conn)
			})
			return inboundBound{
				listener: wrapped,
				serve:    func(ctx context.Context) error { return srv.Serve(ctx, wrapped) },
				close:    func() { _ = wrapped.Close() },
				addr:     func() string { return listenerAddr(wrapped) },
			}, nil
		}
		return is, nil

	case config.TypeSOCKS5:
		live, err := b.liveView(ic)
		if err != nil {
			return InboundServer{}, err
		}
		srv := &socks5.Server{Live: live, Logger: b.logger, Telemetry: b.metrics}
		is := newInboundServer(core.ProtoSOCKS5, *ic)
		is.auth = live.auth
		is.bind = func(limiter *connlimit.Limiter, previous string) (inboundBound, error) {
			ln, err := net.Listen("tcp", bindAddr(ic.Listen, previous))
			if err != nil {
				return inboundBound{}, fmt.Errorf("clientapp: listen socks5 %s: %w", ic.Listen, err)
			}
			wrapped := connlimit.WrapListener(ln, limiter, func(conn net.Conn) {
				b.metrics.ConnOpened(core.ProtoSOCKS5)
				b.metrics.ConnRejected(core.ProtoSOCKS5, core.ResultOverload)
				socks5.WriteOverloadReply(conn)
			})
			return inboundBound{
				listener: wrapped,
				serve:    func(ctx context.Context) error { return srv.Serve(ctx, wrapped) },
				close:    func() { _ = wrapped.Close() },
				addr:     func() string { return listenerAddr(wrapped) },
			}, nil
		}
		return is, nil

	case config.TypeDNS:
		srv, err := dnsgw.New(dnsgw.Options{
			ListenAddr: ic.Listen,
			Remote:     rt.dnsRemote,
			Local:      rt.dnsLocal,
			Timeout:    rt.dnsTimeout,
			Router:     dnsRouter{live: b.live},
			// 出站两侧注入的是读当前快照的适配器：直连路径（本地解析）与
			// 代理路径（经出口隧道远程解析）始终跟随热加载后的运行时。
			Direct:          dnsDirectDialer{live: b.live},
			Proxy:           dnsTunnelDialer{live: b.live},
			Logger:          b.logger,
			Observer:        b.metrics,
			ShutdownTimeout: rt.cfg.Timeouts.EffectiveShutdown(),
			QueryLimiter:    b.dnsLimiter,
			Live:            b.liveViewShared(),
		})
		if err != nil {
			return InboundServer{}, err
		}
		is := newInboundServer(core.ProtoDNS, *ic)
		is.bind = func(_ *connlimit.Limiter, previous string) (inboundBound, error) {
			ln, err := dnsgw.Listen(bindAddr(ic.Listen, previous))
			if err != nil {
				return inboundBound{}, fmt.Errorf("clientapp: listen dns %s: %w", ic.Listen, err)
			}
			// TCP 侧包装专用查询闸（UDP 侧闸在 dnsgw 包内，经 QueryLimiter 生效）。
			// 过载拒绝也是一次 accept 后的终态：先开后拒，保持 active 口径平衡；
			// 拒绝动作读首帧查询回 REFUSED。dnsgw.serveTCP 识别已包装监听，
			// 不会对同一份预算二次占用名额。
			ln.TCP = connlimit.WrapListener(ln.TCP, b.dnsLimiter, func(conn net.Conn) {
				b.metrics.ConnOpened(core.ProtoDNS)
				b.metrics.ConnRejected(core.ProtoDNS, core.ResultOverload)
				dnsgw.RejectOverload(conn)
			})
			return inboundBound{
				listener: ln.TCP,
				serve:    func(ctx context.Context) error { return srv.Serve(ctx, ln) },
				close:    func() { _ = ln.Close() },
				addr:     func() string { return ln.Addr().String() },
			}, nil
		}
		return is, nil

	default:
		return InboundServer{}, fmt.Errorf("unknown inbound type %q", ic.Type)
	}
}

// liveView 为 http / socks5 入站构建热加载视图（认证锚定该入站凭据）。
func (b *builder) liveView(ic *config.Inbound) (liveView, error) {
	store, err := inboundAuth(ic)
	if err != nil {
		return liveView{}, err
	}
	return liveView{live: b.live, auth: store}, nil
}

// liveViewShared 返回无认证锚定的共享视图（dns 网关无认证概念）。
func (b *builder) liveViewShared() liveView {
	return liveView{live: b.live}
}

// inboundAuth 构建入站凭据存储；未配置认证时返回 nil（消费方以 nil 接口
// 判定“不校验”，nil *Store 装进接口会被误判为启用）。
func inboundAuth(ic *config.Inbound) (*auth.Store, error) {
	if ic.Auth == nil || len(ic.Auth.Users) == 0 {
		return nil, nil
	}
	users := make([]auth.User, 0, len(ic.Auth.Users))
	for _, u := range ic.Auth.Users {
		users = append(users, auth.User{Username: u.Username, Password: u.Password})
	}
	return auth.NewStore(users)
}

// bindAddr 返回实际绑定的地址：端口 0（自动分配）的配置沿用 previous 的
// 已解析地址（重载不改变端口）；显式端口按配置原样绑定。
func bindAddr(configured, previous string) string {
	if previous == "" {
		return configured
	}
	if _, port, err := net.SplitHostPort(configured); err == nil && port == "0" {
		return previous
	}
	return configured
}

func listenerAddr(ln net.Listener) string {
	if ln == nil {
		return ""
	}
	return ln.Addr().String()
}
